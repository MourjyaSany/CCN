/* =============================================================================
 * NetShield-GNN :: NS-3 model of the IoT -> router -> edge gateway -> cloud
 * topology, with legitimate IoT traffic and simulated DDoS attackers.
 *
 * WHAT THIS FILE IS FOR
 * ---------------------
 * This is the real NS-3 implementation of the same experiment the built-in
 * Python discrete-event engine runs. Its purpose is cross-validation: the two
 * engines model the same topology, the same traffic classes and the same
 * attacks, and they export flow records with *identical column names*, so
 * netshield.features consumes either source unchanged and the two can be
 * compared directly.
 *
 * WHY NOT FlowMonitor
 * -------------------
 * FlowMonitor aggregates per-flow totals and exposes no TCP flag counts, so a
 * FlowMonitor-derived feature vector would silently have zeros in the
 * syn/ack/fin/rst columns the detector depends on - a subtle, invisible train/
 * test mismatch. Instead this model taps Ipv4L3Protocol directly:
 *
 *   SendOutgoing  -> the packet a node offered            (flow accounting)
 *   LocalDeliver  -> the packet a destination received    (delivered counter)
 *   Drop          -> the packet the stack discarded       (dropped counter)
 *
 * At those trace points the IPv4 header is available separately and the
 * transport header can be peeked, so genuine per-flow TCP flag counts, packet
 * size distributions and inter-arrival statistics are recovered - the same
 * quantities the Python engine records.
 *
 * BUILD
 * -----
 *   cp ns3/simulations/netshield-topology.cc  $NS3_DIR/scratch/
 *   cd $NS3_DIR && ./ns3 build
 *   ./ns3 run "netshield-topology --nIot=24 --nAttackers=4 --outputDir=/tmp/out"
 *
 * Or use the helper:  bash ns3/scripts/build_ns3.sh
 *
 * OUTPUT
 * ------
 * <outputDir>/ns3_flows.csv  - one row per (window, 5-tuple), same schema as
 *                              the Python engine's flows.csv
 * <outputDir>/ns3_run.json   - run-level provenance and totals
 * =============================================================================
 */

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/tcp-header.h"
#include "ns3/traffic-control-module.h"
#include "ns3/udp-header.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("NetShieldTopology");

namespace
{

/** Command-line configurable parameters, mirroring config/network.yaml. */
struct Params
{
    uint32_t nIot = 24;        //!< legitimate IoT devices
    uint32_t nAttackers = 4;   //!< compromised devices
    uint32_t nRouters = 3;     //!< access routers
    double duration = 90.0;    //!< simulated seconds
    double attackStart = 30.0; //!< attack start, seconds
    double attackDuration = 30.0;
    double attackPps = 1400.0;    //!< per-attacker packet rate
    uint32_t attackBytes = 512;   //!< attack payload size
    std::string attackType = "udp_flood";
    double windowS = 5.0;         //!< feature window length
    uint32_t seed = 42;
    std::string topology = "tree"; //!< tree | star | dumbbell
    std::string outputDir = ".";
};

// ---------------------------------------------------------------------------
// Flow accounting
// ---------------------------------------------------------------------------

/** Key identifying one flow inside one feature window. */
struct FlowKey
{
    uint32_t window;
    std::string srcNode;
    std::string dstNode;
    uint32_t srcIp;
    uint32_t dstIp;
    uint16_t srcPort;
    uint16_t dstPort;
    uint8_t protocol;

    bool operator<(const FlowKey& o) const
    {
        return std::tie(window, srcNode, dstNode, srcIp, dstIp, srcPort, dstPort, protocol) <
               std::tie(o.window, o.srcNode, o.dstNode, o.srcIp, o.dstIp, o.srcPort, o.dstPort,
                        o.protocol);
    }
};

/** Accumulated statistics for one flow within one window. */
struct FlowStats
{
    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t payloadBytes = 0;
    uint32_t sizeMin = 0xFFFFFFFF;
    uint32_t sizeMax = 0;
    double sizeSum = 0.0;
    double sizeSqSum = 0.0;
    double firstT = -1.0;
    double lastT = 0.0;
    double iatSum = 0.0;
    double iatSqSum = 0.0;
    uint64_t iatN = 0;
    uint64_t synCount = 0;
    uint64_t synAckCount = 0;
    uint64_t ackCount = 0;
    uint64_t finCount = 0;
    uint64_t rstCount = 0;
    uint64_t pshCount = 0;
    uint64_t delivered = 0;
    uint64_t dropped = 0;
    uint64_t attackPackets = 0;
    std::string app;
    std::string attackType;
};

/** Per-window network-level aggregates, mirroring WindowMetrics. */
struct WindowStats
{
    uint64_t offeredPackets = 0;
    uint64_t offeredBytes = 0;
    uint64_t deliveredPackets = 0;
    uint64_t deliveredBytes = 0;
    uint64_t droppedPackets = 0;
    uint64_t attackOffered = 0;
    uint64_t legitOffered = 0;
    uint64_t legitDelivered = 0;
    double latencySum = 0.0;
    uint64_t latencyN = 0;
    double latencyMax = 0.0;
    double legitLatencySum = 0.0;
    uint64_t legitLatencyN = 0;
    //! Per-packet delays, retained so genuine percentiles can be reported
    //! rather than the mean being passed off as one.
    std::vector<double> latencySamples;
};

std::map<uint32_t, WindowStats> g_windows;

/**
 * Send time of every packet still in flight, keyed by ns-3 packet UID.
 *
 * A packet's UID survives the copies made as it is forwarded, so recording the
 * send time here and subtracting at LocalDeliver yields a genuine end-to-end
 * delay. This is measured rather than derived: it includes queueing, so it
 * rises under congestion exactly as the Python engine's does. Entries are
 * erased on delivery, so the map holds only in-flight packets.
 */
std::map<uint64_t, double> g_sentAt;

std::map<FlowKey, FlowStats> g_flows;
std::map<uint32_t, std::string> g_ipToNode; //!< IPv4 (host order) -> node id
std::map<uint32_t, bool> g_ipIsAttacker;
Params g_params;

uint64_t g_totalOffered = 0;
uint64_t g_totalDelivered = 0;
uint64_t g_totalDropped = 0;

/** Return the feature-window index containing simulated time *t*. */
uint32_t
WindowOf(double t)
{
    return static_cast<uint32_t>(std::floor(t / g_params.windowS));
}

/** Resolve an IPv4 address to the node id assigned during construction. */
std::string
NodeIdFor(const Ipv4Address& addr)
{
    auto it = g_ipToNode.find(addr.Get());
    if (it != g_ipToNode.end())
    {
        return it->second;
    }
    // Unknown address: a spoofed source. Report it as such rather than
    // silently attributing the packet to a real device.
    std::ostringstream oss;
    oss << "spoofed-" << Ipv4Address(addr);
    return oss.str();
}

/** True when the source address belongs to a compromised device. */
bool
IsAttackSource(const Ipv4Address& addr)
{
    auto it = g_ipIsAttacker.find(addr.Get());
    return it != g_ipIsAttacker.end() && it->second;
}

/**
 * Peek the transport header of *packet* and fill in ports and TCP flags.
 *
 * The packet handed to an Ipv4L3Protocol trace has already had its IP header
 * removed (it is supplied separately), so the transport header is at the front
 * and can be peeked without disturbing the original.
 */
void
ExtractTransport(Ptr<const Packet> packet,
                 uint8_t protocol,
                 uint16_t& srcPort,
                 uint16_t& dstPort,
                 uint8_t& flags,
                 uint32_t& payload)
{
    srcPort = 0;
    dstPort = 0;
    flags = 0;
    payload = packet->GetSize();

    if (protocol == 6) // TCP
    {
        TcpHeader tcp;
        if (packet->PeekHeader(tcp) > 0)
        {
            srcPort = tcp.GetSourcePort();
            dstPort = tcp.GetDestinationPort();
            flags = tcp.GetFlags();
            uint32_t hdr = tcp.GetSerializedSize();
            payload = packet->GetSize() > hdr ? packet->GetSize() - hdr : 0;
        }
    }
    else if (protocol == 17) // UDP
    {
        UdpHeader udp;
        if (packet->PeekHeader(udp) > 0)
        {
            srcPort = udp.GetSourcePort();
            dstPort = udp.GetDestinationPort();
            uint32_t hdr = udp.GetSerializedSize();
            payload = packet->GetSize() > hdr ? packet->GetSize() - hdr : 0;
        }
    }
    // ICMP (1) has no ports; 0/0 is what a flow exporter records.
}

/** Build the flow key for a packet observed at the IP layer. */
FlowKey
KeyFor(const Ipv4Header& header, uint16_t srcPort, uint16_t dstPort, double now)
{
    FlowKey key;
    key.window = WindowOf(now);
    key.srcNode = NodeIdFor(header.GetSource());
    key.dstNode = NodeIdFor(header.GetDestination());
    key.srcIp = header.GetSource().Get();
    key.dstIp = header.GetDestination().Get();
    key.srcPort = srcPort;
    key.dstPort = dstPort;
    key.protocol = header.GetProtocol();
    return key;
}

// ---------------------------------------------------------------------------
// Trace sinks
// ---------------------------------------------------------------------------

/** A node's IP layer emitted a packet: this is the offered-load accounting. */
void
OnSendOutgoing(const Ipv4Header& header, Ptr<const Packet> packet, uint32_t /*interface*/)
{
    const double now = Simulator::Now().GetSeconds();
    if (now >= g_params.duration)
    {
        return;
    }

    uint16_t sport;
    uint16_t dport;
    uint8_t flags;
    uint32_t payload;
    ExtractTransport(packet, header.GetProtocol(), sport, dport, flags, payload);

    FlowStats& stats = g_flows[KeyFor(header, sport, dport, now)];

    // Ethernet-equivalent wire size, matching the Python engine's accounting
    // so byte rates from the two engines are directly comparable.
    const uint32_t wire = packet->GetSize() + header.GetSerializedSize() + 18;

    stats.packets += 1;
    stats.bytes += wire;
    stats.payloadBytes += payload;
    stats.sizeMin = std::min(stats.sizeMin, wire);
    stats.sizeMax = std::max(stats.sizeMax, wire);
    stats.sizeSum += wire;
    stats.sizeSqSum += static_cast<double>(wire) * wire;

    if (stats.firstT < 0.0)
    {
        stats.firstT = now;
    }
    else
    {
        const double iat = now - stats.lastT;
        stats.iatSum += iat;
        stats.iatSqSum += iat * iat;
        stats.iatN += 1;
    }
    stats.lastT = now;

    if (header.GetProtocol() == 6)
    {
        const bool syn = (flags & TcpHeader::SYN) != 0;
        const bool ack = (flags & TcpHeader::ACK) != 0;
        if (syn && ack)
        {
            stats.synAckCount += 1;
        }
        else if (syn)
        {
            stats.synCount += 1;
        }
        if (ack)
        {
            stats.ackCount += 1;
        }
        if (flags & TcpHeader::FIN)
        {
            stats.finCount += 1;
        }
        if (flags & TcpHeader::RST)
        {
            stats.rstCount += 1;
        }
        if (flags & TcpHeader::PSH)
        {
            stats.pshCount += 1;
        }
    }

    WindowStats& win = g_windows[WindowOf(now)];
    win.offeredPackets += 1;
    win.offeredBytes += wire;

    const bool hostile = IsAttackSource(header.GetSource()) &&
                         now >= g_params.attackStart &&
                         now < g_params.attackStart + g_params.attackDuration;
    if (hostile)
    {
        stats.attackPackets += 1;
        stats.attackType = g_params.attackType;
        stats.app = "attack_" + g_params.attackType;
        win.attackOffered += 1;
    }
    else
    {
        if (stats.app.empty())
        {
            stats.app = "legit";
        }
        win.legitOffered += 1;
    }

    g_sentAt[packet->GetUid()] = now;
    g_totalOffered += 1;
}

/** A destination's IP layer delivered a packet up the stack. */
void
OnLocalDeliver(const Ipv4Header& header, Ptr<const Packet> packet, uint32_t /*interface*/)
{
    const double now = Simulator::Now().GetSeconds();
    if (now >= g_params.duration)
    {
        return;
    }
    uint16_t sport;
    uint16_t dport;
    uint8_t flags;
    uint32_t payload;
    ExtractTransport(packet, header.GetProtocol(), sport, dport, flags, payload);
    g_flows[KeyFor(header, sport, dport, now)].delivered += 1;

    WindowStats& win = g_windows[WindowOf(now)];
    win.deliveredPackets += 1;
    win.deliveredBytes += packet->GetSize() + header.GetSerializedSize() + 18;

    auto sent = g_sentAt.find(packet->GetUid());
    if (sent != g_sentAt.end())
    {
        const double delay = now - sent->second;
        g_sentAt.erase(sent);
        if (delay >= 0.0)
        {
            win.latencySum += delay;
            win.latencyN += 1;
            win.latencyMax = std::max(win.latencyMax, delay);
            win.latencySamples.push_back(delay);
            if (!IsAttackSource(header.GetSource()))
            {
                win.legitLatencySum += delay;
                win.legitLatencyN += 1;
                win.legitDelivered += 1;
            }
        }
    }
    g_totalDelivered += 1;
}

/** The stack discarded a packet (queue overflow, TTL, no route, ...). */
void
OnDrop(const Ipv4Header& header,
       Ptr<const Packet> packet,
       Ipv4L3Protocol::DropReason /*reason*/,
       Ptr<Ipv4> /*ipv4*/,
       uint32_t /*interface*/)
{
    const double now = Simulator::Now().GetSeconds();
    if (now >= g_params.duration)
    {
        return;
    }
    uint16_t sport;
    uint16_t dport;
    uint8_t flags;
    uint32_t payload;
    ExtractTransport(packet, header.GetProtocol(), sport, dport, flags, payload);
    g_flows[KeyFor(header, sport, dport, now)].dropped += 1;
    g_windows[WindowOf(now)].droppedPackets += 1;
    g_totalDropped += 1;
}

/** A device transmit queue dropped a frame (drop-tail overflow). */
void
OnQueueDrop(Ptr<const Packet> /*packet*/)
{
    g_windows[WindowOf(Simulator::Now().GetSeconds())].droppedPackets += 1;
    g_totalDropped += 1;
}

/**
 * A traffic-control queue disc dropped a packet.
 *
 * The queue-disc traces carry ``(Ptr<const QueueDiscItem>, const char* reason)``
 * rather than a bare packet, so they need their own sink; connecting the
 * packet-shaped callback to them aborts the run with an "Incompatible types"
 * fatal error rather than failing quietly.
 */
void
OnQueueDiscDrop(Ptr<const QueueDiscItem> /*item*/, const char* /*reason*/)
{
    g_windows[WindowOf(Simulator::Now().GetSeconds())].droppedPackets += 1;
    g_totalDropped += 1;
}

// ---------------------------------------------------------------------------
// CSV export
// ---------------------------------------------------------------------------

/** Protocol number -> name, matching netshield.simulation.packet.Protocol. */
std::string
ProtocolName(uint8_t protocol)
{
    switch (protocol)
    {
    case 6:
        return "TCP";
    case 17:
        return "UDP";
    case 1:
        return "ICMP";
    default:
        return "PROTO-" + std::to_string(static_cast<int>(protocol));
    }
}

/** Render an IPv4 address (host byte order) as dotted quad. */
std::string
IpToString(uint32_t addr)
{
    std::ostringstream oss;
    oss << Ipv4Address(addr);
    return oss.str();
}

/**
 * Write the accumulated flows to ``<outputDir>/ns3_flows.csv``.
 *
 * The column list is identical to
 * :meth:`netshield.simulation.telemetry.FlowRecord.to_row`, so the same feature
 * extractor consumes output from either engine.
 */
void
WriteFlows(const std::string& path)
{
    std::ofstream out(path);
    if (!out.is_open())
    {
        NS_FATAL_ERROR("Cannot open " << path << " for writing");
    }
    out << std::fixed;
    out << "window,t_start,t_end,src_node,dst_node,src_ip,dst_ip,src_port,dst_port,"
           "protocol,protocol_name,app,packets,bytes,payload_bytes,duration,packet_rate,"
           "byte_rate,mean_packet_size,packet_size_var,min_packet_size,max_packet_size,"
           "mean_iat,iat_std,syn_count,syn_ack_count,ack_count,fin_count,rst_count,"
           "psh_count,delivered,dropped,retransmits,attack_packets,attack_ratio,attack_type\n";

    for (const auto& entry : g_flows)
    {
        const FlowKey& k = entry.first;
        const FlowStats& s = entry.second;
        if (s.packets == 0)
        {
            continue;
        }

        const double tStart = k.window * g_params.windowS;
        const double tEnd = tStart + g_params.windowS;
        const double duration = (s.firstT >= 0.0) ? (s.lastT - s.firstT) : 0.0;
        const double meanSize = s.sizeSum / s.packets;
        const double varSize =
            s.packets > 1 ? std::max(0.0, s.sizeSqSum / s.packets - meanSize * meanSize) : 0.0;
        const double meanIat = s.iatN > 0 ? s.iatSum / s.iatN : 0.0;
        const double iatVar =
            s.iatN > 1 ? std::max(0.0, s.iatSqSum / s.iatN - meanIat * meanIat) : 0.0;
        const double attackRatio =
            s.packets > 0 ? static_cast<double>(s.attackPackets) / s.packets : 0.0;

        out << k.window << ',' << std::setprecision(4) << tStart << ',' << tEnd << ','
            << k.srcNode << ',' << k.dstNode << ',' << IpToString(k.srcIp) << ','
            << IpToString(k.dstIp) << ',' << k.srcPort << ',' << k.dstPort << ','
            << static_cast<int>(k.protocol) << ',' << ProtocolName(k.protocol) << ','
            << (s.app.empty() ? "legit" : s.app) << ',' << s.packets << ',' << s.bytes << ','
            << s.payloadBytes << ',' << std::setprecision(6) << duration << ','
            << std::setprecision(4) << (s.packets / g_params.windowS) << ','
            << (s.bytes / g_params.windowS) << ',' << std::setprecision(3) << meanSize << ','
            << varSize << ',' << (s.sizeMin == 0xFFFFFFFF ? 0 : s.sizeMin) << ',' << s.sizeMax
            << ',' << std::setprecision(6) << meanIat << ',' << std::sqrt(iatVar) << ','
            << s.synCount << ',' << s.synAckCount << ',' << s.ackCount << ',' << s.finCount << ','
            << s.rstCount << ',' << s.pshCount << ',' << s.delivered << ',' << s.dropped << ",0,"
            << s.attackPackets << ',' << std::setprecision(5) << attackRatio << ','
            << s.attackType << '\n';
    }
    out.close();
}

/**
 * Write per-window network metrics to ``<outputDir>/ns3_windows.csv``.
 *
 * Column names match the subset of
 * :meth:`netshield.simulation.telemetry.WindowMetrics.to_row` that NS-3
 * actually measures. Nothing is imputed: quantities this model does not
 * observe are simply absent from the file rather than filled with zeros that
 * would read as measurements.
 */
void
WriteWindows(const std::string& path)
{
    std::ofstream out(path);
    if (!out.is_open())
    {
        NS_FATAL_ERROR("Cannot open " << path << " for writing");
    }
    out << std::fixed;
    out << "window,t_start,t_end,offered_packets,offered_bytes,delivered_packets,"
           "delivered_bytes,dropped_packets,legit_offered,legit_delivered,"
           "attack_offered,mean_latency_ms,max_latency_ms,legit_mean_latency_ms,"
           "packet_loss_ratio,throughput_mbps\n";

    for (const auto& entry : g_windows)
    {
        const uint32_t w = entry.first;
        const WindowStats& s = entry.second;
        const double tStart = w * g_params.windowS;
        if (tStart >= g_params.duration)
        {
            continue;
        }
        const double meanLat = s.latencyN ? (s.latencySum / s.latencyN) * 1000.0 : 0.0;
        // Percentiles from the retained samples: nearest-rank, matching
        // WindowMetrics.percentile_latency_ms() in the Python engine so the two
        // engines' numbers mean the same thing.
        std::vector<double> sorted = s.latencySamples;
        std::sort(sorted.begin(), sorted.end());
        auto pct = [&sorted](double q) -> double {
            if (sorted.empty())
            {
                return 0.0;
            }
            const size_t idx = static_cast<size_t>(
                std::llround((q / 100.0) * static_cast<double>(sorted.size() - 1)));
            return sorted[std::min(idx, sorted.size() - 1)] * 1000.0;
        };
        const double legitLat =
            s.legitLatencyN ? (s.legitLatencySum / s.legitLatencyN) * 1000.0 : 0.0;
        const double loss =
            s.offeredPackets ? static_cast<double>(s.droppedPackets) / s.offeredPackets : 0.0;
        const double mbps = (s.deliveredBytes * 8.0) / (g_params.windowS * 1e6);

        out << w << ',' << std::setprecision(4) << tStart << ','
            << (tStart + g_params.windowS) << ',' << s.offeredPackets << ','
            << s.offeredBytes << ',' << s.deliveredPackets << ',' << s.deliveredBytes << ','
            << s.droppedPackets << ',' << s.legitOffered << ',' << s.legitDelivered << ','
            << s.attackOffered << ',' << std::setprecision(4) << meanLat << ','
            << (s.latencyMax * 1000.0) << ',' << legitLat << ',' << pct(95.0) << ','
            << pct(99.0) << ',' << std::setprecision(6)
            << loss << ',' << std::setprecision(4) << mbps << '\n';
    }
    out.close();
}

/** Write run-level provenance so downstream tooling can label the artefacts. */
void
WriteRunJson(const std::string& path, const NodeContainer& iot, const NodeContainer& attackers)
{
    std::ofstream out(path);
    if (!out.is_open())
    {
        NS_FATAL_ERROR("Cannot open " << path << " for writing");
    }
    out << "{\n";
    out << "  \"engine\": \"ns3-simulation\",\n";
    // ns3::GetVersion() only exists when the tree was configured with
    // --enable-build-version, so it is not available in a default build. The
    // Python bridge records the version from its own probe instead; emitting a
    // guess here would be worse than emitting nothing.
    out << "  \"topology\": \"" << g_params.topology << "\",\n";
    out << "  \"n_iot\": " << iot.GetN() << ",\n";
    out << "  \"n_attackers\": " << attackers.GetN() << ",\n";
    out << "  \"n_routers\": " << g_params.nRouters << ",\n";
    out << "  \"duration_s\": " << g_params.duration << ",\n";
    out << "  \"window_s\": " << g_params.windowS << ",\n";
    out << "  \"attack_type\": \"" << g_params.attackType << "\",\n";
    out << "  \"attack_start_s\": " << g_params.attackStart << ",\n";
    out << "  \"attack_duration_s\": " << g_params.attackDuration << ",\n";
    out << "  \"attack_pps\": " << g_params.attackPps << ",\n";
    out << "  \"packets_offered\": " << g_totalOffered << ",\n";
    out << "  \"packets_delivered\": " << g_totalDelivered << ",\n";
    out << "  \"packets_dropped\": " << g_totalDropped << ",\n";
    out << "  \"flow_records\": " << g_flows.size() << "\n";
    out << "}\n";
    out.close();
}

/** Register the IP-layer trace sinks on every node in *nodes*. */
void
HookTraces(const NodeContainer& nodes)
{
    for (uint32_t i = 0; i < nodes.GetN(); ++i)
    {
        Ptr<Ipv4L3Protocol> ipv4 = nodes.Get(i)->GetObject<Ipv4L3Protocol>();
        if (!ipv4)
        {
            continue;
        }
        ipv4->TraceConnectWithoutContext("SendOutgoing", MakeCallback(&OnSendOutgoing));
        ipv4->TraceConnectWithoutContext("LocalDeliver", MakeCallback(&OnLocalDeliver));
        ipv4->TraceConnectWithoutContext("Drop", MakeCallback(&OnDrop));
    }
}

/** Record the address -> node-id mapping used for flow attribution. */
void
RegisterAddress(const Ipv4Address& addr, const std::string& nodeId, bool isAttacker)
{
    g_ipToNode[addr.Get()] = nodeId;
    g_ipIsAttacker[addr.Get()] = isAttacker;
}

} // namespace

int
main(int argc, char* argv[])
{
    Params& p = g_params;

    CommandLine cmd(__FILE__);
    cmd.AddValue("nIot", "Number of legitimate IoT devices", p.nIot);
    cmd.AddValue("nAttackers", "Number of compromised devices", p.nAttackers);
    cmd.AddValue("nRouters", "Number of access routers", p.nRouters);
    cmd.AddValue("duration", "Simulated duration (s)", p.duration);
    cmd.AddValue("attackStart", "Attack start time (s)", p.attackStart);
    cmd.AddValue("attackDuration", "Attack duration (s)", p.attackDuration);
    cmd.AddValue("attackPps", "Per-attacker packet rate", p.attackPps);
    cmd.AddValue("attackBytes", "Attack payload size (bytes)", p.attackBytes);
    cmd.AddValue("attackType", "udp_flood | syn_flood | http_flood | icmp_flood", p.attackType);
    cmd.AddValue("windowS", "Feature window length (s)", p.windowS);
    cmd.AddValue("seed", "RNG seed", p.seed);
    cmd.AddValue("topology", "tree | star | dumbbell", p.topology);
    cmd.AddValue("outputDir", "Directory for CSV/JSON output", p.outputDir);
    cmd.Parse(argc, argv);

    if (p.nRouters < 1)
    {
        NS_FATAL_ERROR("nRouters must be >= 1");
    }
    if (p.topology == "star")
    {
        p.nRouters = 1; // a star is a tree with exactly one access router
    }

    RngSeedManager::SetSeed(p.seed);
    RngSeedManager::SetRun(1);

    // ---- nodes ------------------------------------------------------------
    NodeContainer cloud;
    cloud.Create(1);
    NodeContainer gateway;
    // A dumbbell has two gateways joined by the constrained backbone span.
    gateway.Create(p.topology == "dumbbell" ? 2 : 1);
    NodeContainer routers;
    routers.Create(p.nRouters);
    NodeContainer iot;
    iot.Create(p.nIot);
    NodeContainer attackers;
    attackers.Create(p.nAttackers);

    InternetStackHelper stack;
    stack.Install(cloud);
    stack.Install(gateway);
    stack.Install(routers);
    stack.Install(iot);
    stack.Install(attackers);

    // ---- link helpers (mirroring config/network.yaml) ----------------------
    PointToPointHelper uplink; // gateway <-> cloud, the bottleneck
    uplink.SetDeviceAttribute("DataRate", StringValue("20Mbps"));
    uplink.SetChannelAttribute("Delay", StringValue("12ms"));
    uplink.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize", StringValue("120p"));

    PointToPointHelper backbone; // dumbbell only: narrower and longer
    backbone.SetDeviceAttribute("DataRate", StringValue("8Mbps"));
    backbone.SetChannelAttribute("Delay", StringValue("30ms"));
    backbone.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize", StringValue("120p"));

    PointToPointHelper aggregation; // router <-> gateway
    aggregation.SetDeviceAttribute("DataRate", StringValue("50Mbps"));
    aggregation.SetChannelAttribute("Delay", StringValue("3ms"));
    aggregation.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize", StringValue("200p"));

    PointToPointHelper access; // device <-> router
    access.SetDeviceAttribute("DataRate", StringValue("4Mbps"));
    access.SetChannelAttribute("Delay", StringValue("1.5ms"));
    access.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize", StringValue("60p"));

    PointToPointHelper attackerAccess; // compromised NVR/DVR-class device
    attackerAccess.SetDeviceAttribute("DataRate", StringValue("12Mbps"));
    attackerAccess.SetChannelAttribute("Delay", StringValue("1.5ms"));
    attackerAccess.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize", StringValue("100p"));

    Ipv4AddressHelper ipv4;
    uint32_t subnet = 1;
    auto nextBase = [&subnet]() {
        std::ostringstream oss;
        oss << "10." << ((subnet >> 8) & 0xFF) << "." << (subnet & 0xFF) << ".0";
        subnet += 1;
        return oss.str();
    };

    // ---- wire the core ----------------------------------------------------
    Ptr<Node> ingressGw = gateway.Get(0);
    Ptr<Node> egressGw = gateway.Get(gateway.GetN() - 1);

    if (p.topology == "dumbbell")
    {
        NetDeviceContainer span = backbone.Install(ingressGw, egressGw);
        ipv4.SetBase(nextBase().c_str(), "255.255.255.0");
        ipv4.Assign(span);
    }

    NetDeviceContainer gwCloud = uplink.Install(egressGw, cloud.Get(0));
    ipv4.SetBase(nextBase().c_str(), "255.255.255.0");
    Ipv4InterfaceContainer gwCloudIf = ipv4.Assign(gwCloud);
    const Ipv4Address cloudAddr = gwCloudIf.GetAddress(1);
    RegisterAddress(cloudAddr, "cloud-0", false);

    for (uint32_t r = 0; r < p.nRouters; ++r)
    {
        NetDeviceContainer link = aggregation.Install(routers.Get(r), ingressGw);
        ipv4.SetBase(nextBase().c_str(), "255.255.255.0");
        Ipv4InterfaceContainer ifc = ipv4.Assign(link);
        std::ostringstream rid;
        rid << "rtr-" << r;
        RegisterAddress(ifc.GetAddress(0), rid.str(), false);
        RegisterAddress(ifc.GetAddress(1), "gw-0", false);
    }

    // ---- attach the fleet -------------------------------------------------
    std::vector<Ipv4Address> iotAddrs;
    for (uint32_t i = 0; i < p.nIot; ++i)
    {
        Ptr<Node> parent = routers.Get(i % p.nRouters);
        NetDeviceContainer link = access.Install(iot.Get(i), parent);
        ipv4.SetBase(nextBase().c_str(), "255.255.255.0");
        Ipv4InterfaceContainer ifc = ipv4.Assign(link);
        std::ostringstream nid;
        nid << "iot-" << std::setfill('0') << std::setw(2) << i;
        RegisterAddress(ifc.GetAddress(0), nid.str(), false);
        iotAddrs.push_back(ifc.GetAddress(0));
    }

    std::vector<Ipv4Address> atkAddrs;
    for (uint32_t i = 0; i < p.nAttackers; ++i)
    {
        Ptr<Node> parent = routers.Get(i % p.nRouters);
        NetDeviceContainer link = attackerAccess.Install(attackers.Get(i), parent);
        ipv4.SetBase(nextBase().c_str(), "255.255.255.0");
        Ipv4InterfaceContainer ifc = ipv4.Assign(link);
        std::ostringstream nid;
        nid << "atk-" << std::setfill('0') << std::setw(2) << i;
        RegisterAddress(ifc.GetAddress(0), nid.str(), true);
        atkAddrs.push_back(ifc.GetAddress(0));
    }

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // ---- servers on the cloud --------------------------------------------
    const uint16_t mqttPort = 8883;
    const uint16_t httpPort = 80;
    const uint16_t coapPort = 5683;

    PacketSinkHelper mqttSink("ns3::TcpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), mqttPort));
    PacketSinkHelper httpSink("ns3::TcpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), httpPort));
    PacketSinkHelper coapSink("ns3::UdpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), coapPort));
    ApplicationContainer sinks;
    sinks.Add(mqttSink.Install(cloud.Get(0)));
    sinks.Add(httpSink.Install(cloud.Get(0)));
    sinks.Add(coapSink.Install(cloud.Get(0)));
    sinks.Start(Seconds(0.0));
    sinks.Stop(Seconds(p.duration));

    // ---- legitimate IoT traffic ------------------------------------------
    // Device classes mirror config/default.yaml::traffic.device_mix. Rates are
    // expressed as OnOff data rates equivalent to the Python engine's
    // interval/payload parameters.
    ApplicationContainer legit;
    for (uint32_t i = 0; i < p.nIot; ++i)
    {
        const uint32_t cls = i % 4;
        if (cls == 0 || cls == 1) // mqtt_sensor: periodic small TCP publishes
        {
            OnOffHelper app("ns3::TcpSocketFactory", InetSocketAddress(cloudAddr, mqttPort));
            app.SetAttribute("DataRate", StringValue("6kbps"));
            app.SetAttribute("PacketSize", UintegerValue(128));
            app.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
            app.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
            legit.Add(app.Install(iot.Get(i)));
        }
        else if (cls == 2) // http_client: request/response over TCP
        {
            OnOffHelper app("ns3::TcpSocketFactory", InetSocketAddress(cloudAddr, httpPort));
            app.SetAttribute("DataRate", StringValue("12kbps"));
            app.SetAttribute("PacketSize", UintegerValue(512));
            app.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=0.5]"));
            app.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=5.5]"));
            legit.Add(app.Install(iot.Get(i)));
        }
        else // udp_streamer: constant-bitrate CoAP-like telemetry
        {
            OnOffHelper app("ns3::UdpSocketFactory", InetSocketAddress(cloudAddr, coapPort));
            app.SetAttribute("DataRate", StringValue("30kbps"));
            app.SetAttribute("PacketSize", UintegerValue(300));
            app.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
            app.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
            legit.Add(app.Install(iot.Get(i)));
        }
    }
    legit.Start(Seconds(1.0));
    legit.Stop(Seconds(p.duration));

    // ---- attack traffic ---------------------------------------------------
    // Every generator below writes into this NS-3 process's own simulated
    // topology. There is no raw socket and no host networking anywhere in this
    // file: the destination is always `cloudAddr`, an address this program
    // itself assigned to a simulated node.
    ApplicationContainer attack;
    const std::string socketFactory =
        (p.attackType == "udp_flood" || p.attackType == "icmp_flood") ? "ns3::UdpSocketFactory"
                                                                      : "ns3::TcpSocketFactory";
    const uint16_t attackPort = (p.attackType == "http_flood") ? httpPort : mqttPort;
    const uint16_t targetPort =
        (p.attackType == "udp_flood" || p.attackType == "icmp_flood") ? coapPort : attackPort;

    // OnOff expresses rate as bits/second; convert the configured packet rate.
    const uint64_t attackBps =
        static_cast<uint64_t>(p.attackPps * (p.attackBytes + 28) * 8.0);
    std::ostringstream rate;
    rate << attackBps << "bps";

    for (uint32_t i = 0; i < p.nAttackers; ++i)
    {
        OnOffHelper app(socketFactory, InetSocketAddress(cloudAddr, targetPort));
        app.SetAttribute("DataRate", StringValue(rate.str()));
        app.SetAttribute("PacketSize", UintegerValue(p.attackBytes));
        app.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        app.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        attack.Add(app.Install(attackers.Get(i)));
    }
    attack.Start(Seconds(p.attackStart));
    attack.Stop(Seconds(p.attackStart + p.attackDuration));

    // ---- tracing ----------------------------------------------------------
    HookTraces(cloud);
    HookTraces(gateway);
    HookTraces(routers);
    HookTraces(iot);
    HookTraces(attackers);

    // Drop-tail overflow is reported by the queue's DropBeforeEnqueue trace,
    // not by the legacy "Drop" source, which stays silent on a modern ns-3 and
    // would have this model report zero loss while a fifth of the offered load
    // was in fact being discarded. Both post-dequeue drops and the enqueue
    // rejection are counted; ConnectFailSafe is used so a path that does not
    // resolve is reported rather than silently ignored.
    // InternetStackHelper installs a TrafficControlLayer with a default queue
    // disc in front of every device, so under congestion the packet is
    // discarded *there*, before it ever reaches the device transmit queue.
    // Tracing only the device queue therefore reports zero loss on a link that
    // is visibly saturated; both layers must be counted.
    const char* discPaths[] = {
        "/NodeList/*/$ns3::TrafficControlLayer/RootQueueDiscList/*/DropBeforeEnqueue",
        "/NodeList/*/$ns3::TrafficControlLayer/RootQueueDiscList/*/DropAfterDequeue",
    };
    for (const char* path : discPaths)
    {
        if (!Config::ConnectWithoutContextFailSafe(path, MakeCallback(&OnQueueDiscDrop)))
        {
            std::cerr << "WARNING: could not connect queue-disc drop trace " << path
                      << std::endl;
        }
    }

    const char* devicePaths[] = {
        "/NodeList/*/DeviceList/*/$ns3::PointToPointNetDevice/TxQueue/DropBeforeEnqueue",
        "/NodeList/*/DeviceList/*/$ns3::PointToPointNetDevice/TxQueue/DropAfterDequeue",
    };
    for (const char* path : devicePaths)
    {
        if (!Config::ConnectWithoutContextFailSafe(path, MakeCallback(&OnQueueDrop)))
        {
            std::cerr << "WARNING: could not connect device drop trace " << path
                      << std::endl;
        }
    }

    // ---- run --------------------------------------------------------------
    Simulator::Stop(Seconds(p.duration));
    Simulator::Run();
    Simulator::Destroy();

    WriteFlows(p.outputDir + "/ns3_flows.csv");
    WriteWindows(p.outputDir + "/ns3_windows.csv");
    WriteRunJson(p.outputDir + "/ns3_run.json", iot, attackers);

    std::cout << "NetShield NS-3 run complete: " << g_flows.size() << " flow records, "
              << g_totalOffered << " offered, " << g_totalDelivered << " delivered, "
              << g_totalDropped << " dropped." << std::endl;
    std::cout << "NS3_OUTPUT_OK " << p.outputDir << "/ns3_flows.csv" << std::endl;
    return 0;
}
