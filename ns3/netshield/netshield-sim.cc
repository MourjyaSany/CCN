/* =============================================================================
 * NetShield-GNN :: generic spec-driven NS-3 model
 *
 * PURPOSE
 *   This is the primary simulation engine of NetShield-GNN. The Python side
 *   (netshield.simulation.ns3_spec) writes a plain-text specification of one
 *   scenario -- every node, every link, the device applications and the
 *   compromised-device load -- and this program builds exactly that network
 *   in NS-3 and runs it over the real TCP/IP stack. Because the whole graph is
 *   data, every topology family (tree, star, multi-gateway, dumbbell,
 *   fat-tree, mesh, ring) is a genuine NS-3 network rather than a special case
 *   in C++.
 *
 *   It exports per-flow and per-window telemetry under the same field names as
 *   the Python telemetry classes, so feature extraction, graph construction
 *   and the detectors consume NS-3 output unchanged.
 *
 * TRAFFIC
 *   All traffic -- legitimate device traffic and the elevated load from
 *   compromised devices -- is produced by NS-3's own application helpers
 *   (OnOffApplication, PacketSink) sending from each node's real assigned
 *   address through the real stack. This program never assembles a packet by
 *   hand and never alters a source address, so a compromised node's traffic is
 *   always attributable to the node that sent it -- exactly the ingress
 *   identity the gateway enforcer keys on.
 *
 * SAFETY
 *   Every packet is created inside this simulation and addressed to a node
 *   this program instantiated. No host network interface is touched.
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
#include "ns3/mobility-module.h"
#ifdef NETSHIELD_ANIM
#include "ns3/netanim-module.h"
#endif

#include <algorithm>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("NetShieldSim");

namespace
{

// ===========================================================================
// Scenario specification (written by netshield.simulation.ns3_spec)
// ===========================================================================
struct NodeSpec
{
    std::string id;
    std::string kind;        // cloud | gateway | router | iot | attacker
    int tier = 3;
    bool attacker = false;
    std::string deviceClass; // mqtt_sensor | http_client | tcp_uploader | udp_streamer | -
    double forwardingPps = 0.0;
    uint32_t procQueue = 0;
};

struct LinkSpec
{
    uint32_t a = 0;
    uint32_t b = 0;
    double bandwidthBps = 1e7;
    double delayS = 0.001;
    uint32_t queuePackets = 100;
    double loss = 0.0;
};

struct AppSpec
{
    uint32_t node = 0;
    std::string kind;   // mqtt | http | bulk | coap
    double rateBps = 0; // mean offered application rate
    uint32_t pkt = 256; // representative packet size
    uint16_t port = 0;
    double onS = 1.0;
    double offS = 0.0;
    double start = 1.0;
};

struct BotSpec
{
    uint32_t node = 0;
    std::string family;
    double rateBps = 0; // this bot's offered rate (jitter already applied)
    uint32_t pkt = 512;
    double joinOffset = 0.0;
    std::string socket = "ns3::UdpSocketFactory";
    uint16_t port = 5683;
};

struct Spec
{
    std::map<std::string, std::string> params;
    std::vector<NodeSpec> nodes;
    std::vector<LinkSpec> links;
    std::vector<AppSpec> apps;
    std::vector<BotSpec> bots;
    uint32_t cloud = 0;
    std::vector<uint32_t> enforcement;

    double duration = 90.0;
    double windowS = 5.0;
    uint32_t seed = 42;
    std::string topology = "tree";
    std::string outputDir = ".";

    bool attackEnabled = false;
    double atkStart = 0.0;
    double atkDuration = 0.0;
    std::string atkType = "udp_flood";
    uint16_t atkPort = 5683;
    std::string atkSocket = "ns3::UdpSocketFactory";
    bool burst = false;
    double burstOn = 2.0;
    double burstOff = 3.0;
    std::string profile = "constant";
    double rampLo = 0.1;
    double rampHi = 1.0;
    double sinePeriod = 10.0;
    double sineDepth = 0.5;
    double stepInterval = 5.0;
    std::vector<double> stepLevels;

    double P(const std::string& k, double d) const
    {
        auto it = params.find(k);
        return it == params.end() ? d : std::stod(it->second);
    }
    std::string S(const std::string& k, const std::string& d) const
    {
        auto it = params.find(k);
        return it == params.end() ? d : it->second;
    }
};

Spec g_spec;

Spec
ReadSpec(const std::string& path)
{
    std::ifstream in(path);
    if (!in.is_open())
    {
        NS_FATAL_ERROR("Cannot open spec file " << path);
    }
    Spec s;
    std::string line;
    while (std::getline(in, line))
    {
        if (line.empty() || line[0] == '#')
        {
            continue;
        }
        std::istringstream ss(line);
        std::string kw;
        ss >> kw;
        if (kw == "param")
        {
            std::string k, v;
            ss >> k >> v;
            s.params[k] = v;
        }
        else if (kw == "node")
        {
            NodeSpec n;
            int atk = 0;
            ss >> n.id >> n.kind >> n.tier >> atk >> n.deviceClass >> n.forwardingPps >>
                n.procQueue;
            n.attacker = atk != 0;
            s.nodes.push_back(n);
        }
        else if (kw == "link")
        {
            LinkSpec l;
            ss >> l.a >> l.b >> l.bandwidthBps >> l.delayS >> l.queuePackets >> l.loss;
            s.links.push_back(l);
        }
        else if (kw == "cloud")
        {
            ss >> s.cloud;
        }
        else if (kw == "enforce")
        {
            uint32_t n;
            while (ss >> n)
            {
                s.enforcement.push_back(n);
            }
        }
        else if (kw == "app")
        {
            AppSpec a;
            ss >> a.node >> a.kind >> a.rateBps >> a.pkt >> a.port >> a.onS >> a.offS >> a.start;
            s.apps.push_back(a);
        }
        else if (kw == "bot")
        {
            BotSpec b;
            int tcp = 0;
            ss >> b.node >> b.family >> b.rateBps >> b.pkt >> b.joinOffset >> tcp >> b.port;
            b.socket = tcp ? "ns3::TcpSocketFactory" : "ns3::UdpSocketFactory";
            s.bots.push_back(b);
        }
        else if (kw == "steplevels")
        {
            double v;
            while (ss >> v)
            {
                s.stepLevels.push_back(v);
            }
        }
    }
    s.duration = s.P("duration", 90.0);
    s.windowS = s.P("window_s", 5.0);
    s.seed = static_cast<uint32_t>(s.P("seed", 42));
    s.topology = s.S("topology", "tree");
    s.outputDir = s.S("output_dir", ".");
    s.attackEnabled = s.P("attack_enabled", 0) != 0;
    s.atkStart = s.P("attack_start", 0.0);
    s.atkDuration = s.P("attack_duration", 0.0);
    s.atkType = s.S("attack_type", "udp_flood");
    s.atkPort = static_cast<uint16_t>(s.P("attack_port", 5683));
    s.atkSocket = s.S("attack_socket", "ns3::UdpSocketFactory");
    s.burst = s.P("burst", 0) != 0;
    s.burstOn = s.P("burst_on", 2.0);
    s.burstOff = s.P("burst_off", 3.0);
    s.profile = s.S("profile", "constant");
    s.rampLo = s.P("ramp_lo", 0.1);
    s.rampHi = s.P("ramp_hi", 1.0);
    s.sinePeriod = s.P("sine_period", 10.0);
    s.sineDepth = s.P("sine_depth", 0.5);
    s.stepInterval = s.P("step_interval", 5.0);
    if (s.stepLevels.empty())
    {
        s.stepLevels = {0.25, 0.5, 0.75, 1.0};
    }
    return s;
}

// ===========================================================================
// Flow and window accounting (schema matches netshield.simulation.telemetry)
// ===========================================================================
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
    std::vector<double> latencySamples;
    std::vector<double> legitLatencySamples;
};

std::map<FlowKey, FlowStats> g_flows;
std::map<uint32_t, WindowStats> g_windows;
std::map<uint64_t, double> g_sentAt;       // packet UID -> send time
std::map<uint32_t, std::string> g_ipToNode;
std::map<uint32_t, bool> g_ipIsAttacker;
uint64_t g_totalOffered = 0;
uint64_t g_totalDelivered = 0;
uint64_t g_totalDropped = 0;

uint32_t
WindowOf(double t)
{
    return static_cast<uint32_t>(std::floor(t / g_spec.windowS));
}

std::string
NodeIdFor(const Ipv4Address& addr)
{
    auto it = g_ipToNode.find(addr.Get());
    if (it != g_ipToNode.end())
    {
        return it->second;
    }
    std::ostringstream oss;
    oss << "ext-" << Ipv4Address(addr);
    return oss.str();
}

bool
IsAttackSource(const Ipv4Address& addr)
{
    auto it = g_ipIsAttacker.find(addr.Get());
    return it != g_ipIsAttacker.end() && it->second;
}

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
    if (protocol == 6)
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
    else if (protocol == 17)
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
}

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

} // namespace

#include "netshield-trace.h"

int
main(int argc, char* argv[])
{
    std::string specPath;
    CommandLine cmd(__FILE__);
    cmd.AddValue("spec", "Path to the scenario specification file", specPath);
    cmd.Parse(argc, argv);
    if (specPath.empty())
    {
        NS_FATAL_ERROR("--spec=<file> is required");
    }
    g_spec = ReadSpec(specPath);
    Spec& s = g_spec;

    RngSeedManager::SetSeed(s.seed);
    RngSeedManager::SetRun(1);

    // ---- nodes ------------------------------------------------------------
    NodeContainer nodes;
    nodes.Create(s.nodes.size());
    InternetStackHelper stack;
    stack.Install(nodes);

    // ---- links (the whole topology is data) -------------------------------
    Ipv4AddressHelper ipv4;
    uint32_t subnet = 1;
    auto nextBase = [&subnet]() {
        std::ostringstream oss;
        oss << "10." << ((subnet >> 8) & 0xFF) << "." << (subnet & 0xFF) << ".0";
        subnet += 1;
        return oss.str();
    };
    for (const LinkSpec& l : s.links)
    {
        PointToPointHelper p2p;
        std::ostringstream rate;
        rate << static_cast<uint64_t>(l.bandwidthBps) << "bps";
        p2p.SetDeviceAttribute("DataRate", StringValue(rate.str()));
        std::ostringstream delay;
        delay << l.delayS << "s";
        p2p.SetChannelAttribute("Delay", StringValue(delay.str()));
        std::ostringstream q;
        q << l.queuePackets << "p";
        p2p.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize", StringValue(q.str()));
        NetDeviceContainer dev = p2p.Install(nodes.Get(l.a), nodes.Get(l.b));
        if (l.loss > 0.0)
        {
            Ptr<RateErrorModel> em = CreateObject<RateErrorModel>();
            em->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
            em->SetRate(l.loss);
            dev.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(em));
        }
        ipv4.SetBase(nextBase().c_str(), "255.255.255.0");
        Ipv4InterfaceContainer ifc = ipv4.Assign(dev);
        // Attribute each interface address to its node id, so flow records
        // name real devices rather than raw addresses.
        for (uint32_t side = 0; side < 2; ++side)
        {
            uint32_t idx = side == 0 ? l.a : l.b;
            g_ipToNode[ifc.GetAddress(side).Get()] = s.nodes[idx].id;
            g_ipIsAttacker[ifc.GetAddress(side).Get()] = s.nodes[idx].attacker;
        }
    }

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // The cloud's address, as seen by the fleet, is the one every device and
    // bot targets. Use the first interface the cloud node owns.
    Ptr<Ipv4> cloudIpv4 = nodes.Get(s.cloud)->GetObject<Ipv4>();
    Ipv4Address cloudAddr = cloudIpv4->GetAddress(1, 0).GetLocal();

    // ---- cloud services ---------------------------------------------------
    const std::set<uint16_t> ports = {8883, 80, 443, 5683};
    ApplicationContainer sinks;
    for (uint16_t port : ports)
    {
        std::string factory = port == 5683 ? "ns3::UdpSocketFactory" : "ns3::TcpSocketFactory";
        PacketSinkHelper sink(factory, InetSocketAddress(Ipv4Address::GetAny(), port));
        sinks.Add(sink.Install(nodes.Get(s.cloud)));
    }
    sinks.Start(Seconds(0.0));
    sinks.Stop(Seconds(s.duration));

    // ---- legitimate IoT device traffic ------------------------------------
    // Each device is an OnOff application whose mean rate and packet size come
    // from its device class, sending from its own address to the cloud.
    ApplicationContainer legit;
    for (const AppSpec& a : s.apps)
    {
        std::string factory = a.kind == "coap" ? "ns3::UdpSocketFactory" : "ns3::TcpSocketFactory";
        OnOffHelper app(factory, InetSocketAddress(cloudAddr, a.port));
        std::ostringstream rate;
        rate << static_cast<uint64_t>(std::max(1.0, a.rateBps)) << "bps";
        app.SetAttribute("DataRate", StringValue(rate.str()));
        app.SetAttribute("PacketSize", UintegerValue(a.pkt));
        std::ostringstream on, off;
        on << "ns3::ConstantRandomVariable[Constant=" << a.onS << "]";
        off << "ns3::ConstantRandomVariable[Constant=" << a.offS << "]";
        app.SetAttribute("OnTime", StringValue(on.str()));
        app.SetAttribute("OffTime", StringValue(off.str()));
        ApplicationContainer installed = app.Install(nodes.Get(a.node));
        installed.Start(Seconds(a.start));
        installed.Stop(Seconds(s.duration));
        legit.Add(installed);
    }

    // ---- elevated load from compromised devices ---------------------------
    // Every compromised device runs a standard OnOff application from its own
    // real address to the cloud. The attack family selects the transport and
    // target port; the per-bot rate (jitter already applied by the Python
    // side) is the application data rate. Non-volumetric families are load
    // approximations here and are recorded as such in the run metadata.
    std::vector<Ptr<OnOffApplication>> botApps;
    for (const BotSpec& b : s.bots)
    {
        OnOffHelper app(b.socket, InetSocketAddress(cloudAddr, b.port));
        std::ostringstream rate;
        rate << static_cast<uint64_t>(std::max(1.0, b.rateBps)) << "bps";
        app.SetAttribute("DataRate", StringValue(rate.str()));
        app.SetAttribute("PacketSize", UintegerValue(b.pkt));
        app.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        app.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        ApplicationContainer installed = app.Install(nodes.Get(b.node));
        installed.Start(Seconds(s.atkStart + b.joinOffset));
        installed.Stop(Seconds(s.atkStart + s.atkDuration));
        botApps.push_back(DynamicCast<OnOffApplication>(installed.Get(0)));
    }

    // Rate waveform and on/off pulsing are applied by rescheduling each bot's
    // offered DataRate at window granularity over the attack interval.
    if (s.attackEnabled && !botApps.empty() && (s.profile != "constant" || s.burst))
    {
        ScheduleWaveform(botApps, s);
    }

    // ---- optional NetAnim animation --------------------------------------
    // When the spec sets anim_file, lay the nodes out by tier and write a
    // NetAnim trace so the run can be watched in the NS-3 animator GUI. This
    // is for small demonstration scenarios; an animation of a full flood would
    // be unreadable, so the Python side only sets anim_file for short runs.
    const std::string animFile = s.S("anim_file", "");
    if (!animFile.empty())
    {
        MobilityHelper mobility;
        mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        mobility.Install(nodes);
        // Place each node by tier: cloud top-centre, then gateways, routers,
        // and the device fleet spread along the bottom row.
        std::map<int, std::vector<uint32_t>> byTier;
        for (uint32_t i = 0; i < s.nodes.size(); ++i)
        {
            byTier[s.nodes[i].tier].push_back(i);
        }
        for (auto& [tier, idxs] : byTier)
        {
            const double span = 100.0;
            const double step = idxs.size() > 1 ? span / (idxs.size() - 1) : 0.0;
            for (size_t j = 0; j < idxs.size(); ++j)
            {
                const double x = idxs.size() > 1 ? j * step : span / 2.0;
                const double y = tier * 25.0;
                nodes.Get(idxs[j])->GetObject<MobilityModel>()->SetPosition(
                    Vector(x, y, 0.0));
            }
        }
#ifdef NETSHIELD_ANIM
        AnimationInterface* anim = new AnimationInterface(animFile);
        anim->EnablePacketMetadata(true);
        anim->SetMaxPktsPerTraceFile(500000);
        for (uint32_t i = 0; i < s.nodes.size(); ++i)
        {
            anim->UpdateNodeDescription(nodes.Get(i), s.nodes[i].id);
            if (s.nodes[i].kind == "cloud")
                anim->UpdateNodeColor(nodes.Get(i), 0, 120, 255);
            else if (s.nodes[i].kind == "gateway" || s.nodes[i].kind == "router")
                anim->UpdateNodeColor(nodes.Get(i), 150, 150, 150);
            else if (s.nodes[i].attacker)
                anim->UpdateNodeColor(nodes.Get(i), 230, 50, 50);
            else
                anim->UpdateNodeColor(nodes.Get(i), 40, 190, 90);
        }
#endif
    }

    // ---- tracing ----------------------------------------------------------
    HookTraces(nodes);
    ConnectQueueDropTraces();

    Simulator::Stop(Seconds(s.duration));
    Simulator::Run();
    Simulator::Destroy();

    WriteFlows(s.outputDir + "/ns3_flows.csv");
    WriteWindows(s.outputDir + "/ns3_windows.csv");
    WriteRunJson(s.outputDir + "/ns3_run.json");

    std::cout << "NetShield NS-3 run complete: " << g_flows.size() << " flow records, "
              << g_totalOffered << " offered, " << g_totalDelivered << " delivered, "
              << g_totalDropped << " dropped." << std::endl;
    std::cout << "NS3_OUTPUT_OK " << s.outputDir << "/ns3_flows.csv" << std::endl;
    return 0;
}
