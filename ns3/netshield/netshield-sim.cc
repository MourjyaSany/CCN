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
#include "ns3/ipv4-queue-disc-item.h"
#include "ns3/network-module.h"
#include "ns3/node-list.h"
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
#include <cstdio>
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
    // Exact victim-side accounting. Every packet addressed to the cloud is
    // classified once, at its origin, as attack or legitimate, and counted
    // again if and only if it is actually delivered at the cloud. Mitigation
    // effectiveness and goodput preservation are then direct ratios of these
    // four counters, so they are always within [0, 1]. (Inferring attack
    // delivery by subtracting legitimate from total delivery is wrong: total
    // delivery also contains TCP ACKs and other return traffic.)
    uint64_t atkOfferedCloud = 0;
    uint64_t atkDeliveredCloud = 0;
    uint64_t legitOfferedCloud = 0;
    uint64_t legitDeliveredCloud = 0;
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
std::map<uint32_t, uint32_t> g_ipToNodeIndex;  // source IP -> node index (for anim)
std::map<uint32_t, bool> g_ipIsAttacker;
uint64_t g_totalOffered = 0;
uint64_t g_totalDelivered = 0;
uint64_t g_totalDropped = 0;
uint64_t g_gatewayBlockedPackets = 0;
uint64_t g_gatewayBlockedAttackPackets = 0;
uint64_t g_gatewayBlockedLegitPackets = 0;
uint64_t g_progressLastBlockedPackets = 0;
double g_progressLastTime = 0.0;
double g_gatewayBlockedPps = 0.0;

// Victim-side (cloud) accounting, matching the per-window counters above.
uint64_t g_atkOfferedCloud = 0;
uint64_t g_atkDeliveredCloud = 0;
uint64_t g_legitOfferedCloud = 0;
uint64_t g_legitDeliveredCloud = 0;
//: uid -> 1 (attack) or 2 (legitimate), for packets addressed to the cloud.
std::map<uint64_t, uint8_t> g_cloudPktClass;

/** True when *addr* is an address of the cloud (victim) node. */
bool
IsToCloud(const Ipv4Address& addr)
{
    auto it = g_ipToNodeIndex.find(addr.Get());
    return it != g_ipToNodeIndex.end() && it->second == g_spec.cloud;
}
#ifdef NETSHIELD_ANIM
AnimationInterface* g_anim = nullptr;       // set when a NetAnim trace is written
int g_quarantined = 0;                      // blocked bots moved to the quarantine row
uint32_t g_cntBlocked = 0;                  // NetAnim node-counter id: packets blocked
uint32_t g_cntThrottled = 0;                // NetAnim node-counter id: packets throttled
bool g_countersReady = false;
//: enforcement node -> the neighbour on its upstream (victim-facing) link,
//: so that link can be labelled with what the policer is doing to it.
std::map<uint32_t, uint32_t> g_uplinkOf;
#endif

// Recolour a source's node in the NetAnim trace when its enforcement state
// changes, so the animation visibly shows the flood being throttled (orange)
// or cut off (dark red) and then released (back to attacker red).
void
RecolourSource(uint32_t ip, int action)
{
#ifdef NETSHIELD_ANIM
    if (!g_anim)
    {
        return;
    }
    auto it = g_ipToNodeIndex.find(ip);
    if (it == g_ipToNodeIndex.end())
    {
        return;
    }
    uint32_t idx = it->second;
    if (idx == g_spec.cloud)
    {
        return; // the victim is never recoloured: only offending nodes change
    }
    Ptr<Node> node = NodeList::GetNode(idx);
    const std::string base = g_spec.nodes[idx].id;
    if (action == 1) // rate-limited: bright orange, still full size (still emitting)
    {
        g_anim->UpdateNodeColor(node, 255, 150, 0);
        g_anim->UpdateNodeSize(node, 6.0, 6.0);
        g_anim->UpdateNodeDescription(node, base + " RATE-LIMITED");
    }
    else if (action >= 2) // blocked: black, shrunk, and pulled OUT of the network
    {
        g_anim->UpdateNodeColor(node, 25, 25, 25);
        g_anim->UpdateNodeSize(node, 3.0, 3.0);
        g_anim->UpdateNodeDescription(node, base + " BLOCKED");
        // Slide the bot into a quarantine row well below the topology. Moving a
        // node is NetAnim's core, always-rendered animation, so the cut-off is
        // unmistakable: the bot visibly detaches from the network. Position is
        // purely visual here -- the point-to-point links are logical, so this
        // does not change the simulation.
        Ptr<MobilityModel> mob = node->GetObject<MobilityModel>();
        if (mob)
        {
            const double qx = 10.0 + (g_quarantined % 14) * 7.0;
            const double qy = 160.0;
            mob->SetPosition(Vector(qx, qy, 0.0));
            g_quarantined++;
        }
    }
    else // released: back to attacker red, full size
    {
        g_anim->UpdateNodeColor(node, 230, 50, 50);
        g_anim->UpdateNodeSize(node, 6.0, 6.0);
        g_anim->UpdateNodeDescription(node, base);
    }
#else
    (void)ip;
    (void)action;
#endif
}

// Light up the enforcement node itself, so the animation shows *where* the
// traffic is being stopped, not just which bots are affected. The gateway goes
// red while it is dropping blocked traffic, orange while it is only shedding
// rate-limited traffic, and back to grey once the line is clear -- with the
// live per-second drop count in its label.
// Publish a source's cumulative blocked/throttled packet counts onto its own
// node, so NetAnim's node-counter tables list exactly which nodes are being
// stopped or slowed, and by how much.
void
ReportSourceCounters(uint32_t ip, uint64_t blocked, uint64_t throttled)
{
#ifdef NETSHIELD_ANIM
    if (!g_anim || !g_countersReady)
    {
        return;
    }
    auto it = g_ipToNodeIndex.find(ip);
    if (it == g_ipToNodeIndex.end())
    {
        return;
    }
    g_anim->UpdateNodeCounter(g_cntBlocked, it->second, static_cast<double>(blocked));
    g_anim->UpdateNodeCounter(g_cntThrottled, it->second, static_cast<double>(throttled));
#else
    (void)ip;
    (void)blocked;
    (void)throttled;
#endif
}

void
MarkEnforcer(uint32_t nodeIdx, uint64_t blockedPerS, uint64_t limitedPerS,
             uint64_t totalDropped)
{
#ifdef NETSHIELD_ANIM
    if (!g_anim || nodeIdx >= g_spec.nodes.size() || nodeIdx == g_spec.cloud)
    {
        return; // never recolour the victim
    }
    Ptr<Node> node = NodeList::GetNode(nodeIdx);
    const std::string base = g_spec.nodes[nodeIdx].id;
    std::ostringstream label;
    if (blockedPerS > 0)
    {
        g_anim->UpdateNodeColor(node, 220, 40, 40);
        g_anim->UpdateNodeSize(node, 9.0, 9.0);
        label << base << "  BLOCKING " << blockedPerS << " pkt/s";
    }
    else if (limitedPerS > 0)
    {
        g_anim->UpdateNodeColor(node, 255, 150, 0);
        g_anim->UpdateNodeSize(node, 8.0, 8.0);
        label << base << "  THROTTLING " << limitedPerS << " pkt/s";
    }
    else
    {
        g_anim->UpdateNodeColor(node, 150, 150, 150);
        g_anim->UpdateNodeSize(node, 6.0, 6.0);
        label << base;
    }
    label << "  DROPPED " << totalDropped << " PKTS";
    g_anim->UpdateNodeDescription(node, label.str());
    // Annotate the link the policer actually guards, so the animation shows
    // *which* hop the traffic is being stopped on, not just which node.
    auto up = g_uplinkOf.find(nodeIdx);
    if (up != g_uplinkOf.end())
    {
        std::ostringstream link;
        if (blockedPerS > 0)
        {
            link << "BLOCKING " << blockedPerS << " pkt/s";
        }
        else if (limitedPerS > 0)
        {
            link << "THROTTLING " << limitedPerS << " pkt/s";
        }
        else
        {
            link << "clear";
        }
        g_anim->UpdateLinkDescription(nodeIdx, up->second, link.str());
    }
#else
    (void)nodeIdx;
    (void)blockedPerS;
    (void)limitedPerS;
#endif
}

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

// ===========================================================================
// Data-plane enforcement: a reactive rate-based policer installed at the
// gateway (the spec's "enforce" nodes). It watches each source's packet rate
// over a feature window and escalates through the same ladder the control
// plane uses -- watch -> rate-limit (token bucket) -> block -- releasing a
// source once it goes quiet again. This is what makes the NS-3 run (and its
// NetAnim animation) show a flood being throttled and then cut off, with the
// recovery of legitimate traffic an emergent consequence of the drops. The
// GNN remains the intelligent detector in the full closed loop; this gateway
// policer is the in-simulation enforcement mechanism it drives.
//
// It only ever drops traffic (keyed on the real source address); it never
// creates or rewrites a packet, preserving the model's safety posture.
// ===========================================================================
class NetShieldPolicer : public ns3::QueueDisc
{
  public:
    static ns3::TypeId GetTypeId();
    NetShieldPolicer();
    ~NetShieldPolicer() override = default;

    void Configure(double threshPps, double rlPps, double burst, uint32_t rlAfter,
                   uint32_t blockAfter, uint32_t releaseAfter, double evalS);
    void SetEnforcerNode(uint32_t nodeIndex) { m_nodeIndex = nodeIndex; }
    void Evaluate(); // called once per evaluation interval

  private:
    struct SourceState
    {
        int action = 0;         // 0 none, 1 rate-limit, 2 block
        uint64_t windowPackets = 0;
        uint32_t badWindows = 0;
        uint32_t goodWindows = 0;
        double tokens = 0.0;
        double lastRefill = 0.0;
        uint64_t blockedPkts = 0;   // cumulative, this source
        uint64_t limitedPkts = 0;   // cumulative, this source
    };

    bool DoEnqueue(ns3::Ptr<ns3::QueueDiscItem> item) override;
    ns3::Ptr<ns3::QueueDiscItem> DoDequeue() override;
    // NB: DoPeek is deliberately NOT overridden -- the base implementation
    // dequeues into a requeue slot and overriding it desynchronises the
    // queue disc's packet accounting.
    bool CheckConfig() override;
    void InitializeParams() override;
    //: map a source address to its fair-queueing bucket.
    static uint32_t SourceBucket(uint32_t ip);
    //: give each distinct source its own bucket while buckets remain, so that
    //: a legitimate device can never share a queue with a flooding one.
    uint32_t BucketFor(uint32_t ip);
    void RecordGatewayDrop(uint32_t sourceIp);

    //: number of per-source buckets used for fair queueing.
    static const uint32_t kBuckets = 64;
    //: per-bucket backlog limit, in packets. A flooding source can only ever
    //: fill its *own* bucket, so it cannot push legitimate packets out.
    static const uint32_t kBucketLimit = 100;

    std::map<uint32_t, SourceState> m_src;
    std::map<uint32_t, uint32_t> m_bucketOf;  // source address -> bucket
    uint32_t m_nextBucket = 0;                // next unused bucket
    std::vector<int32_t> m_deficit;  // DRR deficit per bucket, bytes
    uint32_t m_rr = 0;               // DRR round-robin cursor
    uint32_t m_quantum = 1500;       // DRR quantum, bytes
    double m_threshPps = 64.0;
    double m_rlPps = 20.0;
    double m_burst = 40.0;
    uint32_t m_rlAfter = 1;
    uint32_t m_blockAfter = 2;
    uint32_t m_releaseAfter = 4;
    double m_evalS = 0.5; // how often the policer re-evaluates each source
    uint32_t m_nodeIndex = 0xFFFFFFFF; // the node this policer enforces on
    uint64_t m_blockedDrops = 0;       // packets dropped outright, this interval
    uint64_t m_limitedDrops = 0;       // packets shed by the token bucket, this interval
};

ns3::TypeId
NetShieldPolicer::GetTypeId()
{
    static ns3::TypeId tid = ns3::TypeId("ns3::NetShieldPolicer")
                                 .SetParent<ns3::QueueDisc>()
                                 .SetGroupName("TrafficControl")
                                 .AddConstructor<NetShieldPolicer>();
    return tid;
}

NS_OBJECT_ENSURE_REGISTERED(NetShieldPolicer);

NetShieldPolicer::NetShieldPolicer()
    : ns3::QueueDisc(ns3::QueueDiscSizePolicy::MULTIPLE_QUEUES),
      m_deficit(kBuckets, 0)
{
    // Sized here as well as in InitializeParams: DoDequeue indexes it, and an
    // unsized vector would be undefined behaviour rather than a clean failure.
}

void
NetShieldPolicer::Configure(double threshPps, double rlPps, double burst, uint32_t rlAfter,
                            uint32_t blockAfter, uint32_t releaseAfter, double evalS)
{
    m_threshPps = threshPps;
    m_rlPps = rlPps;
    m_burst = burst;
    m_rlAfter = std::max(1u, rlAfter);
    m_blockAfter = std::max(m_rlAfter, blockAfter);
    m_releaseAfter = std::max(1u, releaseAfter);
    m_evalS = evalS > 0.0 ? evalS : 0.5;
}

void
NetShieldPolicer::RecordGatewayDrop(uint32_t sourceIp)
{
    ++g_gatewayBlockedPackets;
    if (IsAttackSource(Ipv4Address(sourceIp)))
    {
        ++g_gatewayBlockedAttackPackets;
    }
    else
    {
        ++g_gatewayBlockedLegitPackets;
    }
}

bool
NetShieldPolicer::DoEnqueue(ns3::Ptr<ns3::QueueDiscItem> item)
{
    uint32_t src = 0;
    ns3::Ptr<ns3::Ipv4QueueDiscItem> ip = ns3::DynamicCast<ns3::Ipv4QueueDiscItem>(item);
    if (ip)
    {
        src = ip->GetHeader().GetSource().Get();
    }
    if (src != 0)
    {
        SourceState& st = m_src[src];
        st.windowPackets++; // count the arrival for rate detection, even if dropped
        if (st.action >= 2) // blocked
        {
            m_blockedDrops++;
            st.blockedPkts++;
            RecordGatewayDrop(src);
            DropBeforeEnqueue(item, "netshield-block");
            return false;
        }
        if (st.action == 1) // rate-limited: token bucket
        {
            double now = ns3::Simulator::Now().GetSeconds();
            double elapsed = std::max(0.0, now - st.lastRefill);
            st.lastRefill = now;
            st.tokens = std::min(m_burst, st.tokens + elapsed * m_rlPps);
            if (st.tokens >= 1.0)
            {
                st.tokens -= 1.0;
            }
            else
            {
                m_limitedDrops++;
                st.limitedPkts++;
                RecordGatewayDrop(src);
                DropBeforeEnqueue(item, "netshield-ratelimit");
                return false;
            }
        }
    }
    // Admitted: hand the packet to the child queue disc (FqCoDel), which gives
    // every flow its own queue with CoDel AQM. That per-flow isolation is what
    // stops a flood from crowding legitimate packets out of the buffer during
    // the brief interval before the policer has classified it.
    // Admitted: place it in this source's own bucket. Per-source bucketing is
    // what protects legitimate traffic: a flood can only fill the bucket it
    // hashes into, so it can never consume the whole buffer and push
    // legitimate packets out, even in the interval before it is classified.
    const uint32_t bucket = (src ? BucketFor(src) : 0);
    ns3::Ptr<ns3::QueueDisc::InternalQueue> q = GetInternalQueue(bucket);
    if (q->GetNPackets() >= kBucketLimit)
    {
        RecordGatewayDrop(src);
        DropBeforeEnqueue(item, "netshield-bucket-full");
        return false;
    }
    return q->Enqueue(item);
}

ns3::Ptr<ns3::QueueDiscItem>
NetShieldPolicer::DoDequeue()
{
    // Deficit Round Robin across the per-source buckets: every backlogged
    // source gets an equal share of the link, so one flooding source cannot
    // starve the others of service.
    for (uint32_t i = 0; i < 2 * kBuckets; ++i)
    {
        ns3::Ptr<ns3::QueueDisc::InternalQueue> q = GetInternalQueue(m_rr);
        if (q->GetNPackets() == 0)
        {
            m_deficit[m_rr] = 0;
            m_rr = (m_rr + 1) % kBuckets;
            continue;
        }
        ns3::Ptr<const ns3::QueueDiscItem> head = q->Peek();
        const int32_t sz = head ? static_cast<int32_t>(head->GetSize()) : 0;
        if (m_deficit[m_rr] < sz)
        {
            m_deficit[m_rr] += static_cast<int32_t>(m_quantum);
            m_rr = (m_rr + 1) % kBuckets;
            continue;
        }
        ns3::Ptr<ns3::QueueDiscItem> item = q->Dequeue();
        if (item)
        {
            m_deficit[m_rr] -= static_cast<int32_t>(item->GetSize());
        }
        return item;
    }
    return nullptr;
}

bool
NetShieldPolicer::CheckConfig()
{
    if (GetNPacketFilters() > 0)
    {
        NS_LOG_ERROR("NetShieldPolicer cannot have packet filters");
        return false;
    }
    if (GetNQueueDiscClasses() > 0)
    {
        NS_LOG_ERROR("NetShieldPolicer cannot have child queue discs");
        return false;
    }
    if (GetNInternalQueues() == 0)
    {
        std::ostringstream lim;
        lim << kBucketLimit << "p";
        for (uint32_t i = 0; i < kBuckets; ++i)
        {
            AddInternalQueue(
                ns3::CreateObjectWithAttributes<ns3::DropTailQueue<ns3::QueueDiscItem>>(
                    "MaxSize", ns3::QueueSizeValue(ns3::QueueSize(lim.str()))));
        }
    }
    if (GetNInternalQueues() != kBuckets)
    {
        NS_LOG_ERROR("NetShieldPolicer needs " << kBuckets << " internal queues");
        return false;
    }
    return true;
}

uint32_t
NetShieldPolicer::SourceBucket(uint32_t ip)
{
    // Knuth multiplicative hash, so adjacent addresses land in different
    // buckets rather than clustering.
    return ((ip * 2654435761u) >> 16) % kBuckets;
}

uint32_t
NetShieldPolicer::BucketFor(uint32_t ip)
{
    auto it = m_bucketOf.find(ip);
    if (it != m_bucketOf.end())
    {
        return it->second;
    }
    // Hashing alone would let a legitimate device collide with a flooding one
    // and share its (saturated) queue, so hand out a dedicated bucket while
    // any remain and only fall back to hashing once they are exhausted.
    const uint32_t b = (m_nextBucket < kBuckets) ? m_nextBucket++ : SourceBucket(ip);
    m_bucketOf[ip] = b;
    return b;
}

void
NetShieldPolicer::InitializeParams()
{
    m_deficit.assign(kBuckets, 0);
    m_rr = 0;
}

void
NetShieldPolicer::Evaluate()
{
    const double thr = m_threshPps * m_evalS; // packets per evaluation interval
    for (auto& [src, st] : m_src)
    {
        const double pkts = static_cast<double>(st.windowPackets);
        st.windowPackets = 0;
        const bool flooding = pkts >= thr;
        if (flooding)
        {
            st.badWindows++;
            st.goodWindows = 0;
        }
        else
        {
            st.goodWindows++;
            if (st.action == 0)
            {
                st.badWindows = 0;
            }
        }
        int next = st.action;
        if (st.action == 0 && st.badWindows >= m_rlAfter)
        {
            next = 1; // escalate to rate-limit
        }
        if (st.badWindows >= m_blockAfter)
        {
            next = 2; // escalate to block
        }
        if (st.action != 0 && st.goodWindows >= m_releaseAfter)
        {
            next = 0; // release after the source goes quiet
        }
        if (next != st.action)
        {
            st.action = next;
            if (next == 1)
            {
                st.tokens = m_burst;
                st.lastRefill = ns3::Simulator::Now().GetSeconds();
            }
            RecolourSource(src, next);
        }
        if (st.blockedPkts || st.limitedPkts)
        {
            ReportSourceCounters(src, st.blockedPkts, st.limitedPkts);
        }
    }
    // Report this interval's enforcement activity on the gateway node itself.
    if (m_nodeIndex != 0xFFFFFFFF)
    {
        const double perSec = m_evalS > 0.0 ? 1.0 / m_evalS : 1.0;
        MarkEnforcer(m_nodeIndex,
                     static_cast<uint64_t>(m_blockedDrops * perSec),
                     static_cast<uint64_t>(m_limitedDrops * perSec),
                     g_gatewayBlockedPackets);
    }
    m_blockedDrops = 0;
    m_limitedDrops = 0;
    ns3::Simulator::Schedule(ns3::Seconds(m_evalS), &NetShieldPolicer::Evaluate, this);
}

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

    // TCP-transport families (SYN/ACK/HTTP/slowloris approximations) are
    // offered-load models: without a large socket buffer the OnOff application
    // stalls on a full send buffer long before it reaches its configured rate,
    // so the "flood" never becomes volumetric and there is nothing to mitigate.
    // Congestion control still applies, so the bottleneck remains the limit.
    Config::SetDefault("ns3::TcpSocket::SndBufSize", UintegerValue(4 * 1024 * 1024));
    Config::SetDefault("ns3::TcpSocket::RcvBufSize", UintegerValue(4 * 1024 * 1024));

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
            g_ipToNodeIndex[ifc.GetAddress(side).Get()] = idx;
            g_ipIsAttacker[ifc.GetAddress(side).Get()] = s.nodes[idx].attacker;
        }
    }

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // The cloud's address, as seen by the fleet, is the one every device and
    // bot targets. Use the first interface the cloud node owns.
    Ptr<Ipv4> cloudIpv4 = nodes.Get(s.cloud)->GetObject<Ipv4>();
    Ipv4Address cloudAddr = cloudIpv4->GetAddress(1, 0).GetLocal();

    // ---- cloud services ---------------------------------------------------
    // Listen on both transports for every service port: legitimate devices use
    // TCP for MQTT/HTTP/upload and UDP for CoAP, while attack load may arrive
    // on either, and traffic the victim does not absorb would otherwise be
    // discarded at the transport layer rather than counted as reaching it.
    const std::set<uint16_t> ports = {8883, 80, 443, 5683};
    ApplicationContainer sinks;
    for (uint16_t port : ports)
    {
        for (const char* factory : {"ns3::TcpSocketFactory", "ns3::UdpSocketFactory"})
        {
            PacketSinkHelper sink(factory, InetSocketAddress(Ipv4Address::GetAny(), port));
            sinks.Add(sink.Install(nodes.Get(s.cloud)));
        }
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
        g_anim = new AnimationInterface(animFile);
        g_anim->EnablePacketMetadata(true);
        g_anim->SetMaxPktsPerTraceFile(500000);
        // Per-node counters, shown by NetAnim in its node-counter tables: they
        // name exactly which nodes are being stopped or slowed, and by how much.
        g_cntBlocked = g_anim->AddNodeCounter("Blocked pkts",
                                              AnimationInterface::UINT32_COUNTER);
        g_cntThrottled = g_anim->AddNodeCounter("Throttled pkts",
                                                AnimationInterface::UINT32_COUNTER);
        g_countersReady = true;
        // The upstream (victim-facing) neighbour of each enforcement node is the
        // adjacent node closest to the cloud, i.e. the one with the lowest tier.
        for (uint32_t enf : s.enforcement)
        {
            if (enf >= s.nodes.size())
            {
                continue;
            }
            int best = -1;
            int bestTier = 1 << 30;
            for (const LinkSpec& l : s.links)
            {
                uint32_t other = (l.a == enf) ? l.b : (l.b == enf ? l.a : 0xFFFFFFFF);
                if (other == 0xFFFFFFFF || other >= s.nodes.size())
                {
                    continue;
                }
                if (s.nodes[other].tier < bestTier)
                {
                    bestTier = s.nodes[other].tier;
                    best = static_cast<int>(other);
                }
            }
            if (best >= 0)
            {
                g_uplinkOf[enf] = static_cast<uint32_t>(best);
            }
        }
        for (uint32_t i = 0; i < s.nodes.size(); ++i)
        {
            g_anim->UpdateNodeDescription(nodes.Get(i), s.nodes[i].id);
            if (s.nodes[i].kind == "cloud")
            {
                g_anim->UpdateNodeColor(nodes.Get(i), 0, 120, 255);
                g_anim->UpdateNodeSize(nodes.Get(i), 8.0, 8.0); // the target stands out
            }
            else if (s.nodes[i].kind == "gateway" || s.nodes[i].kind == "router")
            {
                g_anim->UpdateNodeColor(nodes.Get(i), 150, 150, 150);
                g_anim->UpdateNodeSize(nodes.Get(i), 6.0, 6.0);
            }
            else if (s.nodes[i].attacker)
            {
                g_anim->UpdateNodeColor(nodes.Get(i), 230, 50, 50);
                g_anim->UpdateNodeSize(nodes.Get(i), 6.0, 6.0); // baseline, shrinks when blocked
            }
            else
            {
                g_anim->UpdateNodeColor(nodes.Get(i), 40, 190, 90);
                g_anim->UpdateNodeSize(nodes.Get(i), 4.0, 4.0);
            }
        }
#endif
    }

    // ---- data-plane enforcement (reactive gateway policer) ----------------
    // When mitigation is enabled, install a NetShieldPolicer on every link of
    // every enforcement ("gateway") node and start its per-window evaluation.
    // The policer reacts to each source's observed rate and escalates through
    // the ladder; dropped flood traffic is what lets the cloud and the healthy
    // fleet recover, visibly, during the run and in NetAnim.
    if (s.P("mitigation_enabled", 0) != 0 && !s.enforcement.empty())
    {
        std::vector<Ptr<NetShieldPolicer>> policers;
        TrafficControlHelper tch;
        // The policer is the whole root queue disc: it classifies and polices
        // each source, then fair-queues the admitted traffic across per-source
        // buckets (DRR). Policing decides *whether* a packet is admitted; the
        // fair queue decides the order of what is.
        tch.SetRootQueueDisc("ns3::NetShieldPolicer");
        const double threshPps = s.P("mitigation_rate_pps", 50.0);
        const double rlPps = s.P("mitigation_ratelimit_pps", 20.0);
        const double burst = s.P("mitigation_burst", 40.0);
        const uint32_t rlAfter = static_cast<uint32_t>(s.P("mitigation_ratelimit_after", 1));
        const uint32_t blockAfter = static_cast<uint32_t>(s.P("mitigation_block_after", 2));
        const uint32_t releaseAfter = static_cast<uint32_t>(s.P("mitigation_release_after", 6));
        const double evalS = s.P("mitigation_eval_s", 0.5);
        for (uint32_t enf : s.enforcement)
        {
            if (enf >= s.nodes.size())
            {
                continue;
            }
            Ptr<Node> node = nodes.Get(enf);
            const uint32_t nDev = node->GetNDevices();
            for (uint32_t d = 0; d < nDev; ++d)
            {
                Ptr<NetDevice> dev = node->GetDevice(d);
                if (!dev->GetObject<PointToPointNetDevice>())
                {
                    continue; // skip the loopback device
                }
                tch.Uninstall(dev);                 // drop the stack's default qdisc
                QueueDiscContainer qd = tch.Install(dev);
                for (uint32_t qi = 0; qi < qd.GetN(); ++qi)
                {
                    Ptr<NetShieldPolicer> pol = DynamicCast<NetShieldPolicer>(qd.Get(qi));
                    if (pol)
                    {
                        pol->Configure(threshPps, rlPps, burst, rlAfter, blockAfter,
                                       releaseAfter, evalS);
                        pol->SetEnforcerNode(enf);
                        policers.push_back(pol);
                    }
                }
            }
        }
        for (auto& pol : policers)
        {
            Simulator::Schedule(Seconds(evalS), &NetShieldPolicer::Evaluate, pol);
        }
        NS_LOG_UNCOND("NetShield: installed " << policers.size()
                      << " gateway policer(s); mitigation enabled.");
    }

    // ---- tracing ----------------------------------------------------------
    HookTraces(nodes);
    ConnectQueueDropTraces();

    ScheduleLiveProgress();
    Simulator::Stop(Seconds(s.duration));
    Simulator::Run();
    WriteLiveProgress();
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
