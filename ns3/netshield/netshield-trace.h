/* =============================================================================
 * NetShield-GNN :: NS-3 tracing, CSV export and attack-rate waveform.
 *
 * Included by netshield-sim.cc. Kept in a header purely to keep the main file
 * focused on topology and traffic; everything here is trace-sink bookkeeping
 * and file output.
 *
 * The IP-layer taps (SendOutgoing / LocalDeliver / Drop) recover genuine
 * per-flow TCP flag counts, packet-size and inter-arrival statistics and
 * end-to-end delay, which FlowMonitor cannot expose. The column names written
 * here are identical to netshield.simulation.telemetry, so the same feature
 * extractor consumes output from either engine.
 * =============================================================================
 */
#ifndef NETSHIELD_TRACE_H
#define NETSHIELD_TRACE_H

// ---- trace sinks ----------------------------------------------------------

/** A node's IP layer offered a packet: flow and offered-load accounting. */
void
OnSendOutgoing(const Ipv4Header& header, Ptr<const Packet> packet, uint32_t /*interface*/)
{
    const double now = Simulator::Now().GetSeconds();
    if (now >= g_spec.duration)
    {
        return;
    }
    uint16_t sport, dport;
    uint8_t flags;
    uint32_t payload;
    ExtractTransport(packet, header.GetProtocol(), sport, dport, flags, payload);

    FlowStats& st = g_flows[KeyFor(header, sport, dport, now)];
    const uint32_t wire = packet->GetSize() + header.GetSerializedSize() + 18;

    st.packets += 1;
    st.bytes += wire;
    st.payloadBytes += payload;
    st.sizeMin = std::min(st.sizeMin, wire);
    st.sizeMax = std::max(st.sizeMax, wire);
    st.sizeSum += wire;
    st.sizeSqSum += static_cast<double>(wire) * wire;
    if (st.firstT < 0.0)
    {
        st.firstT = now;
    }
    else
    {
        const double iat = now - st.lastT;
        st.iatSum += iat;
        st.iatSqSum += iat * iat;
        st.iatN += 1;
    }
    st.lastT = now;

    if (header.GetProtocol() == 6)
    {
        const bool syn = (flags & TcpHeader::SYN) != 0;
        const bool ack = (flags & TcpHeader::ACK) != 0;
        if (syn && ack)
        {
            st.synAckCount += 1;
        }
        else if (syn)
        {
            st.synCount += 1;
        }
        if (ack)
        {
            st.ackCount += 1;
        }
        if (flags & TcpHeader::FIN)
        {
            st.finCount += 1;
        }
        if (flags & TcpHeader::RST)
        {
            st.rstCount += 1;
        }
        if (flags & TcpHeader::PSH)
        {
            st.pshCount += 1;
        }
    }

    WindowStats& win = g_windows[WindowOf(now)];
    win.offeredPackets += 1;
    win.offeredBytes += wire;

    const bool hostile = IsAttackSource(header.GetSource()) && now >= g_spec.atkStart &&
                         now < g_spec.atkStart + g_spec.atkDuration;
    if (hostile)
    {
        st.attackPackets += 1;
        st.attackType = g_spec.atkType;
        if (st.app.empty())
        {
            st.app = "attack_" + g_spec.atkType;
        }
        win.attackOffered += 1;
    }
    else
    {
        if (st.app.empty())
        {
            st.app = "legit";
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
    if (now >= g_spec.duration)
    {
        return;
    }
    uint16_t sport, dport;
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
            if (win.latencySamples.size() < 4000)
            {
                win.latencySamples.push_back(delay);
            }
            if (!IsAttackSource(header.GetSource()))
            {
                win.legitLatencySum += delay;
                win.legitLatencyN += 1;
                win.legitDelivered += 1;
                if (win.legitLatencySamples.size() < 4000)
                {
                    win.legitLatencySamples.push_back(delay);
                }
            }
        }
    }
    g_totalDelivered += 1;
}

/** The IP stack discarded a packet. */
void
OnDrop(const Ipv4Header& header,
       Ptr<const Packet> packet,
       Ipv4L3Protocol::DropReason /*reason*/,
       Ptr<Ipv4> /*ipv4*/,
       uint32_t /*interface*/)
{
    const double now = Simulator::Now().GetSeconds();
    if (now >= g_spec.duration)
    {
        return;
    }
    uint16_t sport, dport;
    uint8_t flags;
    uint32_t payload;
    ExtractTransport(packet, header.GetProtocol(), sport, dport, flags, payload);
    g_flows[KeyFor(header, sport, dport, now)].dropped += 1;
    g_windows[WindowOf(now)].droppedPackets += 1;
    g_totalDropped += 1;
}

/** A traffic-control queue disc dropped a packet (the real congestion loss). */
void
OnQueueDiscDrop(Ptr<const QueueDiscItem> /*item*/, const char* /*reason*/)
{
    g_windows[WindowOf(Simulator::Now().GetSeconds())].droppedPackets += 1;
    g_totalDropped += 1;
}

void
OnDeviceQueueDrop(Ptr<const Packet> /*packet*/)
{
    g_windows[WindowOf(Simulator::Now().GetSeconds())].droppedPackets += 1;
    g_totalDropped += 1;
}

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

void
ConnectQueueDropTraces()
{
    const char* discPaths[] = {
        "/NodeList/*/$ns3::TrafficControlLayer/RootQueueDiscList/*/DropBeforeEnqueue",
        "/NodeList/*/$ns3::TrafficControlLayer/RootQueueDiscList/*/DropAfterDequeue",
    };
    for (const char* path : discPaths)
    {
        Config::ConnectWithoutContextFailSafe(path, MakeCallback(&OnQueueDiscDrop));
    }
    const char* devPaths[] = {
        "/NodeList/*/DeviceList/*/$ns3::PointToPointNetDevice/TxQueue/DropBeforeEnqueue",
        "/NodeList/*/DeviceList/*/$ns3::PointToPointNetDevice/TxQueue/DropAfterDequeue",
    };
    for (const char* path : devPaths)
    {
        Config::ConnectWithoutContextFailSafe(path, MakeCallback(&OnDeviceQueueDrop));
    }
}

// ---- attack-rate waveform -------------------------------------------------

/**
 * Reschedule each bot's offered DataRate over the attack interval to realise
 * the configured rate waveform (ramp / sine / step) and on/off pulsing. This
 * only changes an application attribute at window boundaries; it never touches
 * a packet.
 */
void
ApplyRate(Ptr<OnOffApplication> app, uint64_t bps)
{
    app->SetAttribute("DataRate", DataRateValue(DataRate(bps)));
}

double
WaveformMultiplier(const Spec& s, double t)
{
    const double elapsed = std::max(0.0, t - s.atkStart);
    const double frac = s.atkDuration > 0 ? std::min(1.0, elapsed / s.atkDuration) : 0.0;
    double value = 1.0;
    if (s.profile == "ramp")
    {
        value = s.rampLo + (s.rampHi - s.rampLo) * frac;
    }
    else if (s.profile == "sine")
    {
        const double period = std::max(1e-6, s.sinePeriod);
        const double depth = std::min(1.0, std::max(0.0, s.sineDepth));
        value = 1.0 - depth + depth * (1.0 - std::cos(2.0 * M_PI * elapsed / period));
    }
    else if (s.profile == "step")
    {
        const double interval = std::max(1e-6, s.stepInterval);
        const size_t idx = static_cast<size_t>(elapsed / interval);
        value = s.stepLevels[std::min(idx, s.stepLevels.size() - 1)];
    }
    return std::max(1e-3, value);
}

void
ScheduleWaveform(const std::vector<Ptr<OnOffApplication>>& apps, const Spec& s)
{
    // Record each bot's base rate once, then step the rate at window granularity.
    std::vector<uint64_t> base(apps.size());
    for (size_t i = 0; i < apps.size(); ++i)
    {
        DataRateValue drv;
        apps[i]->GetAttribute("DataRate", drv);
        base[i] = drv.Get().GetBitRate();
    }
    const double cycle = s.burstOn + s.burstOff;
    for (double t = s.atkStart; t < s.atkStart + s.atkDuration; t += s.windowS)
    {
        double mult = WaveformMultiplier(s, t);
        if (s.burst && cycle > 0)
        {
            const double phase = std::fmod(t - s.atkStart, cycle);
            if (phase >= s.burstOn)
            {
                mult = 1e-3; // off phase
            }
        }
        for (size_t i = 0; i < apps.size(); ++i)
        {
            const uint64_t bps = static_cast<uint64_t>(std::max(1.0, base[i] * mult));
            Simulator::Schedule(Seconds(t), &ApplyRate, apps[i], bps);
        }
    }
}

// ---- CSV / JSON export ----------------------------------------------------

std::string
ProtocolName(uint8_t p)
{
    switch (p)
    {
    case 6:
        return "TCP";
    case 17:
        return "UDP";
    case 1:
        return "ICMP";
    default:
        return "PROTO-" + std::to_string(static_cast<int>(p));
    }
}

std::string
IpToString(uint32_t addr)
{
    std::ostringstream oss;
    oss << Ipv4Address(addr);
    return oss.str();
}

void
WriteFlows(const std::string& path)
{
    std::ofstream out(path);
    if (!out.is_open())
    {
        NS_FATAL_ERROR("Cannot open " << path);
    }
    out << std::fixed;
    out << "window,t_start,t_end,src_node,dst_node,src_ip,dst_ip,src_port,dst_port,"
           "protocol,protocol_name,app,packets,bytes,payload_bytes,duration,packet_rate,"
           "byte_rate,mean_packet_size,packet_size_var,min_packet_size,max_packet_size,"
           "mean_iat,iat_std,syn_count,syn_ack_count,ack_count,fin_count,rst_count,"
           "psh_count,delivered,dropped,retransmits,attack_packets,attack_ratio,attack_type\n";
    for (const auto& e : g_flows)
    {
        const FlowKey& k = e.first;
        const FlowStats& s = e.second;
        if (s.packets == 0)
        {
            continue;
        }
        const double tStart = k.window * g_spec.windowS;
        const double dur = (s.firstT >= 0.0) ? (s.lastT - s.firstT) : 0.0;
        const double meanSize = s.sizeSum / s.packets;
        const double varSize =
            s.packets > 1 ? std::max(0.0, s.sizeSqSum / s.packets - meanSize * meanSize) : 0.0;
        const double meanIat = s.iatN > 0 ? s.iatSum / s.iatN : 0.0;
        const double iatVar =
            s.iatN > 1 ? std::max(0.0, s.iatSqSum / s.iatN - meanIat * meanIat) : 0.0;
        const double ratio = s.packets > 0 ? double(s.attackPackets) / s.packets : 0.0;
        out << k.window << ',' << std::setprecision(4) << tStart << ','
            << (tStart + g_spec.windowS) << ',' << k.srcNode << ',' << k.dstNode << ','
            << IpToString(k.srcIp) << ',' << IpToString(k.dstIp) << ',' << k.srcPort << ','
            << k.dstPort << ',' << int(k.protocol) << ',' << ProtocolName(k.protocol) << ','
            << (s.app.empty() ? "legit" : s.app) << ',' << s.packets << ',' << s.bytes << ','
            << s.payloadBytes << ',' << std::setprecision(6) << dur << ',' << std::setprecision(4)
            << (s.packets / g_spec.windowS) << ',' << (s.bytes / g_spec.windowS) << ','
            << std::setprecision(3) << meanSize << ',' << varSize << ','
            << (s.sizeMin == 0xFFFFFFFF ? 0 : s.sizeMin) << ',' << s.sizeMax << ','
            << std::setprecision(6) << meanIat << ',' << std::sqrt(iatVar) << ',' << s.synCount
            << ',' << s.synAckCount << ',' << s.ackCount << ',' << s.finCount << ',' << s.rstCount
            << ',' << s.pshCount << ',' << s.delivered << ',' << s.dropped << ",0,"
            << s.attackPackets << ',' << std::setprecision(5) << ratio << ',' << s.attackType
            << '\n';
    }
}

double
Percentile(std::vector<double> v, double q)
{
    if (v.empty())
    {
        return 0.0;
    }
    std::sort(v.begin(), v.end());
    const size_t idx =
        static_cast<size_t>(std::llround((q / 100.0) * static_cast<double>(v.size() - 1)));
    return v[std::min(idx, v.size() - 1)] * 1000.0;
}

void
WriteWindows(const std::string& path)
{
    std::ofstream out(path);
    if (!out.is_open())
    {
        NS_FATAL_ERROR("Cannot open " << path);
    }
    out << std::fixed;
    out << "window,t_start,t_end,offered_packets,offered_bytes,delivered_packets,"
           "delivered_bytes,dropped_packets,legit_offered,legit_delivered,attack_offered,"
           "mean_latency_ms,max_latency_ms,legit_mean_latency_ms,clean_p95_latency_ms,"
           "clean_p99_latency_ms,packet_loss_ratio,throughput_mbps\n";
    for (const auto& e : g_windows)
    {
        const uint32_t w = e.first;
        const WindowStats& s = e.second;
        const double tStart = w * g_spec.windowS;
        if (tStart >= g_spec.duration)
        {
            continue;
        }
        const double meanLat = s.latencyN ? (s.latencySum / s.latencyN) * 1000.0 : 0.0;
        const double legitLat = s.legitLatencyN ? (s.legitLatencySum / s.legitLatencyN) * 1000.0 : 0.0;
        const double loss = s.offeredPackets ? double(s.droppedPackets) / s.offeredPackets : 0.0;
        const double mbps = (s.deliveredBytes * 8.0) / (g_spec.windowS * 1e6);
        out << w << ',' << std::setprecision(4) << tStart << ',' << (tStart + g_spec.windowS)
            << ',' << s.offeredPackets << ',' << s.offeredBytes << ',' << s.deliveredPackets << ','
            << s.deliveredBytes << ',' << s.droppedPackets << ',' << s.legitOffered << ','
            << s.legitDelivered << ',' << s.attackOffered << ',' << std::setprecision(4) << meanLat
            << ',' << (s.latencyMax * 1000.0) << ',' << legitLat << ','
            << Percentile(s.legitLatencySamples, 95.0) << ',' << Percentile(s.legitLatencySamples, 99.0)
            << ',' << std::setprecision(6) << loss << ',' << std::setprecision(4) << mbps << '\n';
    }
}

void
WriteRunJson(const std::string& path)
{
    std::ofstream out(path);
    if (!out.is_open())
    {
        NS_FATAL_ERROR("Cannot open " << path);
    }
    out << "{\n";
    out << "  \"engine\": \"ns3-simulation\",\n";
    out << "  \"topology\": \"" << g_spec.topology << "\",\n";
    out << "  \"n_nodes\": " << g_spec.nodes.size() << ",\n";
    out << "  \"n_links\": " << g_spec.links.size() << ",\n";
    out << "  \"duration_s\": " << g_spec.duration << ",\n";
    out << "  \"window_s\": " << g_spec.windowS << ",\n";
    out << "  \"attack_type\": \"" << g_spec.atkType << "\",\n";
    out << "  \"attack_start_s\": " << g_spec.atkStart << ",\n";
    out << "  \"attack_duration_s\": " << g_spec.atkDuration << ",\n";
    out << "  \"packets_offered\": " << g_totalOffered << ",\n";
    out << "  \"packets_delivered\": " << g_totalDelivered << ",\n";
    out << "  \"packets_dropped\": " << g_totalDropped << ",\n";
    out << "  \"flow_records\": " << g_flows.size() << "\n";
    out << "}\n";
}

#endif // NETSHIELD_TRACE_H
