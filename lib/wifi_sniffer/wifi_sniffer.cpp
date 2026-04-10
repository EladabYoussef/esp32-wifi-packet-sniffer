#include "wifi_sniffer.h"

// IP header structure for parsing
struct ip_header
{
    unsigned char version_length;
    unsigned char dscp_ecn;
    unsigned short total_length;
    unsigned short identification;
    unsigned short flags_fragment;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short header_checksum;
    unsigned int ip_src;
    unsigned int ip_dst;
};

// TCP header structure
struct tcp_header
{
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int seq_num;
    unsigned int ack_num;
    unsigned char data_offset;
    unsigned char flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent;
};

// UDP header structure
struct udp_header
{
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short length;
    unsigned short checksum;
};

// Global flow database
std::map<uint32_t, NetworkFlow> flowDatabase;

// Convert IP address integer to string
String ip_to_string(uint32_t ip)
{
    return String((ip & 0xFF)) + "." +
           String((ip >> 8) & 0xFF) + "." +
           String((ip >> 16) & 0xFF) + "." +
           String((ip >> 24) & 0xFF);
}

// Calculate flow ID based on 5-tuple
uint32_t calculate_flow_id(String ip_src, String ip_dst, uint16_t port_src, uint16_t port_dst, uint8_t proto)
{
    uint32_t hash = 5381;
    String flow_key = ip_src + ":" + ip_dst + ":" + String(port_src) + ":" + String(port_dst) + ":" + String(proto);

    for (uint32_t i = 0; i < flow_key.length(); i++)
    {
        hash = ((hash << 5) + hash) + flow_key[i];
    }

    return hash;
}

// Parse and extract features from IP packet
void parse_ip_packet(const uint8_t *payload, uint16_t length, PacketFeature &feature)
{
    if (length < sizeof(ip_header))
        return;

    ip_header *iph = (ip_header *)payload;

    // Extract IP addresses
    feature.ip_src = ip_to_string(iph->ip_src);
    feature.ip_dst = ip_to_string(iph->ip_dst);
    feature.ip_proto = iph->protocol;

    // Calculate header length
    uint8_t iph_len = (iph->version_length & 0x0F) * 4;

    // Parse transport layer
    if (iph->protocol == 6)
    { // TCP
        if (length < iph_len + sizeof(tcp_header))
            return;

        tcp_header *tcph = (tcp_header *)(payload + iph_len);
        feature.src_port = ntohs(tcph->src_port);
        feature.dst_port = ntohs(tcph->dst_port);
        feature.tcp_window = ntohs(tcph->window);
    }
    else if (iph->protocol == 17)
    { // UDP
        if (length < iph_len + sizeof(udp_header))
            return;

        udp_header *udph = (udp_header *)(payload + iph_len);
        feature.src_port = ntohs(udph->src_port);
        feature.dst_port = ntohs(udph->dst_port);
        feature.tcp_window = 0; // UDP has no window
    }
}

// Process packet and update flow features
void process_packet_features(PacketFeature &pkt)
{
    // Calculate flow ID
    uint32_t flow_id = calculate_flow_id(pkt.ip_src, pkt.ip_dst, pkt.src_port, pkt.dst_port, pkt.ip_proto);

    // Check if flow exists, if not create it
    if (flowDatabase.find(flow_id) == flowDatabase.end())
    {
        NetworkFlow new_flow;
        new_flow.flow_id = flow_id;
        new_flow.flow_ip_src = pkt.ip_src;
        new_flow.flow_ip_dst = pkt.ip_dst;
        new_flow.flow_srcport = pkt.src_port;
        new_flow.flow_dstport = pkt.dst_port;
        new_flow.flow_proto = pkt.ip_proto;
        new_flow.num_packets = 0;
        new_flow.total_length = 0;
        new_flow.forward_packets = 0;
        new_flow.receiving_packets = 0;
        new_flow.fragments = 0;
        new_flow.total_payload = 0;
        new_flow.min_time = 0xFFFFFFFF;
        new_flow.max_time = 0;
        new_flow.tcp_window_size_avg = 0;
        new_flow.first_packet_time = pkt.timestamp;
        new_flow.last_packet_time = pkt.timestamp;
        new_flow.target_numeric = 0;

        flowDatabase[flow_id] = new_flow;
    }

    // Update flow statistics
    NetworkFlow &flow = flowDatabase[flow_id];

    flow.num_packets++;
    flow.total_length += pkt.length;
    flow.total_payload += (pkt.length > 54) ? (pkt.length - 54) : 0; // Subtract typical header size

    // Update direction counters
    if (pkt.is_forward)
    {
        flow.forward_packets++;
    }
    else
    {
        flow.receiving_packets++;
    }

    // Update timing info
    uint32_t time_delta = (flow.last_packet_time > 0) ? (pkt.timestamp - flow.last_packet_time) : 0;
    if (time_delta > 0 && time_delta < flow.min_time)
    {
        flow.min_time = time_delta;
    }
    if (time_delta > flow.max_time)
    {
        flow.max_time = time_delta;
    }

    flow.last_packet_time = pkt.timestamp;
    flow.flow_duration = pkt.timestamp - flow.first_packet_time;

    // Update average packet size
    flow.avg_packet_size = flow.total_length / flow.num_packets;

    // Update TCP window size average
    if (flow.flow_proto == 6 && pkt.tcp_window > 0)
    {
        flow.tcp_window_size_avg = (flow.tcp_window_size_avg + pkt.tcp_window) / 2;
    }
}

// Print flow features in format for logging
void print_flow_features(NetworkFlow &flow)
{
    Serial.printf("FLOW_ID:%lu|IP_SRC:%s|IP_DST:%s|SRC_PORT:%u|DST_PORT:%u|PROTO:%u|NUM_PKT:%lu|AVG_SIZE:%u|TCP_WIN:%u|PAYLOAD:%lu|DURATION:%lu\n",
                  flow.flow_id,
                  flow.flow_ip_src.c_str(),
                  flow.flow_ip_dst.c_str(),
                  flow.flow_srcport,
                  flow.flow_dstport,
                  flow.flow_proto,
                  flow.num_packets,
                  flow.avg_packet_size,
                  flow.tcp_window_size_avg,
                  flow.total_payload,
                  flow.flow_duration);
}

// WiFi sniffer callback - captures packets and extracts features
void wifi_sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
    static uint32_t total_packets = 0;
    static uint32_t ip_packets = 0;
    static uint32_t last_debug = 0;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;

    total_packets++;

    // Print debug info every 500 packets
    if ((millis() - last_debug) > 10000)
    {
        last_debug = millis();
        Serial.printf("[DEBUG] Total packets captured: %lu, IP packets processed: %lu\n", total_packets, ip_packets);
    }

    // Skip very small packets
    if (pkt->rx_ctrl.sig_len < 40)
        return;

    PacketFeature feature;
    feature.timestamp = millis();
    feature.rssi = pkt->rx_ctrl.rssi;
    feature.length = pkt->rx_ctrl.sig_len;
    feature.frameType = pkt->payload[0];
    feature.channel = pkt->rx_ctrl.channel;

    feature.src_port = 0;
    feature.dst_port = 0;
    feature.ip_proto = 0;
    feature.tcp_window = 0;
    feature.is_forward = true;

    // Try to find and parse IP header (look for 0x45 or 0x46 at various offsets)
    bool ip_found = false;
    for (uint8_t offset = 20; offset < pkt->rx_ctrl.sig_len - sizeof(ip_header); offset += 4)
    {
        uint8_t version = pkt->payload[offset] >> 4;
        if (version == 4)
        { // IPv4
            parse_ip_packet(pkt->payload + offset, pkt->rx_ctrl.sig_len - offset, feature);
            if (feature.ip_proto > 0)
            {
                ip_found = true;
                ip_packets++;
                process_packet_features(feature);
                break;
            }
        }
    }
}
