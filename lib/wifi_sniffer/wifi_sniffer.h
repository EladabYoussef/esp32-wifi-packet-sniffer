#pragma once

#include <Arduino.h>
#include "esp_wifi.h"
#include <map>
#include <string>

// Paper feature definitions (Section III.B)
struct NetworkFlow
{
    // Flow identifiers (5-tuple)
    uint32_t flow_id;      // Unique flow identifier
    String flow_ip_src;    // Source IP address
    String flow_ip_dst;    // Destination IP address
    uint16_t flow_srcport; // Source port
    uint16_t flow_dstport; // Destination port

    // Flow statistics
    uint8_t flow_proto;           // Protocol (TCP=6, UDP=17)
    uint32_t num_packets;         // Total packets in flow
    uint32_t total_length;        // Total payload length
    uint16_t avg_packet_size;     // Average packet size
    uint32_t min_time;            // Min time between packets
    uint32_t max_time;            // Max time between packets
    uint16_t tcp_window_size_avg; // Average TCP window size
    uint32_t total_payload;       // Total payload data
    uint32_t forward_packets;     // Packets in forward direction
    uint32_t receiving_packets;   // Packets in reverse direction
    uint8_t fragments;            // Number of fragments
    uint32_t flow_duration;       // Flow duration (ms)

    // Timing information
    uint32_t first_packet_time; // First packet timestamp
    uint32_t last_packet_time;  // Last packet timestamp

    // Target label (to be assigned)
    uint8_t target_numeric; // Numeric target label
    String target_label;    // String target label
};

// Individual packet data structure
struct PacketFeature
{
    uint32_t timestamp;
    int8_t rssi;
    uint8_t frameType;
    uint16_t length;
    uint8_t channel;

    // IP layer information
    String ip_src;
    String ip_dst;
    uint8_t ip_proto;

    // TCP/UDP layer information
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t tcp_window;

    // Direction indicator
    bool is_forward; // true=forward, false=reverse
};

extern QueueHandle_t packetQueue;
extern std::map<uint32_t, NetworkFlow> flowDatabase;

void wifi_sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type);
uint32_t calculate_flow_id(String ip_src, String ip_dst, uint16_t port_src, uint16_t port_dst, uint8_t proto);
void process_packet_features(PacketFeature &pkt);
void print_flow_features(NetworkFlow &flow);