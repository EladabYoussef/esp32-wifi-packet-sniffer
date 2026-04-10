#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "wifi_sniffer.h"

#define LED_PIN 2
#define DISPLAY_INTERVAL 10000 // Output collected flows every 10 seconds

QueueHandle_t packetQueue;

void setup()
{
    Serial.begin(115200);
    delay(1000);

    Serial.println("\n=== WiFi Packet Sniffer - Attack Data Collection Mode ===");
    Serial.println("Outputting: flow_id|flow_ip_src|flow_ip_dst|flow_srcport|flow_dstport|flow_proto|num_packets|total_length|avg_packet_size|min_time|max_time|tcp_window_size_avg|total_payload|forward_packets|receiving_packets|fragments|flow_duration|target");
    Serial.println("*NOTE: All flows labeled as target=1 (ATTACK)");

    packetQueue = xQueueCreate(100, sizeof(PacketFeature));
    if (packetQueue == NULL)
    {
        Serial.println("ERROR: Failed to create packet queue");
        return;
    }

    // Initialize WiFi in promiscuous mode
    Serial.println("Initializing WiFi sniffer...");
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_callback);
    esp_wifi_set_channel(6, WIFI_SECOND_CHAN_NONE);

    Serial.println("[OK] WiFi in promiscuous mode on channel 6");
    Serial.println("[START_ATTACK_DATA_COLLECTION]");

    pinMode(LED_PIN, OUTPUT);
}

void loop()
{
    static uint32_t last_output = millis();
    static uint32_t total_flows_output = 0;
    uint32_t current_time = millis();

    digitalWrite(LED_PIN, HIGH);

    // Output collected flows every DISPLAY_INTERVAL
    if (current_time - last_output >= DISPLAY_INTERVAL)
    {
        last_output = current_time;

        if (flowDatabase.size() > 0)
        {
            for (auto &pair : flowDatabase)
            {
                NetworkFlow &flow = pair.second;

                // Output only flows with at least 1 packet
                if (flow.num_packets > 0)
                {
                    // Output in pipe-delimited format for CSV parsing
                    // TARGET IS HARDCODED TO 1 FOR ATTACK FLOWS
                    Serial.printf("DATA|%lu|%s|%s|%u|%u|%u|%lu|%lu|%u|%lu|%lu|%u|%lu|%lu|%lu|%u|%lu|1\n",
                                  flow.flow_id,
                                  flow.flow_ip_src.c_str(),
                                  flow.flow_ip_dst.c_str(),
                                  flow.flow_srcport,
                                  flow.flow_dstport,
                                  flow.flow_proto,
                                  flow.num_packets,
                                  flow.total_length,
                                  flow.avg_packet_size,
                                  (flow.min_time == 0xFFFFFFFF) ? 0 : flow.min_time,
                                  flow.max_time,
                                  flow.tcp_window_size_avg,
                                  flow.total_payload,
                                  flow.forward_packets,
                                  flow.receiving_packets,
                                  flow.fragments,
                                  flow.flow_duration,
                                  1); // target = 1 (ATTACK)

                    total_flows_output++;
                }
            }
        }

        // Print status line every 30 seconds
        if ((total_flows_output % 3) == 0 && total_flows_output > 0)
        {
            Serial.printf("[STATUS] Active flows: %d, Total flows output: %lu (ATTACK DATA)\n", (int)flowDatabase.size(), total_flows_output);
        }
    }

    delay(10);
}
