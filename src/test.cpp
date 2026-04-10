#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "wifi_sniffer.h"

#define LED_PIN 2
#define DISPLAY_INTERVAL 5000 // Display flow stats every 5 seconds

QueueHandle_t packetQueue;

void setup()
{
    Serial.begin(115200);
    delay(1000);

    Serial.println("\n=== WiFi Packet Sniffer - Paper Feature Extraction ===");
    Serial.println("Features from Paper Section III.B");

    packetQueue = xQueueCreate(100, sizeof(PacketFeature));
    if (packetQueue == NULL)
    {
        Serial.println("ERROR: Failed to create packet queue");
        return;
    }
    Serial.println("[OK] Packet queue created");

    // Initialize WiFi in promiscuous mode
    Serial.println("Initializing WiFi sniffer...");
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_NULL);
    esp_wifi_start();

    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_callback);

    // Set to channel 6 (can be changed later)
    esp_wifi_set_channel(6, WIFI_SECOND_CHAN_NONE);

    Serial.println("[OK] WiFi in promiscuous mode on channel 6");
    Serial.println("Waiting for packets...\n");
    Serial.println("=== FEATURE EXTRACTION IN PROGRESS ===");

    pinMode(LED_PIN, OUTPUT);
}

void loop()
{
    static uint32_t last_display = millis();
    uint32_t current_time = millis();

    digitalWrite(LED_PIN, HIGH);

    // Display accumulated flow features every DISPLAY_INTERVAL
    if (current_time - last_display >= DISPLAY_INTERVAL)
    {
        last_display = current_time;

        if (flowDatabase.size() > 0)
        {
            Serial.printf("\n=== Active Flows: %d ===\n", (int)flowDatabase.size());

            for (auto &pair : flowDatabase)
            {
                NetworkFlow &flow = pair.second;

                // Check if flow has enough data to be meaningful
                if (flow.num_packets > 0)
                {
                    // Print in format that can be captured to CSV
                    Serial.printf("FLOW|");
                    Serial.printf("flow_id:%lu|", flow.flow_id);
                    Serial.printf("flow_ip_src:%s|", flow.flow_ip_src.c_str());
                    Serial.printf("flow_ip_dst:%s|", flow.flow_ip_dst.c_str());
                    Serial.printf("flow_srcport:%u|", flow.flow_srcport);
                    Serial.printf("flow_dstport:%u|", flow.flow_dstport);
                    Serial.printf("flow_proto:%u|", flow.flow_proto);
                    Serial.printf("num_packets:%lu|", flow.num_packets);
                    Serial.printf("total_length:%lu|", flow.total_length);
                    Serial.printf("avg_packet_size:%u|", flow.avg_packet_size);
                    Serial.printf("min_time:%lu|", (flow.min_time == 0xFFFFFFFF) ? 0 : flow.min_time);
                    Serial.printf("max_time:%lu|", flow.max_time);
                    Serial.printf("tcp_window_size_avg:%u|", flow.tcp_window_size_avg);
                    Serial.printf("total_payload:%lu|", flow.total_payload);
                    Serial.printf("forward_packets:%lu|", flow.forward_packets);
                    Serial.printf("receiving_packets:%lu|", flow.receiving_packets);
                    Serial.printf("fragments:%u|", flow.fragments);
                    Serial.printf("flow_duration:%lu|", flow.flow_duration);
                    Serial.printf("target:%u\n", flow.target_numeric);
                }
            }

            Serial.println("===");
        }
        else
        {
            Serial.println("[INFO] Waiting for IP packets... Make sure devices are communicating on the network");
        }
    }

    delay(10);
}
