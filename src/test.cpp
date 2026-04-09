#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "wifi_sniffer.h"

#define LED_PIN 2

QueueHandle_t packetQueue;

void setup()
{
    Serial.begin(115200);
    delay(1000);


    packetQueue = xQueueCreate(100, sizeof(PacketFeature));
    if (packetQueue == NULL)
    {
        Serial.println("failed to create packet queue");
        return;
    }
    Serial.println("packet queue created");

    
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
    Serial.println("Waiting for packets...\n");
    pinMode(LED_PIN, OUTPUT);
}

void loop()
{
    digitalWrite(LED_PIN, HIGH); 
    PacketFeature feature;

    if (xQueueReceive(packetQueue, &feature, 0) == pdTRUE)
    {
        Serial.printf("[PKT] RSSI: %3d dBm | Type: 0x%02X | Len: %4d | Ch: %d | Time: %lu ms\n",
                      feature.rssi,
                      feature.frameType,
                      feature.length,
                      feature.channel,
                      feature.timestamp);
    }

    delay(10);
}
