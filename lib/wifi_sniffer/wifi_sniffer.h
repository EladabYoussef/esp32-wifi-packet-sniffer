#pragma once

#include <Arduino.h>
#include "esp_wifi.h"


struct PacketFeature
{
    uint32_t timestamp; 
    int8_t rssi;        
    uint8_t frameType;  
    uint16_t length;    
    uint8_t channel;    
};

extern QueueHandle_t packetQueue;

void wifi_sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type);
