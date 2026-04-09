#include "wifi_sniffer.h"

void wifi_sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type)
{
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;

    PacketFeature feature;
    feature.timestamp = millis();
    feature.rssi = pkt->rx_ctrl.rssi;
    feature.length = pkt->rx_ctrl.sig_len;
    feature.frameType = pkt->payload[0];
    feature.channel = pkt->rx_ctrl.channel;

    xQueueSendFromISR(packetQueue, &feature, NULL);
}
