//
// Created by root on 2020/2/21.
//
#include "common.h"

PCAP_BOOL _ether_packet_exec(u_char* packet)
{
    //以太网头
    ether_header* eth_ptr;

    eth_ptr = (ether_header*)packet;

    //格式化mac地址
    bzero(pcap_factory.eth_packet->source_mac,sizeof(pcap_factory.eth_packet->source_mac));
    bzero(pcap_factory.eth_packet->dest_mac,sizeof(pcap_factory.eth_packet->dest_mac));

    php_sprintf(pcap_factory.eth_packet->source_mac,MAC_FMT,eth_ptr->h_source[0],eth_ptr->h_source[1],eth_ptr->h_source[2],
                eth_ptr->h_source[3],eth_ptr->h_source[4],eth_ptr->h_source[5]);

    //格式化mac
    php_sprintf(pcap_factory.eth_packet->dest_mac,MAC_FMT,eth_ptr->h_dest[0],eth_ptr->h_dest[1],eth_ptr->h_dest[2],
                eth_ptr->h_dest[3],eth_ptr->h_dest[4],eth_ptr->h_dest[5]);
}