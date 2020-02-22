//
// Created by root on 2020/2/21.
//
#include "common.h"

PCAP_BOOL init_ether_packet(ether_packet* ether)
{
    bzero(ether,sizeof(ether_packet));
    ether->ether_type = 0;
    ether->ether_len = ETHER_HEADER_LEN;
    ether->parse = _ether_packet_exec;
    ether->finish = _ether_packet_finish;
    return PCAP_TRUE;
}

PCAP_BOOL _ether_packet_exec(const u_char* packet)
{
    //以太网头
    ether_header* eth_ptr;

    eth_ptr = (ether_header*)packet;

    NG(eth_packet_handle)->ether_type = htons(eth_ptr->h_proto);

    //格式化mac地址
    bzero(NG(eth_packet_handle)->source_mac,sizeof(NG(eth_packet_handle)->source_mac));
    bzero(NG(eth_packet_handle)->dest_mac,sizeof(NG(eth_packet_handle)->dest_mac));

    php_sprintf(NG(eth_packet_handle)->source_mac,MAC_FMT,eth_ptr->h_source[0],eth_ptr->h_source[1],eth_ptr->h_source[2],
                eth_ptr->h_source[3],eth_ptr->h_source[4],eth_ptr->h_source[5]);

    //格式化mac
    php_sprintf(NG(eth_packet_handle)->dest_mac,MAC_FMT,eth_ptr->h_dest[0],eth_ptr->h_dest[1],eth_ptr->h_dest[2],
                eth_ptr->h_dest[3],eth_ptr->h_dest[4],eth_ptr->h_dest[5]);

    return PCAP_TRUE;
}

void _ether_packet_dtor()
{

}

void _ether_packet_finish()
{

}