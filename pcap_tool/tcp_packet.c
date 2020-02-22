//
// Created by root on 20-2-21.
//

#include "common.h"

PCAP_BOOL init_tcp_packet(tcp_packet* packet)
{
    bzero(packet,sizeof(tcp_packet));
    packet->parse = tcp_parse;
    packet->finish = tcp_packet_finish;
    packet->dtor = tcp_packet_dtor;
    return PCAP_TRUE;
}

PCAP_BOOL tcp_parse(const u_char* packet)
{
    /*--------------------------------------*/
    //         source     |      dest       |
    /*--------------------------------------*/
    //             ack_seq                  |
    //--------------------------------------
    //  doff|res1|        |   window        |
    //         check      |    urg_ptr      |
    //              options                 |
    //---------------------------------------
    //端口往来
    tcp_header* _tcphdr = (tcp_header*)(packet);
    //数据偏移
    NG(tcp_packet_handle)->flags = _tcphdr->th_flags;//这个字段可以判断is_fin和is_rst等状态
    NG(tcp_packet_handle)->header_len = TH_OFF(_tcphdr)<<2;
    NG(tcp_packet_handle)->source_port = ntohs(_tcphdr->th_sport);
    NG(tcp_packet_handle)->dest_port = ntohs(_tcphdr->th_dport);
    NG(tcp_packet_handle)->win = ntohs(_tcphdr->th_win);
    NG(tcp_packet_handle)->sum = ntohs(_tcphdr->th_sum);
    NG(tcp_packet_handle)->urp = ntohs(_tcphdr->th_urp);
    NG(tcp_packet_handle)->seq = ntohl(_tcphdr->th_seq);
    NG(tcp_packet_handle)->ack = ntohl(_tcphdr->th_ack);
    NG(tcp_packet_handle)->payload_size = (NG(ip_packet_handle)->total_len -
            NG(ip_packet_handle)->header_len - NG(tcp_packet_handle)->header_len);
    NG(tcp_packet_handle)->payload = packet + NG(tcp_packet_handle)->header_len;
    return PCAP_TRUE;
}

void tcp_packet_dtor()
{

}

void tcp_packet_finish()
{

}