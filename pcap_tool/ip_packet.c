//
// Created by root on 20-2-21.
//

#include "common.h"

PCAP_BOOL init_ip_packet(ip_packet* ip_handle)
{
    bzero(ip_handle,sizeof(ip_packet));
    ip_handle->parse = parse;
    ip_handle->finish = _ip_packet_finish;
    ip_handle->dtor = _ip_packet_dtor;
    return PCAP_TRUE;
}

PCAP_BOOL parse(const u_char* packet)
{
    //ip的包
    ip_header * ipptr;
    ipptr = (ip_header*) (packet);
    NG(ip_packet_handle)->header_len = IP_HL(ipptr)<<2;
    NG(ip_packet_handle)->version = ntohl(ipptr->ip_v);
    NG(ip_packet_handle)->ttl = ipptr->ip_ttl;
    NG(ip_packet_handle)->tos = ipptr->ip_tos;
    NG(ip_packet_handle)->protocol = ipptr->ip_p;
    NG(ip_packet_handle)->total_len = ntohs(ipptr->ip_len);
    NG(ip_packet_handle)->id = ntohs(ipptr->ip_id);
    NG(ip_packet_handle)->sum = ntohs(ipptr->ip_sum);
    inet_ntop(AF_INET,&ipptr->ip_src,NG(ip_packet_handle)->src_addr,sizeof(NG(ip_packet_handle)->src_addr));
    inet_ntop(AF_INET,&ipptr->ip_dst,NG(ip_packet_handle)->dest_addr,sizeof(NG(ip_packet_handle)->dest_addr));
    return PCAP_TRUE;
}

void _ip_packet_dtor()
{

}

void _ip_packet_finish()
{

}