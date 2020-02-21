//
// Created by root on 2020/2/21.
//

#ifndef LIBPCAP_ETHER_PACKET_H
#define LIBPCAP_ETHER_PACKET_H

typedef struct _ether_packet{
    int ether_type;
    char source_mac[MAX_LENGTH_OF_LONG];
    char dest_mac[MAX_LENGTH_OF_LONG];
    PCAP_BOOL (*do_packet)();
}ether_packet;

PCAP_BOOL _ether_packet_exec(u_char* packet);

#endif //LIBPCAP_ETHER_PACKET_H
