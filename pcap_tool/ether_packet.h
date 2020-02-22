//
// Created by root on 2020/2/21.
//

#ifndef LIBPCAP_ETHER_PACKET_H
#define LIBPCAP_ETHER_PACKET_H

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define ETHER "ether"
#define MAC_SOURCE "source_mac"
#define ETH_PROTO "ether_proto"
#define MAC_DEST "dest_mac"
#define MAC_TYPE "mac_type"
typedef struct ethhdr ether_header;
#define ETHER_HEADER_LEN 14
struct vlan_8021q_header {
    u_int16_t	priority_cfi_vid;
    u_int16_t	ether_type;
};
typedef struct _ether_packet{
    int ether_type;
    int ether_len;
    char source_mac[MAX_LENGTH_OF_LONG];
    char dest_mac[MAX_LENGTH_OF_LONG];
    PCAP_BOOL (*parse)(const u_char* packet);
    void (*finish)();
    void (*dtor)();
}ether_packet;

PCAP_BOOL init_ether_packet(ether_packet* ether);
PCAP_BOOL _ether_packet_exec(const u_char* packet);
void _ether_packet_dtor();
void _ether_packet_finish();
#endif //LIBPCAP_ETHER_PACKET_H
