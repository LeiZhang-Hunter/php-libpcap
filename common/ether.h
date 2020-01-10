//
// Created by root on 2020/1/5.
//

#ifndef LIBPCAP_ETHER_H
#define LIBPCAP_ETHER_H
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>


#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_SOURCE "source_mac"
#define ETH_PROTO "ether_proto"
#define ETHER_HEADER "ether_header"
#define MAC_DEST "dest_mac"
#define MAC_TYPE "mac_type"

#define ETHER_HEADER_LEN 14
struct vlan_8021q_header {
    u_int16_t	priority_cfi_vid;
    u_int16_t	ether_type;
};
#endif //LIBPCAP_ETHER_H
