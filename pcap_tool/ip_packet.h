//
// Created by root on 20-2-21.
//

#ifndef LIBPCAP_IP_PACKET_H
#define LIBPCAP_IP_PACKET_H
#define IP_PACKET "ip"
# define _IP_TTL  "ttl"
#define _IP_PROTOCOL "protocol"
#define _IP_TOS "tos"
# define _IP_TOTAL_LEN "total_len"
# define _IP_ID "id"
# define _IP_SUM "sum"
# define _IP_SRC "src"
# define _IP_DST "dst"
# define _IP_HEADER_LEN "header_len"
# define _IP_VERSION "version"
#define IP_HL(ip)   ((ip)->ip_hl & 0x0f)

typedef struct ip ip_header;

typedef struct _ip_packet{
    uint8_t ttl;
    uint8_t protocol;
    uint8_t tos;			/* type of service */
    unsigned short total_len;
    unsigned short id;
    unsigned short sum;
    unsigned int header_len;
    unsigned int version;
    void (*finish)();
    void (*dtor)();
    char src_addr[INET_ADDRSTRLEN];
    char dest_addr[INET_ADDRSTRLEN];
    PCAP_BOOL (*parse)(const u_char* packet);
}ip_packet;

PCAP_BOOL init_ip_packet(ip_packet*);
PCAP_BOOL parse(const u_char* packet);
void _ip_packet_finish();
void _ip_packet_dtor();
#endif //LIBPCAP_IP_PACKET_H
