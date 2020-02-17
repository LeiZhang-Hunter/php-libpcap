//
// Created by root on 2020/1/7.
//

#ifndef LIBPCAP_TCP_STRUCT_H
#define LIBPCAP_TCP_STRUCT_H

# define _TCP_SPORT "src_port"
# define _TCP_DPORT "dest_port"
# define _TCP_TH_SEQ "seq"
# define _TCP_TH_ACK "ack"
# define _TCP_WINDOW "window"
# define _TCP_CHECK "check"
# define _TCP_URG_PTR "urg_ptr"

struct tcphdr {
    uint16_t th_sport;       /* source port */
    uint16_t th_dport;       /* destination port */
    uint32_t th_seq;         /* sequence number */
    uint32_t th_ack;         /* acknowledgement number */
#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    uint8_t th_offx2;       /* data offset, rsvd */
/* TCP flags */
#define TH_FIN     0x01
#define TH_SYN     0x02
#define TH_RST     0x04
#define TH_PUSH    0x08
#define TH_ACK     0x10
#define TH_URG     0x20
#define TH_ECNECHO 0x40 /* ECN Echo */
#define TH_CWR     0x80 /* ECN Cwnd Reduced */
    uint8_t th_flags;
    uint16_t th_win;         /* window */
    uint16_t th_sum;         /* checksum */
    uint16_t th_urp;         /* urgent pointer */
};

#endif //LIBPCAP_TCP_STRUCT_H
