//
// Created by zhanglei on 2020/1/2.
//

#ifndef LIBPCAP_COMMON_H
#define LIBPCAP_COMMON_H
#include <netdb.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <zlib.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#ifndef PCAP_BOOL
#define PCAP_BOOL int
#define PCAP_FALSE -1
#define PCAP_TRUE 0
#endif

#define ERROR_BUF "error"
#define PCAP_CONFIG "config"
#define PCAP_DEV "dev"
#define PCAP_MAXPACKET_NUM "max_packet_num"
#define PCAP_RULE "rule"
#define PCAP_RECV "onRecv"


#include "php.h"
#include "pcap_lib.h"
#include "zend_libpcap.h"
#include "http_parse.h"
#include "ether_packet.h"
#include "ip_packet.h"
#include "tcp_packet.h"
#include "gzip_tool.h"
#include "node_sentry.h"



//加载类
#define CLASS_LOAD(class_name) class_##class_name##_load()

#endif //LIBPCAP_COMMON_H

