//
// Created by zhanglei on 2020/1/2.
//

#ifndef LIBPCAP_COMMON_H
#define LIBPCAP_COMMON_H
#include <netdb.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>


#include "php.h"
#include "pcap_lib.h"
#include "zend_libpcap.h"
#include "zend_pcap.h"
#include "ether.h"

#define ERROR_BUF "error"
#define PCAP_CONFIG "config"
#define PCAP_DEV "dev"
#define PCAP_MAXPACKET_NUM "max_packet_num"
#define PCAP_RECV "onRecv"





//加载类
#define CLASS_LOAD(class_name) class_##class_name##_load()

#endif //LIBPCAP_COMMON_H

