//
// Created by zhanglei on 2020/1/2.
//pcap对应的库

#ifndef LIBPCAP_PCAP_LIB_H
#define LIBPCAP_PCAP_LIB_H


#include "ether_packet.h"

#define PCAP_BOOL int
#define PCAP_FALSE -1
#define PCAP_TRUE 0
typedef struct _pcap_dev_config{
    char* name;//设备名字
    int flag;//设备模式
    int timeout;
}pcap_dev_config;

typedef struct _pcap_module{
    uint8_t loop_state;//运行状态防止一个进程中重复运行
    int max_packet_num;
    zend_string* dev_name;
    pcap_if_t* (*find_all_devs)();
    ether_packet* eth_packet;
    void (*packer_handle)(u_char *param, const struct pcap_pkthdr *header,const u_char *data);
    PCAP_BOOL (*free_all_devs)(pcap_if_t* alldevs);
    PCAP_BOOL (*loop)(void* pcaket_handle);
    char err_buf[PCAP_ERRBUF_SIZE];
}pcap_module;

typedef struct ethhdr ether_header;

typedef struct ip ip_header;

typedef struct tcphdr tcp_header;

pcap_module pcap_factory;

PCAP_BOOL pcap_lib_init();

//发现所有的设备
pcap_if_t* pcap_find_all_devs();

PCAP_BOOL pcap_free_all_devs(pcap_if_t*);

PCAP_BOOL _packet_ether();

PCAP_BOOL loop(void* pcaket_handle);

#endif //LIBPCAP_PCAP_LIB_H

