//
// Created by zhanglei on 2020/1/2.
//pcap对应的库

#ifndef LIBPCAP_PCAP_LIB_H
#define LIBPCAP_PCAP_LIB_H


#include "ether_packet.h"
#include "http_parse.h"



typedef struct _pcap_module{
    uint8_t loop_state;//运行状态防止一个进程中重复运行
    long max_packet_num;
    zend_string* dev_name;
    pcap_if_t* (*find_all_devs)();
    void (*packer_handle)(u_char *param, const struct pcap_pkthdr *header,const u_char *data);
    PCAP_BOOL (*pcap_config_check)(zval* config);
    PCAP_BOOL (*pcap_if_t_to_zend_hash)(pcap_if_t* alldevs,HashTable* table);
    PCAP_BOOL (*free_all_devs)(pcap_if_t* alldevs);
    PCAP_BOOL (*loop)(void* pcaket_handle);
    char err_buf[PCAP_ERRBUF_SIZE];
}pcap_module;

PCAP_BOOL pcap_lib_init(pcap_module* pcap_lib);
//发现所有的设备
pcap_if_t* pcap_find_all_devs();
PCAP_BOOL pcap_free_all_devs(pcap_if_t*);

PCAP_BOOL pcap_if_t_to_zend_hash(pcap_if_t* alldevs,HashTable* table);

/**
 * 检查加载php层面的配置文件是否正确,如果说存在配置项挂载到配置属性上
 * @param config
 * @param object
 * @param object_ce
 * @return
 */
PCAP_BOOL pcap_config_check(zval* config);

PCAP_BOOL pcap_set_packet_handle(pcap_t* handle);

#endif //LIBPCAP_PCAP_LIB_H

