//
// Created by zhanglei on 2020/1/2.
//
#include <pthread.h>
#include "common.h"
extern pcap_module pcap_factory;

//初始化处理对象
PCAP_BOOL pcap_lib_init()
{
    bzero(&pcap_factory,sizeof(pcap_module));
    pcap_factory.find_all_devs = pcap_find_all_devs;
    pcap_factory.free_all_devs = pcap_free_all_devs;
}

//发现所有的设备
pcap_if_t* pcap_find_all_devs()
{
    pcap_if_t *alldevs;
    if(pcap_findalldevs(&alldevs,pcap_factory.err_buf) == PCAP_FALSE)
    {
        return NULL;
    }

    return alldevs;
}

//释放查找句柄
PCAP_BOOL pcap_free_all_devs(pcap_if_t* alldevs)
{
    if(UNEXPECTED(alldevs))
    {
        return PCAP_FALSE;
    }

    pcap_freealldevs(alldevs);
    return PCAP_TRUE;
}

//循环处理函数
static void zend_pcaket_handle(u_char *param, const struct pcap_pkthdr *header,const u_char *pcaket)
{
    int ether_type;
    struct ether* eth_ptr;
    eth_ptr = (struct ether*)pcaket;
    unsigned char *payload;
}
