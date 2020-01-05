//
// Created by zhanglei on 2020/1/3.
//这个库文件使用来将pcap的数据结构转化为zend数据结构的

#ifndef LIBPCAP_ZEND_PCAP_H
#define LIBPCAP_ZEND_PCAP_H

//zend的接口从用来处理zend的数据结构和
typedef struct _zend_pcap_tool
{
    zval* hook;
    PCAP_BOOL (*pcap_if_t_to_zend_hash)(pcap_if_t* alldevs,HashTable* table);
    PCAP_BOOL (*pcap_config_check)(zval* config);
    PCAP_BOOL (*pcap_set_packet_handle)(pcap_t* handle);
}zend_pcap_tool;

//这个结构体是zend和pcap库对接的结构体
zend_pcap_tool zend_pcap_tree;

PCAP_BOOL init_factory();

/**
 * 将pcap_if_t转换成hashtable
 * @param alldevs
 * @param table
 * @return
 */
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
#endif //LIBPCAP_ZEND_PCAP_H
