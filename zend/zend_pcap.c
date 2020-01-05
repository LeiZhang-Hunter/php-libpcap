//
// Created by zhanglei on 2020/1/3.
//
#include "common.h"

PCAP_BOOL init_factory()
{
    zend_pcap_tree.pcap_if_t_to_zend_hash = pcap_if_t_to_zend_hash;
    zend_pcap_tree.pcap_config_check = pcap_config_check;
    zend_pcap_tree.pcap_set_packet_handle = pcap_set_packet_handle;
}

PCAP_BOOL pcap_if_t_to_zend_hash(pcap_if_t* handle,HashTable* table)
{
    if(!handle)
        return PCAP_FALSE;

    pcap_if_t* dev;//单个设备

    int count = 0;

    zval dev_arr;//设备单元数组

    zval dev_name;//设备名

    zval dev_description;//设备描述

    zval dev_sock_family;//sa_family

    zend_string* dev_zend_str_name;

    zend_string* dev_zend_str_description;

    struct pcap_addr *pcap_address;

    char ipv4_str[INET_ADDRSTRLEN];

    char ipv6_str[INET6_ADDRSTRLEN];

    char broad_str[INET_ADDRSTRLEN];

    int address_count = 0;

    zval address_arr;

    for(dev = handle;dev != NULL;dev = dev->next)
    {
        array_init(&dev_arr);
        array_init(&address_arr);
        if(dev->description) {
            ZVAL_STRING(&dev_description,dev->description);
        }else{
            ZVAL_EMPTY_STRING(&dev_description);
        }

        //如果说存在socket地址
        if(dev->addresses) {
            //ipv4
            pcap_address = dev->addresses;
            while(pcap_address)
            {
                switch (pcap_address->addr->sa_family)
                {
                    case AF_INET:
                        //ipv4
                        bzero(ipv4_str, sizeof(ipv4_str));
                        inet_ntop(AF_INET,&(((struct sockaddr_in*)pcap_address->addr)->sin_addr),ipv4_str,sizeof(ipv4_str));
                        ZVAL_STRING(&dev_sock_family,ipv4_str);
                        zend_hash_str_add(Z_ARRVAL_P(&address_arr),"ipv4_address",strlen("ipv4_address"),&dev_sock_family);
                        //打印广播地址
                        if(pcap_address->broadaddr) {
                            inet_ntop(AF_INET, &(((struct sockaddr_in *) pcap_address->broadaddr)->sin_addr), broad_str,
                                      sizeof(broad_str));
                            ZVAL_STRING(&dev_sock_family,broad_str);
                            zend_hash_str_add(Z_ARRVAL_P(&address_arr), "broad_address", strlen("broad_address"),
                                              &dev_sock_family);
                        }
                        break;
                    case AF_INET6:
                        //ipv6
                        bzero(ipv6_str, sizeof(ipv6_str));
                        inet_ntop(AF_INET6,&(((struct sockaddr_in6*)pcap_address->addr)->sin6_addr),ipv6_str,sizeof(ipv6_str));
                        ZVAL_STRING(&dev_sock_family,ipv6_str);
                        zend_hash_str_add(Z_ARRVAL_P(&address_arr),"ipv6_address",strlen("ipv6_address"),&dev_sock_family);
                        break;
                }
                pcap_address = pcap_address->next;
                address_count++;
            }
        }
        ZVAL_STRING(&dev_name,dev->name);
        zend_hash_str_add(Z_ARRVAL_P(&dev_arr),"name",strlen("name"),&dev_name);
        zend_hash_str_add(Z_ARRVAL_P(&dev_arr),"description",strlen("description"),&dev_description);
        zend_hash_str_add(Z_ARRVAL_P(&dev_arr),"address",strlen("address"),&address_arr);
        zend_hash_index_add(table, count, &dev_arr);
        count++;
    }
    return PCAP_TRUE;
}

PCAP_BOOL pcap_config_check(zval* config)
{
    //检查设备名字是否存在
    HashTable* config_table = Z_ARRVAL_P(config);

    zval* result;

    //加载设备名字
    if(EXPECTED(!(result = zend_hash_str_find(config_table,PCAP_DEV,strlen(PCAP_DEV)))))
    {
        return PCAP_FALSE;
    }
    pcap_factory.dev_name = Z_STR(*result);

    if(EXPECTED(!(result = zend_hash_str_find(config_table,PCAP_MAXPACKET_NUM,strlen(PCAP_MAXPACKET_NUM)))))
    {
        pcap_factory.max_packet_num = 0;
    }else{
        convert_to_long(result);
        pcap_factory.max_packet_num = Z_LVAL(*result);
    }
    return PCAP_TRUE;
}

//获取包的类型
PCAP_BOOL pcap_set_packet_handle(pcap_t* handle)
{
    int type;

    //数据类型
    type = pcap_datalink(handle);

    switch (type){
        //以太网
        case DLT_EN10MB:

            return PCAP_TRUE;
        case DLT_AX25:
            return PCAP_TRUE;
    }
    return PCAP_FALSE;
}