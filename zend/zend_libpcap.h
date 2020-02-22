//
// Created by zhanglei on 2020/1/2.
//

#ifndef LIBPCAP_ZEND_LIBPCAP_H
#define LIBPCAP_ZEND_LIBPCAP_H

//定义参数
ZEND_BEGIN_ARG_INFO_EX(pcap_config, 0, 0, 1)
                ZEND_ARG_INFO(0, pcap_config)
ZEND_END_ARG_INFO()

//定义参数
ZEND_BEGIN_ARG_INFO_EX(pcap_recv_hook, 0, 0, 1)
                ZEND_ARG_INFO(0, pcap_recv_hook)
ZEND_END_ARG_INFO()

PHP_METHOD(HttpSentry,__construct);
//设置配置文件
PHP_METHOD(HttpSentry,setConfig);
//当收到数据的时候触发
PHP_METHOD(HttpSentry,onReceive);
//开启循环
PHP_METHOD(HttpSentry,monitor);
//发现所有设备
PHP_METHOD(HttpSentry,findAllDevs);

PHP_METHOD(HttpSentry,__destruct);
void class_Pcap_load();
#endif //LIBPCAP_ZEND_LIBPCAP_H




