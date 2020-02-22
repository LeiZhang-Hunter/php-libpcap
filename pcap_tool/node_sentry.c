//
// Created by root on 20-2-21.
//
#include "common.h"

PCAP_BOOL init_node_sentry(zend_sentry_client_globals* handle)
{
    handle->dispatch = NO_DISPATCH;
    //初始化pcap的操作库
    handle->pcap_lib = emalloc(sizeof(pcap_module));
    pcap_lib_init(handle->pcap_lib);

    //初始化以太网头
    handle->eth_packet_handle = emalloc(sizeof(ether_packet));
    init_ether_packet(handle->eth_packet_handle);

    //初始化ip头
    handle->ip_packet_handle = emalloc(sizeof(ip_packet));
    init_ip_packet(handle->ip_packet_handle);

    //初始化tcp头
    handle->tcp_packet_handle = emalloc(sizeof(tcp_packet));
    init_tcp_packet(handle->tcp_packet_handle);

    //初始化http头
    handle->http_sentry_handle = emalloc(sizeof(http_sentry));
    init_http_sentry_container(handle->http_sentry_handle);

    handle->task = emalloc(sizeof(user_hook));

    handle->finish = node_sentry_finish;

    handle->dtor = node_sentry_dtor;
}

PCAP_BOOL node_sentry_finish()
{
    zval args[1];
    zval result;
    zval ether_var;
    zval ip_var;
    zval tcp_var;
    zval* http_var;
    HashTable* args_var;
    HashTable* table;
    zval unit;
    if(NG(dispatch) == DO_DISPATCH)
    {
        array_init(&args[0]);
        args_var = Z_ARRVAL_P(&args[0]);

        /*============================物理网卡==================================*/
        array_init(&ether_var);
        table = Z_ARRVAL_P(&ether_var);
        ZVAL_STRING(&unit,NG(eth_packet_handle)->source_mac);
        zend_hash_str_add(table,MAC_SOURCE,strlen(MAC_SOURCE),&unit);
        ZVAL_STRING(&unit,NG(eth_packet_handle)->dest_mac);
        zend_hash_str_add(table,MAC_DEST,strlen(MAC_DEST),&unit);
        ZVAL_LONG(&unit,NG(eth_packet_handle)->ether_type);
        zend_hash_str_add(table,ETH_PROTO,strlen(ETH_PROTO),&unit);
        zend_hash_str_update(args_var,ETHER,strlen(ETHER),&ether_var);

        /*============================ip头==================================*/
        array_init(&ip_var);
        table = Z_ARRVAL_P(&ip_var);
        ZVAL_STRING(&unit,NG(ip_packet_handle)->src_addr);
        zend_hash_str_add(table,_IP_SRC,strlen(_IP_SRC),&unit);
        ZVAL_STRING(&unit,NG(ip_packet_handle)->dest_addr);
        zend_hash_str_add(table,_IP_DST,strlen(_IP_DST),&unit);
        ZVAL_LONG(&unit,NG(ip_packet_handle)->ttl);
        zend_hash_str_add(table,_IP_TTL,strlen(_IP_TTL),&unit);
        ZVAL_LONG(&unit,NG(ip_packet_handle)->protocol);
        zend_hash_str_add(table,_IP_PROTOCOL,strlen(_IP_PROTOCOL),&unit);
        ZVAL_LONG(&unit,NG(ip_packet_handle)->tos);
        zend_hash_str_add(table,_IP_TOS,strlen(_IP_TOS),&unit);
        ZVAL_LONG(&unit,NG(ip_packet_handle)->total_len);
        zend_hash_str_add(table,_IP_TOTAL_LEN,strlen(_IP_TOTAL_LEN),&unit);
        ZVAL_LONG(&unit,NG(ip_packet_handle)->id);
        zend_hash_str_add(table,_IP_ID,strlen(_IP_ID),&unit);
        ZVAL_LONG(&unit,NG(ip_packet_handle)->sum);
        zend_hash_str_add(table,_IP_SUM,strlen(_IP_SUM),&unit);
        ZVAL_LONG(&unit,NG(ip_packet_handle)->header_len);
        zend_hash_str_add(table,_IP_HEADER_LEN,strlen(_IP_HEADER_LEN),&unit);
        ZVAL_LONG(&unit,NG(ip_packet_handle)->version);
        zend_hash_str_add(table,_IP_VERSION,strlen(_IP_VERSION),&unit);
        zend_hash_str_update(args_var,IP_PACKET,strlen(IP_PACKET),&ip_var);

        /*============================tcp头==================================*/
        array_init(&tcp_var);
        table = Z_ARRVAL_P(&tcp_var);
        ZVAL_LONG(&unit,NG(tcp_packet_handle)->flags);
        zend_hash_str_add(table,_TCP_FLAGS,strlen(_TCP_FLAGS),&unit);
        ZVAL_LONG(&unit,NG(tcp_packet_handle)->source_port);
        zend_hash_str_add(table,_TCP_SPORT,strlen(_TCP_SPORT),&unit);
        ZVAL_LONG(&unit,NG(tcp_packet_handle)->dest_port);
        zend_hash_str_add(table,_TCP_DPORT,strlen(_TCP_DPORT),&unit);
        ZVAL_LONG(&unit,NG(tcp_packet_handle)->win);
        zend_hash_str_add(table,_TCP_WINDOW,strlen(_TCP_WINDOW),&unit);
        ZVAL_LONG(&unit,NG(tcp_packet_handle)->sum);
        zend_hash_str_add(table,_TCP_SUM,strlen(_TCP_SUM),&unit);
        ZVAL_LONG(&unit,NG(tcp_packet_handle)->urp);
        zend_hash_str_add(table,_TCP_URG,strlen(_TCP_URG),&unit);
        ZVAL_LONG(&unit,NG(tcp_packet_handle)->seq);
        zend_hash_str_add(table,_TCP_TH_SEQ,strlen(_TCP_TH_SEQ),&unit);
        ZVAL_LONG(&unit,NG(tcp_packet_handle)->ack);
        zend_hash_str_add(table,_TCP_TH_ACK,strlen(_TCP_TH_ACK),&unit);
        ZVAL_LONG(&unit,NG(tcp_packet_handle)->payload_size);
        zend_hash_str_add(table,_TCP_SEGMENT,strlen(_TCP_SEGMENT),&unit);
        zend_hash_str_update(args_var,_TCP_PACKET,strlen(_TCP_PACKET),&tcp_var);

        /*============================http头==================================*/
        http_var = NG(http_sentry_handle)->get_auto_http_table_zval();
        if(http_var && Z_TYPE(*http_var) == IS_ARRAY)
        {
            zend_hash_str_update(args_var,HTTP_PACKET,strlen(HTTP_PACKET),http_var);
            //执行任务
            call_user_function_ex(EG(function_table), NULL, &NG(task)->hook,&result, 1, args, 0, NULL);
        }

    }

    NG(http_sentry_handle)->finish();
    NG(tcp_packet_handle)->finish();
    NG(ip_packet_handle)->finish();
    NG(eth_packet_handle)->finish();
}

PCAP_BOOL node_sentry_dtor()
{
    NG(http_sentry_handle)->dtor();
    NG(tcp_packet_handle)->dtor();
    NG(ip_packet_handle)->dtor();
    NG(eth_packet_handle)->dtor();
}