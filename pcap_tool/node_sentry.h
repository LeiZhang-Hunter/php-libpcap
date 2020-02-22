//
// Created by root on 20-2-21.
//

#ifndef LIBPCAP_NODESENTRY_H
#define LIBPCAP_NODESENTRY_H
typedef struct _user_hook{
    zval object;
    zval hook;
}user_hook;

#define NO_DISPATCH 0
#define DO_DISPATCH 1

ZEND_BEGIN_MODULE_GLOBALS(sentry_client)
    uint8_t dispatch;
    user_hook* task;
    pcap_module* pcap_lib;
    ether_packet* eth_packet_handle;
    ip_packet* ip_packet_handle;
    tcp_packet* tcp_packet_handle;
    http_sentry* http_sentry_handle;
    PCAP_BOOL (*finish)();
    PCAP_BOOL (*dtor)();
ZEND_END_MODULE_GLOBALS(sentry_client)

ZEND_DECLARE_MODULE_GLOBALS(sentry_client)
ZEND_EXTERN_MODULE_GLOBALS(sentry_client)
#define NG(v) ZEND_MODULE_GLOBALS_ACCESSOR(sentry_client, v)

PCAP_BOOL init_node_sentry(zend_sentry_client_globals* handle);
PCAP_BOOL node_sentry_finish();
PCAP_BOOL node_sentry_dtor();
#endif //LIBPCAP_NODESENTRY_H
