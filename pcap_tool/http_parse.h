//
// Created by root on 2020/2/17.
//

#ifndef LIBPCAP_HTTP_PARSE_H
#define LIBPCAP_HTTP_PARSE_H

#endif //LIBPCAP_HTTP_PARSE_H

enum {
    PARSE_R_NO_HAVE_COMPLETE,//解析到了\r但是没有解析出头
    PARSE_COMPLETE,//解析到了http的头
    FOUND_HTTP_KEY_POSITION,
    FOUND_HTTP_VALUE_POSITION,
    COMPILE_HTTP_VALUE_POSITION,
    HTTP_BEGIN_LENGTH,//开始计算包长度
    HTTP_START_GZIP,//开始计算主题内容
    SECOND_CR,
    SECOND_LF,
    CHUNK_FOUND_BODY_BEGIN,
    CHUNK_BODY_BEGIN,
};
#define HTTP_TYPE "http_type"
#define HTTP_REQUEST "http_request"
#define HTTP_REQUEST_POST "http_request_post"
#define HTTP_RESPONSE "http_response"
#define HTTP_BINARY_DATA "http_binary_data"
#define HTTP_HEADER "http_header"
#define HTTP_BODY "http_body"

#define HTTP_STOP 0
#define HTTP_START 1

#define HTTP_SENTRY_STOP 0
#define HTTP_SENTRY_START 1

//https://blog.csdn.net/suliangkuanjiayou/article/details/98966822
#define CR '\r'
#define LF '\n'
#define EOS '\0' //end of string 的缩写

#define CURRENT_OFFSET_KEY_BEGIN() offset_key_begin
#define CURRENT_OFFSET_KEY_END() offset_key_end
#define CURRENT_OFFSET_VALUE_BEGIN() offset_value_begin
#define CURRENT_OFFSET_VALUE_END() offset_value_end

#define CHUNK_OPEN 1
#define CHUNK_CLOSE 0

#define GZIP_OPEN 1
#define GZIP_CLOSE 0

#define CTIME "ctime"
#define CHUNK_FLAG "chunk_flag"
#define GZIP_FLAG "gzip_flag"

typedef struct _http_sentry{
    //这是一个用来计算chunk块的
    uint8_t run_state;
    uint8_t wait_return;//是否开启chunked解析
    uint16_t source_port;
    uint16_t dest_port;
    zend_string* source_ip;
    zend_string* dest_ip;
    zend_string* hash_key;//自动生成散列表单元的时候会生成这个key
    zval* (*get_auto_http_table)();//进入http table
    PCAP_BOOL (*auto_set_chunk)(uint8_t chunk_flag);//进入http table
    PCAP_BOOL (*auto_set_gzip)(uint8_t gzip_flag);//进入http table
    PCAP_BOOL (*auto_join_http_table)();//进入http table
    PCAP_BOOL (*auto_leave_http_table)();//进入http table
    PCAP_BOOL (*start)();
    PCAP_BOOL (*stop)();
    PCAP_BOOL (*destroy)();
    PCAP_BOOL (*execute_http_compile)(u_char* context,size_t context_size,zval* zval_container);
    int (*auto_get_chunk)();
    int (*auto_get_gzip)();
    size_t html_size;//html的尺寸
    /**
     *
     * ["ip:port_ip:port"]=>
     * [
     *  "chunk_flag"=>"",
     *  "gzip_flag"=>"",
     *  "ctime"=>"",
     *  "body"=>""
     * ]
     *
     */
    zval* http_array_table;//这是一个http的消息块，用来存储html的,用来存储chunk的标识，因为http有chunk
    zend_string* html_body;//html的消息体 这里用柔性数组，用来存储不定长的html
}http_sentry;

http_sentry* http_sentry_container;

PCAP_BOOL _auto_set_chunk(uint8_t chunk_flag);

//设置gzip的启用标志
PCAP_BOOL _auto_set_gzip(uint8_t gzip_flag);

PCAP_BOOL init_http_sentry_container();

void check_http_sentry_container();

PCAP_BOOL _auto_join_http_table();

PCAP_BOOL http_sentry_start();

PCAP_BOOL http_sentry_stop();

PCAP_BOOL http_sentry_destroy(http_sentry* container);

PCAP_BOOL _execute_http_compile(u_char* context,size_t context_size,zval* zval_container);

PCAP_BOOL _auto_leave_http_table();

int _auto_get_chunk();

int _auto_get_gzip();

zval* _get_auto_http_table();