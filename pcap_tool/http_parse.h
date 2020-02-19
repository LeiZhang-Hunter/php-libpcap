//
// Created by root on 2020/2/17.
//

#ifndef LIBPCAP_HTTP_PARSE_H
#define LIBPCAP_HTTP_PARSE_H

#endif //LIBPCAP_HTTP_PARSE_H

enum {
    HTTP_GET_CODE,
    HTTP_POST_CODE,
    HTTP_RESPONSE_CODE,
    PARSE_R_NO_HAVE_COMPLETE,//解析到了\r但是没有解析出头
    PARSE_COMPLETE,//解析到了http的头
    HEADER_COMPLETE,//解析成功头部
    FOUND_HTTP_KEY_POSITION,
    FOUND_HTTP_VALUE_POSITION,
    HTTP_GZIP_BEGIN_LENGTH,//开始计算包长度
    HTTP_GZIP_DO_LENGTH,//计算中
    HTTP_GZIP_END_LENGTH,
    HTTP_GZIP_START_BODY,//开始计算主题内容

};
#define HTTP_TYPE "http_type"
#define HTTP_REQUEST "http_request"
#define HTTP_REQUEST_POST "http_request_post"
#define HTTP_RESPONSE "http_response"
#define HTTP_BINARY_DATA "http_binary_data"
#define HTTP_HEADER "http_header"

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
#define CHUNK_STOP 0

typedef struct _http_sentry{
    //这是一个用来计算chunk块的
    uint8_t run_state;
    uint8_t start_chunk;//是否开启chunked解析
    uint8_t start_gzip;//是否开启gzip解析
    PCAP_BOOL (*start)();
    PCAP_BOOL (*stop)();
    PCAP_BOOL (*destroy)();
    PCAP_BOOL (*execute_http_compile)(u_char* context,size_t context_size,zval* zval_container);
    size_t html_size;//html的尺寸
    zend_string* html_body;//html的消息体 这里用柔性数组，用来存储不定长的html
}http_sentry;

http_sentry* http_sentry_container;

PCAP_BOOL init_http_sentry_container();

void check_http_sentry_container();

PCAP_BOOL http_sentry_start();

PCAP_BOOL http_sentry_stop();

PCAP_BOOL http_sentry_destroy(http_sentry* container);

PCAP_BOOL _execute_http_compile(u_char* context,size_t context_size,zval* zval_container);

