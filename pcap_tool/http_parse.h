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
};
#define HTTP_TYPE "http_type"
#define HTTP_REQUEST "http_request"
#define HTTP_REQUEST_POST "http_request_post"
#define HTTP_RESPONSE "http_response"
#define HTTP_BINARY_DATA "http_binary_data"
#define HTTP_HEADER "http_header"

#define CURRENT_OFFSET_KEY_BEGIN() offset_key_begin
#define CURRENT_OFFSET_KEY_END() offset_key_end
#define CURRENT_OFFSET_VALUE_BEGIN() offset_value_begin
#define CURRENT_OFFSET_VALUE_END() offset_value_end

typedef struct _http_parse{

    PCAP_BOOL (*execute_http_compile)(u_char* context,zval* zval_container);

}http_parse;

PCAP_BOOL _execute_http_compile(u_char* context,size_t context_size,zval* zval_container);

