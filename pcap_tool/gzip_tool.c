//
// Created by root on 2020/2/17.
//
#include "common.h"
//解压gzip
PCAP_BOOL gzip_decompress(void* context,size_t decompress_size)
{
    z_stream stream;
    bzero(&stream, sizeof(stream));
    zend_string* html_buf;
    zend_string* result = NG(http_sentry_handle)->html_body;

    if(inflateInit2(&stream,16+MAX_WBITS) != Z_OK)
    {
        return PCAP_FALSE;
    }
    char chunk[BUFSIZ];
    size_t buf_len = 0;

    int ret;
    char* html;
    size_t extend_len;
    stream.next_in = (Bytef *)context;
    stream.avail_in = decompress_size;
    //csdn https://blog.csdn.net/stayneckwind2/article/details/89199422
    do {
        bzero(chunk, sizeof(chunk));
        stream.next_out = (Bytef *)chunk;
        stream.avail_out = sizeof(chunk);
        ret = inflate(&stream,Z_NO_FLUSH);
        if(ret < Z_OK)
        {
            break;
        }

        //装填进入缓冲区
        buf_len = strlen(chunk);
        extend_len = NG(http_sentry_handle)->html_size + buf_len;
        //扩容字符串
        result = zend_string_extend(result,extend_len,0);
        memcpy(ZSTR_VAL(result)+NG(http_sentry_handle)->html_size,chunk,buf_len);
        NG(http_sentry_handle)->html_size += buf_len;
    }while (ret == Z_OK);
    NG(http_sentry_handle)->html_body = zend_string_extend(result,0,0);
    inflateEnd(&stream);
    php_printf("buf:%s\n",ZSTR_VAL(result));
    if(ret == Z_STREAM_END)
        return PCAP_FALSE;
    else
        return PCAP_TRUE;
}