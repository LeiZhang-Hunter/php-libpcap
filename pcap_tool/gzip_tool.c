//
// Created by root on 2020/2/17.
//
#include "common.h"
//解压gzip
PCAP_BOOL gzip_decompress(char* buf,void* context,size_t decompress_size)
{
    z_stream stream;
    bzero(&stream, sizeof(stream));
    zend_string* html_buf;
    zend_string* result;

    if(inflateInit2(&stream,16+MAX_WBITS) != Z_OK)
    {
        return PCAP_FALSE;
    }
    char chunk[BUFSIZ];
    size_t buf_len = 0;

    int ret;
    char* html;
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
        html_buf = zend_string_init(chunk,strlen(chunk),0);
        http_sentry_container->html_size += buf_len;//扩容
        result = zend_string_extend(html_buf,http_sentry_container->html_size,0);
        http_sentry_container->html_size = strlen(chunk);
        zend_string_release(html_buf);
    }while (ret == Z_OK);
    php_printf("buf:%s\n",ZSTR_VAL(result));
    inflateEnd(&stream);
    if(ret == Z_STREAM_END)
        return PCAP_FALSE;
    else
        return PCAP_TRUE;
}