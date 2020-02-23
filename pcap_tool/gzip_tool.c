//
// Created by root on 2020/2/17.
//
#include "common.h"
//解压gzip
zend_string* gzip_decompress(u_char* context,uint decompress_size)
{
    z_stream stream;
    bzero(&stream,sizeof(z_stream));
    bzero(&stream, sizeof(stream));
    zend_string* html_buf = NULL;
    zend_string* result = NULL;
    size_t html_size = 0;
    if(inflateInit2(&stream,16+MAX_WBITS) != Z_OK)
    {
        return NULL;
    }
    char chunk[BUFSIZ];
    size_t buf_len = 0;

    int ret;
    size_t extend_len;
    stream.next_in = (Bytef *)context;
    stream.avail_in = decompress_size;
    //csdn https://blog.csdn.net/stayneckwind2/article/details/89199422
    do {
        bzero(chunk, sizeof(chunk));
        stream.next_out = (Bytef *)chunk;
        stream.avail_out = sizeof(chunk)-1;
        ret = inflate(&stream,Z_NO_FLUSH);
        if(ret < Z_OK)
        {
            break;
        }

        //装填进入缓冲区
        buf_len = strlen(chunk);
        if(!html_buf)
        {
            html_buf = zend_string_init(chunk,stream.total_out,0);
        }else{
            extend_len = stream.total_out;
            //扩容字符串
            result = zend_string_extend(html_buf,extend_len,0);
            memcpy(ZSTR_VAL(result)+html_size,chunk,buf_len);
            html_buf = result;//重置方便下次继续拼接
        }
        html_size += buf_len;
    }while (ret == Z_OK);
    inflateEnd(&stream);
    return result ? result : html_buf;
}