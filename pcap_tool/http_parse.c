//
// Created by root on 2020/2/17.
//
#include "common.h"
PCAP_BOOL _execute_http_compile(u_char* context,size_t context_size,zval* zval_container)
{
    //由于http前半段的packet不可能出现\0所以可以直接转化为字符串
    char* http_header_context = (char*)context;

    size_t http_header_len = strlen(http_header_context);

    //小于四个字节可以直接忽略了
    if(http_header_len < 4)
    {
        return PCAP_FALSE;
    }

    if(!zval_container)
    {
        return PCAP_FALSE;
    }

    zval unit;
    HashTable* http_table = Z_ARRVAL_P(zval_container);

    if(!memcmp(http_header_context,"GET ",4))
    {
        ZVAL_STRING(&unit,HTTP_REQUEST);
        zend_hash_str_add(http_table,HTTP_TYPE,strlen(HTTP_TYPE),&unit);
    }else if(!memcmp(http_header_context,"POST ",5))
    {
        ZVAL_STRING(&unit,HTTP_REQUEST_POST);
        zend_hash_str_add(http_table,HTTP_TYPE,strlen(HTTP_TYPE),&unit);
    }else if(!memcmp(http_header_context,"HTTP",4))
    {
        ZVAL_STRING(&unit,HTTP_RESPONSE);
        zend_hash_str_add(http_table,HTTP_TYPE,strlen(HTTP_TYPE),&unit);
    }else{
        //二进制数据
        ZVAL_STRING(&unit,HTTP_BINARY_DATA);
        zend_hash_str_add(http_table,HTTP_TYPE,strlen(HTTP_TYPE),&unit);
        return PCAP_TRUE;
    }

    int i;
    //是否解析出http的头
    uint8_t header_complete = 0;
    uint parse_state = 0;
    u_char byte;
    int header_finish_position = 0;//头解析结束位置
    char* save_data;
    char* http_header_key;//存放key的
    char* http_header_value;//存放value的
    uint8_t gzip_compress = 0;//是否开启gzip的解压工作
    size_t CURRENT_OFFSET_KEY_BEGIN() = 0;
    size_t CURRENT_OFFSET_KEY_END() = 0;
    size_t CURRENT_OFFSET_VALUE_BEGIN() = 0;
    size_t CURRENT_OFFSET_VALUE_END() = 0;
    for(i = 0;i<context_size;i++)
    {
        byte = context[i];
        if(!header_complete && byte == '\r')
        {
            parse_state = PARSE_R_NO_HAVE_COMPLETE;
            continue;
        }

        if(!header_complete && byte == '\n' && parse_state == PARSE_R_NO_HAVE_COMPLETE)
        {
            header_finish_position = i-1;
            parse_state = PARSE_COMPLETE;
            context[header_finish_position] = '\0';
            save_data = (char*)context;
            ZVAL_STRING(&unit,save_data);
            context[header_finish_position] = '\r';//还原回原本的字符串
            zend_hash_str_add(http_table,HTTP_HEADER,strlen(HTTP_HEADER),&unit);
            header_complete = HEADER_COMPLETE;
            CURRENT_OFFSET_KEY_BEGIN() = i+1;
            continue;
        }

        //如果头解析成功
        if(header_complete == HEADER_COMPLETE && header_finish_position)
        {
            if(byte == ':' && parse_state==PARSE_COMPLETE)
            {
                CURRENT_OFFSET_KEY_END() = i;
                parse_state = FOUND_HTTP_KEY_POSITION;
            }

            //发现了一个key这时候出现了\r
            if(byte == '\r' && parse_state==FOUND_HTTP_KEY_POSITION)
            {
                parse_state = FOUND_HTTP_VALUE_POSITION;
                continue;
            }

            //这里
            if(byte == '\n' && parse_state == FOUND_HTTP_VALUE_POSITION)
            {
                //这里要求出key和value并存到php数组里
                http_header_key = (char*)context + CURRENT_OFFSET_KEY_BEGIN();
                context[CURRENT_OFFSET_KEY_END()] = '\0';

                http_header_value = (char*)context + CURRENT_OFFSET_KEY_END()+2;//因为是两个有:和''
                context[i-1] = '\0';

                ZVAL_STRING(&unit,http_header_value);
                zend_hash_str_add(http_table,http_header_key,strlen(http_header_key),&unit);

                //在这里要确认是否要gzip解压，如果出现要解压的情况则要执行解压
                if(!strcmp(http_header_key,"Content-Encoding") && !strcmp(http_header_value,"gzip"))
                {
                    //开始进行gzip解压缩
                    gzip_compress = 1;
                }

                //这里要小心意义复原不要破坏原本的字节
                context[CURRENT_OFFSET_KEY_END()] = ':';
                context[i-1] = '\r';

                //执行解压逻辑,然后跳出代码块了
                if(gzip_compress)
                {
                    break;
                }

                //重置他们的位置方便下次计算
                CURRENT_OFFSET_KEY_BEGIN() = i+1;
                parse_state = PARSE_COMPLETE;//重置为头状态
            }
        }

    }
    return PCAP_TRUE;
}