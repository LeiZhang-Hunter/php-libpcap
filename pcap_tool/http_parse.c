//
// Created by root on 2020/2/17.
//
#include "common.h"

//初始化哨兵容器
PCAP_BOOL init_http_sentry_container()
{
    http_sentry_container = emalloc(sizeof(http_sentry));
    bzero(http_sentry_container,sizeof(http_sentry));
    http_sentry_container->run_state = 0;
    http_sentry_container->start_chunk = 0;//初始化为0
    http_sentry_container->start_gzip = 0;//初始化gzip
    http_sentry_container->destroy = http_sentry_destroy;
    http_sentry_container->start = http_sentry_start;
    http_sentry_container->stop = http_sentry_stop;
    http_sentry_container->execute_http_compile = _execute_http_compile;
    http_sentry_container->html_size = 0;
    http_sentry_container->html_body = zend_string_init("",strlen(""),0);//初始化html
}

//16进制字符串转化为代码
int htoi(char s[])
{
    int i;
    int n = 0;
    if (s[0] == '0' && (s[1]=='x' || s[1]=='X'))
    {
        i = 2;
    }
    else
    {
        i = 0;
    }
    for (; (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >='A' && s[i] <= 'Z');++i)
    {
        if (tolower(s[i]) > '9')
        {
            n = 16 * n + (10 + tolower(s[i]) - 'a');
        }
        else
        {
            n = 16 * n + (tolower(s[i]) - '0');
        }
    }
    return n;
}

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
    uint8_t gzip_decompress_flag = 0;//是否开启gzip的解压工作
    size_t CURRENT_OFFSET_KEY_BEGIN() = 0;
    size_t CURRENT_OFFSET_KEY_END() = 0;
    size_t CURRENT_OFFSET_VALUE_BEGIN() = 0;
    size_t CURRENT_OFFSET_VALUE_END() = 0;
    u_char* http_body;
    int body_size = 0;
    int chunk_body_length_begin = 0;//chunk长度开始的位置
    int chunk_body_length_end = 0;//chunk长度结束的位置
    char* chunk_len_ptr;
    //first fit 首次适应算法

    for(i = 0;i<context_size;i++)
    {
        byte = context[i];
        if(!header_complete && byte == CR)
        {
            parse_state = PARSE_R_NO_HAVE_COMPLETE;
            continue;
        }

        if(!header_complete && byte == LF && parse_state == PARSE_R_NO_HAVE_COMPLETE)
        {
            header_finish_position = i-1;
            parse_state = PARSE_COMPLETE;
            context[header_finish_position] = EOS;
            save_data = (char*)context;
            ZVAL_STRING(&unit,save_data);
            context[header_finish_position] = CR;//还原回原本的字符串
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
            if(byte == CR && parse_state==FOUND_HTTP_KEY_POSITION)
            {
                parse_state = FOUND_HTTP_VALUE_POSITION;
                continue;
            }

            //这里
            if(byte == LF && parse_state == FOUND_HTTP_VALUE_POSITION)
            {
                //这里要求出key和value并存到php数组里
                http_header_key = (char*)context + CURRENT_OFFSET_KEY_BEGIN();
                context[CURRENT_OFFSET_KEY_END()] = EOS;

                http_header_value = (char*)context + CURRENT_OFFSET_KEY_END()+2;//因为是两个有:和''
                context[i-1] = EOS;

                ZVAL_STRING(&unit,http_header_value);
                zend_hash_str_add(http_table,http_header_key,strlen(http_header_key),&unit);

                //如果采用chunk块传输
                if(!strcmp(http_header_key,"Transfer-Encoding") && !strcmp(http_header_value,"chunked"))
                {
                    http_sentry_container->start_chunk = CHUNK_OPEN;
                }

                //在这里要确认是否要gzip解压，如果出现要解压的情况则要执行解压
                if(!strcmp(http_header_key,"Content-Encoding") && !strcmp(http_header_value,"gzip"))
                {
                    //开始进行gzip解压缩
                    gzip_decompress_flag = HTTP_GZIP_BEGIN_LENGTH;
                }

                //这里要小心意义复原不要破坏原本的字节
                context[CURRENT_OFFSET_KEY_END()] = ':';
                context[i-1] = CR;

                //重置他们的位置方便下次计算
                CURRENT_OFFSET_KEY_BEGIN() = i+1;
                parse_state = PARSE_COMPLETE;//重置为头状态
            }

            //已经进入解压状态
            if(gzip_decompress_flag == HTTP_GZIP_BEGIN_LENGTH)
            {
                //如果说可以被过滤掉是无用的内容
                if(byte == CR || byte == LF)
                {
                    continue;
                }else{
                    gzip_decompress_flag = HTTP_GZIP_DO_LENGTH;
                    chunk_body_length_begin = i;
                    continue;
                }
            }

            if(gzip_decompress_flag == HTTP_GZIP_DO_LENGTH)
            {
                if(byte == CR){
                    //gzip body的长度计算是 len + body 内容,body可以用gzip 解压缩 len是长度用来计算
                    if(!chunk_body_length_begin)
                    {
                        continue;
                    }
                    context[i] = EOS;
                    chunk_len_ptr = (char*)(context+chunk_body_length_begin);
                    body_size = htoi(chunk_len_ptr);
                    context[i] = CR;
                    continue;
                }else if(byte == LF){
                    gzip_decompress_flag = HTTP_GZIP_END_LENGTH;//计算结束
                    continue;
                }
            }

            if(gzip_decompress_flag == HTTP_GZIP_END_LENGTH)
            {
                if(!body_size)
                {
                    continue;
                }
                http_body = context+i;
                char buf[BUFSIZ];
                gzip_decompress(buf,(void *)http_body,body_size);
                break;
            }
        }

    }

    return PCAP_TRUE;
}

PCAP_BOOL http_sentry_stop()
{
    http_sentry_container->run_state = HTTP_SENTRY_STOP;
}

PCAP_BOOL http_sentry_start()
{
    http_sentry_container->run_state = HTTP_SENTRY_START;
}

PCAP_BOOL http_sentry_destroy(http_sentry* container)
{
    if(!container)
    {
        return PCAP_FALSE;
    }

    free(container);

    return PCAP_TRUE;
}

//检查容器
void check_http_sentry_container()
{
    if(!http_sentry_container)
    {
        zend_throw_error(NULL,"%s\n","httpSentry not initialized");
        exit(-1);
    }
}