//
// Created by root on 2020/2/17.
//
#include "common.h"

//初始化哨兵容器
PCAP_BOOL init_http_sentry_container(http_sentry* http_sentry_container)
{
    bzero(http_sentry_container,sizeof(http_sentry));
    http_sentry_container->http_state = ON_INIT;
    http_sentry_container->wait_return = 0;//初始化为0
    http_sentry_container->auto_join_http_table = _auto_join_http_table;
    http_sentry_container->auto_set_chunk = _auto_set_chunk;
    http_sentry_container->auto_set_gzip = _auto_set_gzip;
    http_sentry_container->dtor = _http_sentry_dtor;
    http_sentry_container->finish = _http_sentry_finish;
    http_sentry_container->on_request = _on_request;
    http_sentry_container->on_chunk = _on_chunk;
    http_sentry_container->on_body = _on_body;
    http_sentry_container->fill_html = _fill_html;
    http_sentry_container->on_response = _on_response;
    http_sentry_container->auto_get_chunk = _auto_get_chunk;
    http_sentry_container->auto_get_gzip = _auto_get_gzip;
    http_sentry_container->get_auto_http_table = _get_auto_http_table;
    http_sentry_container->auto_set_http_table_str = _auto_set_http_table_str;
    http_sentry_container->get_auto_http_table_zval = _get_auto_http_table_zval;
    http_sentry_container->auto_leave_http_table = _auto_leave_http_table;
    http_sentry_container->parse = _execute_http_compile;
    http_sentry_container->check_chunk_footer = _check_chunk_footer;
    zval* array = emalloc(sizeof(zval));
    array_init(array);
    http_sentry_container->http_array_table = array;
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

PCAP_BOOL _execute_http_compile(const u_char* context,size_t context_size)
{
    //由于http前半段的packet不可能出现\0所以可以直接转化为字符串
    char* http_header_context = (char*)context;
    size_t http_header_len = strlen(http_header_context);

    NG(http_sentry_handle)->http_state = ON_BEGIN;

    //小于四个字节可以直接忽略了
    if(http_header_len < 4)
    {
        NG(http_sentry_handle)->http_state = ON_ERROR;
        return PCAP_FALSE;
    }
    //进入
    NG(http_sentry_handle)->auto_join_http_table();

    //解析到如果是rst则是复位包
    if(NG(tcp_packet_handle)->flags & TH_RST)
    {
        NG(http_sentry_handle)->http_state = ON_ERROR;
        return PCAP_FALSE;
    }

    //解析到如果是fin则是复位包
    if(NG(tcp_packet_handle)->flags & TH_FIN)
    {
        NG(http_sentry_handle)->http_state = ON_CLOSE;
        return PCAP_FALSE;
    }

    //如果是rst则对端关闭

    if(!CHECK_HTTP_GET(http_header_context) || !CHECK_HTTP_POST(http_header_context))
    {
        //request
        NG(http_sentry_handle)->on_request(context,context_size);
        NG(http_sentry_handle)->http_state = ON_COMPELETE;
        return PCAP_TRUE;
    }else if(!CHECK_HTTP_RESPONSE(http_header_context))
    {
        return NG(http_sentry_handle)->on_response(context,context_size);
    }else {
        if(NG(http_sentry_handle)->auto_get_chunk())
        {
            return NG(http_sentry_handle)->on_chunk(context,context_size);
        }else{
            return NG(http_sentry_handle)->on_body(context,context_size);
        }
    }
}

PCAP_BOOL http_sentry_stop()
{
}

PCAP_BOOL http_sentry_start()
{
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
    if(!NG(http_sentry_handle))
    {
        zend_throw_error(NULL,"%s\n","httpSentry not initialized");
        exit(-1);
    }
}

//自动进入
PCAP_BOOL _auto_join_http_table()
{
    char http_key[255];
    zval http_hash;//一个空的数组
    time_t time_val;
    zval now_time;
    //生成的ip和post的key
    php_sprintf(http_key,"%s:%d_%s:%d",(NG(ip_packet_handle)->src_addr),NG(tcp_packet_handle)->source_port,
    (NG(ip_packet_handle)->dest_addr),NG(tcp_packet_handle)->dest_port);

    array_init(&http_hash);
    HashTable* table = Z_ARRVAL_P(NG(http_sentry_handle)->http_array_table);
    //存储住这个key
    strcpy(NG(http_sentry_handle)->hash_key,http_key);

    //首先查找这个key是否存在
    zval* record = zend_hash_str_find(table,http_key,strlen(http_key));
    time(&time_val);
    ZVAL_LONG(&now_time,time_val);
    if(record && Z_TYPE(*record) == IS_ARRAY)
    {
        zend_hash_str_update(Z_ARRVAL_P(record),CTIME,strlen(CTIME),&now_time);
    }else{
        zend_hash_str_update(Z_ARRVAL_P(&http_hash),CTIME,strlen(CTIME),&now_time);
        zend_hash_str_update(table,http_key,strlen(http_key),&http_hash);
    }
    return PCAP_TRUE;
}

//设置是否开启了chunk
PCAP_BOOL _auto_set_chunk(uint8_t chunk_flag)
{
    zval* hash_unit;
    HashTable* table = Z_ARRVAL_P(NG(http_sentry_handle)->http_array_table);
    found:
    if(!(hash_unit = zend_hash_str_find(table,NG(http_sentry_handle)->hash_key,strlen(NG(http_sentry_handle)->hash_key))))
    {
        NG(http_sentry_handle)->auto_join_http_table();//自动加入
        //重新查找
        goto found;
    }

    zval data;
    ZVAL_LONG(&data,chunk_flag);

    zend_hash_str_update(Z_ARRVAL_P(hash_unit),CHUNK_FLAG,strlen(CHUNK_FLAG),&data);

    return PCAP_TRUE;
}

//设置是否开启了gzip,自动的默认的就是当前请求的
PCAP_BOOL _auto_set_gzip(uint8_t gzip_flag)
{
    zval* hash_unit;
    zval data;
    HashTable* table = Z_ARRVAL_P(NG(http_sentry_handle)->http_array_table);
    found:
    if(!(hash_unit = zend_hash_str_find(table,NG(http_sentry_handle)->hash_key,strlen(NG(http_sentry_handle)->hash_key))))
    {
        NG(http_sentry_handle)->auto_join_http_table();//自动加入
        //重新查找
        goto found;
    }
    ZVAL_LONG(&data,gzip_flag);
    zend_hash_str_update(Z_ARRVAL_P(hash_unit),GZIP_FLAG,strlen(GZIP_FLAG),&data);
    return PCAP_TRUE;
}

//获取gzip的状态位
int _auto_get_gzip()
{
    zval* hash_unit;
    HashTable* table = Z_ARRVAL_P(NG(http_sentry_handle)->http_array_table);
    if(!(hash_unit = zend_hash_str_find(table,NG(http_sentry_handle)->hash_key,strlen(NG(http_sentry_handle)->hash_key))))
    {
        return GZIP_CLOSE;
    }

    zval* gzip_zval = zend_hash_str_find(Z_ARRVAL_P(hash_unit),GZIP_FLAG,strlen(GZIP_FLAG));
    if(!gzip_zval)
    {
        return GZIP_CLOSE;
    }
    return (int)Z_LVAL(*gzip_zval);
}

//获取chunk标志位的状态
int _auto_get_chunk()
{
    zval* hash_unit;
    HashTable* table = Z_ARRVAL_P(NG(http_sentry_handle)->http_array_table);
    if(!(hash_unit = zend_hash_str_find(table,NG(http_sentry_handle)->hash_key,strlen(NG(http_sentry_handle)->hash_key))))
    {
        return GZIP_CLOSE;
    }

    zval* gzip_zval = zend_hash_str_find(Z_ARRVAL_P(hash_unit),CHUNK_FLAG,strlen(CHUNK_FLAG));
    if(!gzip_zval)
    {
        return GZIP_CLOSE;
    }

    return (int)Z_LVAL(*gzip_zval);
}

//获取自己的http table
zval* _get_auto_http_table_zval()
{
    zval* hash_unit = NULL;
    HashTable* table = Z_ARRVAL_P(NG(http_sentry_handle)->http_array_table);
    if(!(hash_unit = zend_hash_str_find(table,NG(http_sentry_handle)->hash_key,strlen(NG(http_sentry_handle)->hash_key))))
    {
        return NULL;
    }

    return hash_unit;

}

//自动离开，并且进行内存回收
PCAP_BOOL _auto_leave_http_table()
{
    HashTable* table = Z_ARRVAL_P(NG(http_sentry_handle)->http_array_table);
    if(!(zend_hash_str_find(table,NG(http_sentry_handle)->hash_key,strlen(NG(http_sentry_handle)->hash_key))))
    {
        return PCAP_FALSE;
    }
    zend_hash_str_del(table,NG(http_sentry_handle)->hash_key,strlen(NG(http_sentry_handle)->hash_key));
    return PCAP_TRUE;
}

HashTable* _get_auto_http_table()
{
    zval* table = zend_hash_str_find(Z_ARRVAL_P(NG(http_sentry_handle)->http_array_table),NG(http_sentry_handle)->hash_key
            ,strlen(NG(http_sentry_handle)->hash_key));

    if(!table)
    {
        return NULL;
    }

    return Z_ARRVAL_P(table);
}

PCAP_BOOL _auto_set_http_table_str(char* key,char* value)
{
    HashTable* this_table = NG(http_sentry_handle)->get_auto_http_table();
    if(!this_table)
    {
        return PCAP_FALSE;
    }

    zval unit;
    ZVAL_STRING(&unit,value);
    if(zend_hash_str_update(this_table,(key),strlen(key),&unit))
    {
        return PCAP_TRUE;
    }else{
        return PCAP_FALSE;
    }
}

//这是一个处理请求的
PCAP_BOOL _on_request(const u_char* context,size_t segment)
{
    char* content;
    char* save_ptr;
    char* line;
    char* line_save_ptr;
    char* http_request_key;
    char* http_request_value;
    content = (char*)context;
    u_char byte = context[segment];
    content[segment] = '\0';
    //首先处理请求头
    char* header = strtok_r(content,"\r\n",&save_ptr);
    if(!header)
        return PCAP_FALSE;
    NG(http_sentry_handle)->auto_set_http_table_str(HTTP_HEADER,header);

    while((line = strtok_r(NULL,"\r\n",&save_ptr)))
    {
        http_request_key = strtok_r(line,": ",&line_save_ptr);
        if(!http_request_key)
            continue;

        http_request_value = strtok_r(NULL,": ",&line_save_ptr);
        if(!http_request_value)
            continue;

        NG(http_sentry_handle)->auto_set_http_table_str(http_request_key,http_request_value);
    }
    content[segment] = byte;
    return PCAP_TRUE;
}

PCAP_BOOL _check_chunk_footer(u_char* context,size_t segment)
{
    if(segment < 5)
    {
        return PCAP_FALSE;
    }

    size_t offset = segment-5;
    char* footer_mem = (char*)(context+offset);
    if(!memcmp(footer_mem,"\0\r\n\r\n",5))
    {
        return PCAP_TRUE;
    }else{
        return PCAP_FALSE;
    }
}

//处理响应
PCAP_BOOL _on_response(const u_char* packet,size_t segment)
{
    /*=====================变量的定义区域==========================*/
    size_t i;
    char byte;
    char temp;//临时存储
    size_t header_finish_position = 0;//头解析结束位置
    char* http_header_key;//存放key的
    char* http_header_value;//存放value的
    uint8_t gzip_decompress_flag = 0;//是否开启gzip的解压工作
    size_t CURRENT_OFFSET_KEY_BEGIN() = 0;
    size_t CURRENT_OFFSET_KEY_END() = 0;
    size_t CURRENT_OFFSET_VALUE_BEGIN() = 0;
    size_t CURRENT_OFFSET_VALUE_END() = 0;
    size_t body_size = 0;
    size_t chunk_body_length_begin = 0;//chunk长度开始的位置
    char* chunk_len_ptr;
    uint8_t is_chunk = CHUNK_CLOSE;//是否是chunk
    size_t context_size=segment;
    zend_string* html = NULL;
    zval unit;
    //当前的解析状态
    uint parse_state = PARSE_R_NO_HAVE_COMPLETE;
    HashTable* http_table = NG(http_sentry_handle)->get_auto_http_table();
    char* context = (char*)packet;
    /*======================================================================*/

    //http响应的解析区域
    for(i = 0;i<segment;i++)
    {
        byte = context[i];
        switch (parse_state)
        {
            //没解析出来头部
            case PARSE_R_NO_HAVE_COMPLETE:
                //解析出来header
                if(byte == LF)
                {
                    header_finish_position = i-1;
                    if(header_finish_position < 0)
                    {
                        goto error;
                    }
                    temp = context[header_finish_position];
                    context[header_finish_position] = EOS;
                    ZVAL_STRING(&unit,context);
                    context[header_finish_position] = temp;//还原回原本的字符串
                    zend_hash_str_add(http_table,HTTP_HEADER,strlen(HTTP_HEADER),&unit);
                    CURRENT_OFFSET_KEY_BEGIN() = i+1;
                    parse_state = PARSE_COMPLETE;
                    continue;
                }
                break;

            case PARSE_COMPLETE:
                //头部解析完成开始解析各个key_value
                if(byte == ':')
                {
                    CURRENT_OFFSET_KEY_END() = i;
                    parse_state = FOUND_HTTP_KEY_POSITION;
                    break;
                }
                break;

            case FOUND_HTTP_KEY_POSITION: {
                //找到了\r就发现了值
                if (byte == CR) {
                    parse_state = FOUND_HTTP_VALUE_POSITION;
                }
                break;
            }

            case FOUND_HTTP_VALUE_POSITION: {
                //这里出现了\n ,而且在之前已经出现了 : '' 所以说这里是key的结束位置
                if (byte == LF) {
                    temp = context[CURRENT_OFFSET_KEY_END()];
                    //这里要求出key和value并存到php数组里
                    http_header_key =  context + CURRENT_OFFSET_KEY_BEGIN();
                    context[CURRENT_OFFSET_KEY_END()] = EOS;

                    if(segment - CURRENT_OFFSET_KEY_END() < 2)
                    {
                        goto error;
                    }
                    http_header_value =  context + CURRENT_OFFSET_KEY_END() + 2;//因为是两个有:和''
                    byte = context[i - 1];
                    context[i - 1] = EOS;

                    ZVAL_STRING(&unit, http_header_value);
                    zend_hash_str_add(http_table, http_header_key, strlen(http_header_key), &unit);

                    //如果采用chunk块传输
                    if (!strcmp(http_header_key, "Transfer-Encoding") && !strcmp(http_header_value, "chunked")) {
                        NG(http_sentry_handle)->auto_set_chunk(CHUNK_OPEN);//自动把位置标记为开启chunk
                        is_chunk = CHUNK_OPEN;
                    }

                    //在这里要确认是否要gzip解压，如果出现要解压的情况则要执行解压
                    if (!strcmp(http_header_key, "Content-Encoding") && !strcmp(http_header_value, "gzip")) {
                        //开始进行gzip解压缩
                        gzip_decompress_flag = HTTP_GZIP;
                        NG(http_sentry_handle)->auto_set_gzip(GZIP_OPEN);//自动把位置标记为开启chunk
                    }

                    //这里要小心意义复原不要破坏原本的字节
                    context[CURRENT_OFFSET_KEY_END()] = temp;
                    context[i - 1] = byte;

                    //重置他们的位置方便下次计算,防止越界
                    CURRENT_OFFSET_KEY_BEGIN() = i+1;

                    //key: value\r\n\r\n 这种情况肯能是数据区域或者是 chunk的区域了
                    if(context[i+1] == CR)
                    {
                        parse_state = COMPILE_HTTP_VALUE_POSITION;
                    }else{
                        //key: value \r\n key:value 这里是继续去解析下一次的值
                        parse_state = PARSE_COMPLETE;
                    }
                    break;
                }
                break;
            }

            case COMPILE_HTTP_VALUE_POSITION: {
                if(byte == CR)
                {
                    parse_state = SECOND_CR;
                }
                break;
            }

            case SECOND_CR:{
                if(byte == LF)
                {
                    parse_state = SECOND_LF;
                }
                break;
            }

            //进入了数据区
            case SECOND_LF: {
                /*==========================================================================*/
                //如果说是块传输 并且已经进入到第二个以后了 那么这个是size
                if(is_chunk == CHUNK_OPEN)
                {
                    chunk_body_length_begin = i;//开始位置是这个之后一个字节
                    parse_state = HTTP_BEGIN_LENGTH;
                }else{
                    //开始计算长度了
                    if(gzip_decompress_flag == HTTP_GZIP) {

                    }else{
                    }
                }
                break;
            }

            //计算chunk的长度
            case HTTP_BEGIN_LENGTH:{
                if(byte == CR)
                {
                    temp = context[i];
                    chunk_len_ptr = (context+chunk_body_length_begin);
                    context[i] = EOS;
                    body_size = (size_t)htoi(chunk_len_ptr);
                    context[i] = temp;
                    parse_state = CHUNK_FOUND_BODY_BEGIN;//还原方便进入数据区
                    ZVAL_LONG(&unit,body_size)
                    zend_hash_str_update(http_table,CHUNK_SIZE,strlen(CHUNK_SIZE),&unit);
                    continue;
                }
                break;
            }

            case CHUNK_FOUND_BODY_BEGIN: {
                if(byte == LF)
                {
                    parse_state = CHUNK_BODY_BEGIN;
                }
                break;
            }

            //只有chunk会走到这一块逻辑
            case CHUNK_BODY_BEGIN:{
                //从这里开始是块的body了
                if(NG(http_sentry_handle)->auto_get_gzip())
                {
                    //开启了gzip
                    body_size = context_size - i;
                    temp = context[body_size];
                    //检查chunk的footer
                    if(NG(http_sentry_handle)->check_chunk_footer((u_char*)packet,segment) == PCAP_TRUE)
                    {
                        //如果说是开启了gzip
                        html = gzip_decompress((u_char*)(context+i), (uint)body_size);
                        if(!html)
                        {
                            goto error;
                        }
                        NG(http_sentry_handle)->auto_set_http_table_str(HTML,ZSTR_VAL(html));
                        goto finish;
                    }else{
                        html = zend_string_init(context+i,body_size,0);
                        if(!html)
                        {
                            goto error;
                        }
                        HashTable* this_table = NG(http_sentry_handle)->get_auto_http_table();
                        ZVAL_STR(&unit,html);
                        zend_hash_str_update(this_table,HTML,strlen(HTML),&unit);
                        goto wait;
                    }




                }else{
                }
                break;
            }
        }
    }

    finish:{
        NG(http_sentry_handle)->http_state = ON_COMPELETE;
        return PCAP_TRUE;
    };

    error:{
        NG(http_sentry_handle)->http_state = ON_ERROR;
        return PCAP_FALSE;
    };

    wait:{
        NG(http_sentry_handle)->http_state = ON_WAIT;
        return PCAP_FALSE;
    };
}

void _http_sentry_dtor()
{

}

void _http_sentry_finish()
{
    switch (NG(http_sentry_handle)->http_state)
    {
        case ON_COMPELETE:
        case ON_ERROR:
        case ON_CLOSE:
            NG(http_sentry_handle)->auto_leave_http_table();
            break;
    }
}

PCAP_BOOL _on_chunk(const u_char* context,size_t segment)
{
    char* content = (char*)context;
    char byte = content[segment];
    zend_string* buffer;
    zend_string* html;
    HashTable* table;
    zval* ret;

    //压缩 解压缩
    if(NG(http_sentry_handle)->auto_get_gzip())
    {
        buffer = zend_string_init(content,segment,0);
        NG(http_sentry_handle)->fill_html((buffer));

        PCAP_BOOL footer = NG(http_sentry_handle)->check_chunk_footer((u_char*)context,segment);
        if(footer)
        {
            table = NG(http_sentry_handle)->get_auto_http_table();
            if(!table)
            {
                goto error;
            }
            ret = zend_hash_str_find(table,HTML,strlen(HTML));
            if(!ret)
            {
                goto error;
            }
            html = gzip_decompress((u_char*)(ZSTR_VAL(Z_STR(*ret))),Z_STRLEN(*ret));
            if(!html)
            {
                goto error;
            }

            NG(http_sentry_handle)->auto_set_http_table_str(HTML,ZSTR_VAL(html));
            goto finish;
        }else{
            goto wait;
        }
    }else{

    }
    content[segment] = byte;

    finish:{
        NG(http_sentry_handle)->http_state = ON_COMPELETE;
        return PCAP_TRUE;
    };

    error:{
        NG(http_sentry_handle)->http_state = ON_ERROR;
        return PCAP_FALSE;
    };

    wait:{
        NG(http_sentry_handle)->http_state = ON_WAIT;
        return PCAP_FALSE;
    };
    return PCAP_FALSE;
}

PCAP_BOOL _on_body(const u_char* context,size_t segment)
{
    NG(http_sentry_handle)->http_state = ON_COMPELETE;
    return PCAP_FALSE;
}

PCAP_BOOL _fill_html(zend_string* html)
{
    zval unit;
    size_t extend_len;
    if(!html)
        return PCAP_FALSE;
    HashTable* table = NG(http_sentry_handle)->get_auto_http_table();
    zval* html_zval = zend_hash_str_find(table,HTML,strlen(HTML));
    if(!html_zval) {
        ZVAL_STR(&unit,html);
        zend_hash_str_add(table,HTML,strlen(HTML),&unit);
        return PCAP_TRUE;
    }else{
        zend_string* body = Z_STR(*html_zval);
        size_t body_len = ZSTR_LEN(body);
        extend_len = body_len+ZSTR_LEN(html);
        //扩容
        zend_string* new_string = zend_string_extend(body,extend_len,0);
        if(!new_string)
        {
            return PCAP_FALSE;
        }
        //拼接
        memcpy(ZSTR_VAL(new_string)+body_len,ZSTR_VAL(html),ZSTR_LEN(html));
        ZVAL_STR(&unit,new_string);
        zend_hash_str_update(table,HTML,strlen(HTML),&unit);
        return PCAP_TRUE;
    }

}