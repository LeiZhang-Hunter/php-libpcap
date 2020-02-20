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
    http_sentry_container->hash_key = NULL;
    http_sentry_container->wait_return = 0;//初始化为0
    http_sentry_container->auto_join_http_table = _auto_join_http_table;
    http_sentry_container->auto_set_chunk = _auto_set_chunk;
    http_sentry_container->auto_set_gzip = _auto_set_gzip;
    http_sentry_container->destroy = http_sentry_destroy;
    http_sentry_container->start = http_sentry_start;
    http_sentry_container->stop = http_sentry_stop;
    http_sentry_container->auto_get_chunk = _auto_get_chunk;
    http_sentry_container->auto_get_gzip = _auto_get_gzip;
    http_sentry_container->get_auto_http_table = _get_auto_http_table;
    http_sentry_container->execute_http_compile = _execute_http_compile;
    http_sentry_container->html_size = 0;
    http_sentry_container->html_body = zend_string_init("",strlen(""),0);//初始化html
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

PCAP_BOOL _execute_http_compile(u_char* context,size_t context_size,zval* zval_container)
{
    int i = 0;
    //将数据存入zval hash
    int num = 0;

    //是否解析出http的头
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
    uint8_t is_chunk = CHUNK_CLOSE;//是否是chunk
    char bodyBuffer[context_size];
    char buf[BUFSIZ];
    zend_string* zend_html_body;
    zval *this_http_table;
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
        http_sentry_container->wait_return = 0;

        //查验是否是之前的chunk传输如果是的话那么就要拼接前面的chunk
        if(http_sentry_container->auto_get_chunk())
        {
            ZVAL_LONG(&unit,1);
            zend_hash_str_add(http_table,"is_chunk",strlen("is_chunk"),&unit);
            //如果说是开启了chunk
            if(http_sentry_container->auto_get_gzip())
            {
                gzip_decompress(context,context_size);
            }else{
                //如果没开启gzip
                this_http_table = http_sentry_container->get_auto_http_table();
                if(this_http_table)
                {
                    this_http_table = zend_hash_str_find(Z_ARRVAL_P(this_http_table),HTTP_BODY,strlen(HTTP_BODY));
                    if(this_http_table)
                    {
                        //获取其中的zend_string
                        if(Z_TYPE(*this_http_table) == IS_STRING)
                        {

                            zend_html_body = Z_STR(*this_http_table);
                            size_t html_body_len = ZSTR_LEN(zend_html_body);
                            size_t extend_len = html_body_len+context_size;
                            //扩容
                            zend_string* new_address = zend_string_extend(zend_html_body,extend_len,0);
                            if(new_address)
                            {
                                memcpy(ZSTR_VAL(new_address)+html_body_len,context,context_size);
                            }
                        }
                    }
                }

                if(context[context_size] == '0')
                {
                    http_sentry_container->wait_return = 0;
                }
            }
        }else{
            //不知道什么数据用tcpdump的格式去打印出来他并且加入到buffer里吧
            for(num=0;num<context_size;num++)
            {
                if(isprint(context[num]))
                {
                    bodyBuffer[num] = context[num];
                }else{
                    if(context[num] == '\t' || context[num] == '\r' || context[num] == '\n')
                    {
                        bodyBuffer[num] = context[num];
                    }else{
                        bodyBuffer[num] = '.';
                    }
                }
            }
            ZVAL_STRING(&unit,bodyBuffer);
            zend_hash_str_add(http_table,"body",strlen("body"),&unit);
        }
        return PCAP_TRUE;
    }


    //first fit 首次适应算法
    parse_state = PARSE_R_NO_HAVE_COMPLETE;//没有完成解析
    for(i = 0;i<context_size;i++)
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
                    context[header_finish_position] = EOS;
                    save_data = (char*)context;
                    ZVAL_STRING(&unit,save_data);
                    context[header_finish_position] = CR;//还原回原本的字符串
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
                    //这里要求出key和value并存到php数组里
                    http_header_key = (char *) context + CURRENT_OFFSET_KEY_BEGIN();
                    context[CURRENT_OFFSET_KEY_END()] = EOS;

                    http_header_value = (char *) context + CURRENT_OFFSET_KEY_END() + 2;//因为是两个有:和''
                    context[i - 1] = EOS;

                    ZVAL_STRING(&unit, http_header_value);
                    zend_hash_str_add(http_table, http_header_key, strlen(http_header_key), &unit);

                    //如果采用chunk块传输
                    if (!strcmp(http_header_key, "Transfer-Encoding") && !strcmp(http_header_value, "chunked")) {
                        http_sentry_container->auto_set_chunk(CHUNK_OPEN);//自动把位置标记为开启chunk
                        is_chunk = CHUNK_OPEN;
                        http_sentry_container->wait_return = 1;
                    }

                    //在这里要确认是否要gzip解压，如果出现要解压的情况则要执行解压
                    if (!strcmp(http_header_key, "Content-Encoding") && !strcmp(http_header_value, "gzip")) {
                        //开始进行gzip解压缩
                        gzip_decompress_flag = HTTP_START_GZIP;
                        http_sentry_container->auto_set_gzip(GZIP_OPEN);//自动把位置标记为开启chunk
                    }

                    //这里要小心意义复原不要破坏原本的字节
                    context[CURRENT_OFFSET_KEY_END()] = ':';
                    context[i - 1] = CR;

                    //重置他们的位置方便下次计算,防止越界
                    if(i + 1 > context_size) {
                        CURRENT_OFFSET_KEY_BEGIN() = i;
                    }else{
                        CURRENT_OFFSET_KEY_BEGIN() = i+1;
                    }

                    if(context[CURRENT_OFFSET_KEY_BEGIN()] == CR)
                    {
                        parse_state = COMPILE_HTTP_VALUE_POSITION;
                    }else{
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
                    if(gzip_decompress_flag == HTTP_START_GZIP) {

                        if (!body_size) {
                            continue;
                        }
                        http_body = context + i;
                        body_size = context_size - i;
                        //如果说是开启了gzip
                        if (http_sentry_container->auto_get_gzip()) {
                            gzip_decompress((void *) http_body, body_size);
                        }
                    }else{
                        //不需要gzip解压的 明文的 但是开启了chunk 传输
                        if(http_sentry_container->auto_get_chunk())
                        {
                            http_body = context+i+1;
                            http_body[context_size] = '\0';

                        }else{
                            //没有开启chunk 传输的
                            //将这个http_body加入到数组里直接打印出去可以了
//                            ZVAL_STRING(&unit,(char*)http_body);
//                            zend_hash_str_add(http_table,HTTP_BODY,strlen(HTTP_BODY),&unit);
                        }
                    }
                }
                break;
            }

            //必须要chunk的状态下
            case HTTP_BEGIN_LENGTH:{
                if(byte == CR && is_chunk == CHUNK_OPEN)
                {
                    chunk_len_ptr = (char*)(context+chunk_body_length_begin);
                    context[i] = '\0';
                    body_size = htoi(chunk_len_ptr);
                    parse_state = CHUNK_FOUND_BODY_BEGIN;//还原方便进入数据区
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

            case CHUNK_BODY_BEGIN:{
                //从这里开始是块的body了
                if(http_sentry_container->auto_get_gzip())
                {//开启了gzip

                }else{
                    //没有开启gzip
                    http_body = context+i;
                    http_body[context_size] = '\0';
                    this_http_table = http_sentry_container->get_auto_http_table();
                    if(this_http_table)
                    {
                        ZVAL_STRING(&unit,(char*)http_body);
                        zend_hash_str_add(Z_ARRVAL_P(this_http_table),HTTP_BODY,strlen(HTTP_BODY),&unit);
                    }
                }
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

//自动进入
PCAP_BOOL _auto_join_http_table()
{
    char http_key[255];
    //生成的ip和post的key
    php_sprintf(http_key,"%s:%d_%s:%d",ZSTR_VAL(http_sentry_container->source_ip),http_sentry_container->source_port,
                ZSTR_VAL(http_sentry_container->dest_ip),http_sentry_container->dest_port);
    zval http_hash;//一个空的数组
    zval* hash_unit;
    array_init(&http_hash);
    HashTable* table = Z_ARRVAL_P(http_sentry_container->http_array_table);
    //存储住这个key
    http_sentry_container->hash_key = zend_string_init(http_key,strlen(http_key),0);
    //如果说发现了一个单元
    if((hash_unit = zend_hash_str_find(table,http_key,strlen(http_key)+1)))
    {
        //释放掉旧的zval
        zval_ptr_dtor(hash_unit);
    }

    //加入创建时间作为标记块，用来处理垃圾回收，防止当块长时间不使用造成的内存泄露
    //获取当前时间
    time_t time_val;
    zval now_time;
    time(&time_val);
    ZVAL_LONG(&now_time,time_val);
    zend_hash_str_add(Z_ARRVAL_P(&http_hash),CTIME,strlen(CTIME),&now_time);
    zend_hash_str_add(table,http_key,strlen(http_key),&http_hash);

    return PCAP_TRUE;
}

//设置是否开启了chunk
PCAP_BOOL _auto_set_chunk(uint8_t chunk_flag)
{
    if(!http_sentry_container->hash_key)
    {
        http_sentry_container->auto_join_http_table();//自动加入
    }

    zval* hash_unit;
    HashTable* table = Z_ARRVAL_P(http_sentry_container->http_array_table);
    found:
    if(!(hash_unit = zend_hash_str_find(table,ZSTR_VAL(http_sentry_container->hash_key),ZSTR_LEN(
            http_sentry_container->hash_key))))
    {
        http_sentry_container->auto_join_http_table();//自动加入
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
    if(!http_sentry_container->hash_key)
    {
        http_sentry_container->auto_join_http_table();//自动加入
    }

    zval* hash_unit;
    HashTable* table = Z_ARRVAL_P(http_sentry_container->http_array_table);
    found:
    if(!(hash_unit = zend_hash_str_find(table,ZSTR_VAL(http_sentry_container->hash_key),ZSTR_LEN(
            http_sentry_container->hash_key))))
    {
        http_sentry_container->auto_join_http_table();//自动加入
        //重新查找
        goto found;
    }

    zval data;
    ZVAL_LONG(&data,gzip_flag);

    zend_hash_str_update(Z_ARRVAL_P(hash_unit),GZIP_FLAG,strlen(GZIP_FLAG),&data);

    return PCAP_TRUE;
}

//获取gzip的状态位
int _auto_get_gzip()
{
    if(!http_sentry_container->hash_key)
    {
        http_sentry_container->auto_join_http_table();//自动加入
    }

    zval* hash_unit;
    HashTable* table = Z_ARRVAL_P(http_sentry_container->http_array_table);
    if(!(hash_unit = zend_hash_str_find(table,ZSTR_VAL(http_sentry_container->hash_key),ZSTR_LEN(
            http_sentry_container->hash_key))))
    {
        return GZIP_CLOSE;
    }

    zval* gzip_zval = zend_hash_str_find(Z_ARRVAL_P(hash_unit),GZIP_FLAG,strlen(GZIP_FLAG));
    if(!gzip_zval)
    {
        return GZIP_CLOSE;
    }

    return Z_LVAL(*gzip_zval);
}

//获取chunk标志位的状态
int _auto_get_chunk()
{
    if(!http_sentry_container->hash_key)
    {
        http_sentry_container->auto_join_http_table();//自动加入
    }

    zval* hash_unit;
    HashTable* table = Z_ARRVAL_P(http_sentry_container->http_array_table);
    if(!(hash_unit = zend_hash_str_find(table,ZSTR_VAL(http_sentry_container->hash_key),ZSTR_LEN(
            http_sentry_container->hash_key))))
    {
        return GZIP_CLOSE;
    }

    zval* gzip_zval = zend_hash_str_find(Z_ARRVAL_P(hash_unit),CHUNK_FLAG,strlen(CHUNK_FLAG));
    if(!gzip_zval)
    {
        return GZIP_CLOSE;
    }

    return Z_LVAL(*gzip_zval);
}

//获取自己的http table
zval* _get_auto_http_table()
{
    if(!http_sentry_container->hash_key)
    {
        http_sentry_container->auto_join_http_table();//自动加入
    }

    zval* hash_unit = NULL;
    HashTable* table = Z_ARRVAL_P(http_sentry_container->http_array_table);
    if(!(hash_unit = zend_hash_str_find(table,ZSTR_VAL(http_sentry_container->hash_key),ZSTR_LEN(
            http_sentry_container->hash_key))))
    {
        return NULL;
    }

    return hash_unit;

}

//自动离开，并且进行内存回收
PCAP_BOOL _auto_leave_http_table()
{

}