//
// Created by zhanglei on 2020/1/2.
//

#include "common.h"
zend_class_entry* http_sentry_ce;
zval* this_object;
const zend_function_entry pcap_function_list[] = {
        PHP_ME(HttpSentry, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
        PHP_ME(HttpSentry, findAllDevs, NULL, ZEND_ACC_PUBLIC)
        PHP_ME(HttpSentry, setConfig, pcap_config, ZEND_ACC_PUBLIC)
        PHP_ME(HttpSentry, onReceive, pcap_recv_hook, ZEND_ACC_PUBLIC)
        PHP_ME(HttpSentry, monitor, NULL, ZEND_ACC_PUBLIC)
        PHP_ME(HttpSentry, __destruct, NULL, ZEND_ACC_PUBLIC)
        PHP_FE_END
};

static void setErrBuf(zval* object)
{
    zend_update_property_string(http_sentry_ce,object,ERROR_BUF,sizeof(ERROR_BUF),NG(pcap_lib)->err_buf);
}

static void php_sentry_client_globals_ctor(zend_sentry_client_globals *sentry_client_globals TSRMLS_DC)
{
    // 在线程运行起来后始化一个新的 zend_sample4_globals 结构体
    init_node_sentry(sentry_client_globals);
}

//构造函数
PHP_METHOD(HttpSentry,__construct)
{
    php_sentry_client_globals_ctor(&sentry_client_globals TSRMLS_CC);
    this_object = getThis();
}

//设置配置文件
PHP_METHOD(HttpSentry,setConfig)
{
    zval *config = NULL;//this opetion begin single model
    ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_ARRAY(config)
    ZEND_PARSE_PARAMETERS_END();
    zend_update_property(http_sentry_ce,getThis(),PCAP_CONFIG,strlen(PCAP_CONFIG),config);
}

//当收到数据的时候进行触发
PHP_METHOD(HttpSentry,onReceive)
{
    zval *hook = NULL;
    ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_ZVAL(hook)
    ZEND_PARSE_PARAMETERS_END();

    //如果说是回调函数才会加载到配置当中，不是的话抛出error
    if(EXPECTED(zend_is_callable(hook,0,NULL)))
    {
        zend_update_property(http_sentry_ce,getThis(),PCAP_RECV,strlen(PCAP_RECV),hook);
    }else{
        zend_throw_error(NULL,"%s\n","Pcap->onReceive must be callable");
    }
}

//循环处理函数
static void zend_pcaket_handle(u_char *param, const struct pcap_pkthdr *header,const u_char *packet)
{
    //传入的对象参数
    //call_user_function_ex的返回结果
    //802.1Q帧格式
    struct vlan_8021q_header* vptr;
    //这个是ethhdr之后到达ip结构体的偏移量
    int ip_offset = 0;
    NG(dispatch) = NO_DISPATCH;
    /*=====================================以太网头部的添加=================================================*/
    NG(eth_packet_handle)->parse(packet);
    /*=========================================================================================================*/
    //计算偏移量
    if(NG(eth_packet_handle)->ether_type == ETH_P_8021Q) {
        ip_offset += sizeof(struct vlan_8021q_header);
    }else{
        ip_offset = ETHER_HEADER_LEN;
    }
    //ipv4
    if(NG(eth_packet_handle)->ether_type == ETH_P_IP)
    {
        /*======================================IP结构体部分解析======================================================*/
        packet+=ip_offset;
        //ipv4
        NG(ip_packet_handle)->parse(packet);

        switch (NG(ip_packet_handle)->protocol)
        {
            //ip
            case IPPROTO_TCP: {
                packet+=NG(ip_packet_handle)->header_len;
                //解析tcp的协议
                NG(tcp_packet_handle)->parse(packet);

                if(NG(tcp_packet_handle)->header_len > NG(ip_packet_handle)->total_len)
                {
                    return;
                }

                //如果没有载荷就不要继续向下解析了
                if(NG(tcp_packet_handle)->payload_size <= 0)
                    return;

                //开始解析http包
                PCAP_BOOL result = NG(http_sentry_handle)->parse(
                        NG(tcp_packet_handle)->payload,
                        NG(tcp_packet_handle)->payload_size);

                if(result == PCAP_TRUE)
                    NG(dispatch) = DO_DISPATCH;
                else
                    NG(dispatch) = NO_DISPATCH;

                //finish
                NG(finish)();

            }
                break;
            case IPPROTO_UDP:
                return;
            case IPPROTO_ICMP://useless
                return;
            case IPPROTO_IP: //useless
                printf("   Protocol: IP\n");
                return;
            default:
                return;
        }
    }else{
        return;
    }
}

//执行捕捉循环
PHP_METHOD(HttpSentry,monitor)
{
    zval* config;

    zval zv;

    PCAP_BOOL res;

    config = zend_read_property(http_sentry_ce,getThis(),PCAP_CONFIG,strlen(PCAP_CONFIG),0,&zv);

    pcap_t* pcap_handle;

    char errbuf[PCAP_ERRBUF_SIZE];

    struct bpf_program fp;
    bzero(errbuf,sizeof(errbuf));
    bzero(NG(pcap_lib)->err_buf,sizeof(NG(pcap_lib)->err_buf));
    //检查配置文件
    res = NG(pcap_lib)->pcap_config_check(config);
    if(EXPECTED(res == PCAP_FALSE))
    {
        RETURN_FALSE;
    }
    pcap_handle = pcap_create(ZSTR_VAL(NG(pcap_lib)->dev_name),errbuf);
    if(EXPECTED(!pcap_handle))
    {
        RETURN_FALSE
    }
    res = pcap_activate(pcap_handle);
    if(EXPECTED(res != 0))
    {
        zend_throw_error(NULL,"%s\n",pcap_geterr(pcap_handle));
        RETURN_FALSE
    }
    bpf_u_int32 net;
    //初始化用户hook
    NG(task)->hook = *zend_read_property(http_sentry_ce,this_object,PCAP_RECV,strlen(PCAP_RECV),0,&zv);
    NG(task)->object = *getThis();
    net=0xffffff;
    zval* rule = zend_hash_str_find(Z_ARRVAL_P(config),PCAP_RULE,strlen(PCAP_RULE));
    if (pcap_compile(pcap_handle, &fp, Z_STRVAL(*rule), 0, net) == -1) {
        zend_throw_error(NULL,"%s\n",pcap_geterr(pcap_handle));
        RETURN_FALSE
    }
    if(pcap_setfilter(pcap_handle,&fp) == -1)
    {
        zend_throw_error(NULL,"%s\n",pcap_geterr(pcap_handle));
        RETURN_FALSE
    }
    res = pcap_loop(pcap_handle,(int)NG(pcap_lib)->max_packet_num,zend_pcaket_handle,NULL);
    if(EXPECTED(res != 0))
    {
        zend_throw_error(NULL,"222:%s\n",pcap_geterr(pcap_handle));
        RETURN_FALSE
    }
}

//停止循环
PHP_METHOD(HttpSentry,stop)
{
}

//发现所有设备
PHP_METHOD(HttpSentry,findAllDevs)
{
    PCAP_BOOL res;

    pcap_if_t* all_devs_handle = NG(pcap_lib)->find_all_devs();
    if(EXPECTED(all_devs_handle))
    {
        zval array;

        array_init(&array);
        res = NG(pcap_lib)->pcap_if_t_to_zend_hash(all_devs_handle,Z_ARRVAL_P(&array));
        NG(pcap_lib)->free_all_devs(all_devs_handle);
        if(EXPECTED(res == PCAP_TRUE))
        {
            RETURN_ZVAL(&array,1,0)
        }else{
            RETURN_FALSE
        }
    }else{
        setErrBuf(getThis());
        RETURN_FALSE
    }
}

PHP_METHOD(HttpSentry,__destruct)
{
    NG(dtor);
}

//将entry加载入模块
void class_Pcap_load()
{
   zend_class_entry entry;

   //初始化
    INIT_CLASS_ENTRY(entry,"HttpSentry",pcap_function_list);
    //注册类
    http_sentry_ce = zend_register_internal_class(&entry);
    zend_declare_property_null(http_sentry_ce,ERROR_BUF,strlen(ERROR_BUF),ZEND_ACC_PRIVATE);//错误信息
    zend_declare_property_null(http_sentry_ce,PCAP_CONFIG,strlen(PCAP_CONFIG),ZEND_ACC_PUBLIC);//配置
    zend_declare_property_null(http_sentry_ce,PCAP_DEV,strlen(PCAP_DEV),ZEND_ACC_PUBLIC);//配置
}