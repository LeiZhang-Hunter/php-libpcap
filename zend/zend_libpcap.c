//
// Created by zhanglei on 2020/1/2.
//

#include "common.h"
extern pcap_module pcap_factory;
zend_class_entry* pcap_ce;
zval* this_object;
const zend_function_entry pcap_function_list[] = {
        PHP_ME(Pcap, __construct, NULL, ZEND_ACC_PUBLIC | ZEND_ACC_CTOR)
        PHP_ME(Pcap, findAllDevs, NULL, ZEND_ACC_PUBLIC)
        PHP_ME(Pcap, setConfig, pcap_config, ZEND_ACC_PUBLIC)
        PHP_ME(Pcap, onReceive, pcap_recv_hook, ZEND_ACC_PUBLIC)
        PHP_ME(Pcap, loop, NULL, ZEND_ACC_PUBLIC)
        PHP_FE_END
};

static void setErrBuf(zval* object)
{
    zend_update_property_string(pcap_ce,object,ERROR_BUF,sizeof(ERROR_BUF),pcap_factory.err_buf);
}

//构造函数
PHP_METHOD(Pcap,__construct)
{
    this_object = getThis();
}

//设置配置文件
PHP_METHOD(Pcap,setConfig)
{
    zval *config = NULL;//this opetion begin single model
    ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_ARRAY(config)
    ZEND_PARSE_PARAMETERS_END();
    zend_update_property(pcap_ce,getThis(),PCAP_CONFIG,strlen(PCAP_CONFIG),config);
}

//当收到数据的时候进行触发
PHP_METHOD(Pcap,onReceive)
{
    zval *hook;
    ZEND_PARSE_PARAMETERS_START(1, 1)
            Z_PARAM_ZVAL(hook)
    ZEND_PARSE_PARAMETERS_END();

    //如果说是回调函数才会加载到配置当中，不是的话抛出error
    if(EXPECTED(zend_is_callable(hook,0,NULL)))
    {
        zend_update_property(pcap_ce,getThis(),PCAP_RECV,strlen(PCAP_RECV),hook);
    }else{
        zend_throw_error(NULL,"%s\n","Pcap->onReceive must be callable");
    }
}

//循环处理函数
static void zend_pcaket_handle(u_char *param, const struct pcap_pkthdr *header,const u_char *packet)
{
    //以太网类型
    int ether_type;

    //以太网头
    ether_header* eth_ptr;

    //来源mac地址
    char source_mac[MAX_LENGTH_OF_LONG];

    //目标mac地址
    char dest_mac[MAX_LENGTH_OF_LONG];

    HashTable* table;

    zval source_mac_zval;

    zval dest_mac_zval;

    //call_user_function_ex一个参数不知道是做什么用的
    zval rv;

    //传入的对象参数
    zval args[1];

    //call_user_function_ex的返回结果
    zval return_result;

    //802.1Q帧格式
    struct vlan_8021q_header* vptr;

    //这个是ethhdr之后到达ip结构体的偏移量
    int ip_offset;

    //ip的包
    struct ip* ipptr;

    eth_ptr = (ether_header*)packet;
    //初始化一个数组
    array_init(&args[0]);
    table = Z_ARRVAL_P(&args[0]);
    //格式化mac地址
    php_sprintf(source_mac,MAC_FMT,eth_ptr->h_source[0],eth_ptr->h_source[1],eth_ptr->h_source[2],
            eth_ptr->h_source[3],eth_ptr->h_source[4],eth_ptr->h_source[5]);
    ZVAL_STRING(&source_mac_zval,source_mac);
    zend_hash_str_add(table,MAC_SOURCE,strlen(MAC_SOURCE),&source_mac_zval);
    //格式化mac
    php_sprintf(dest_mac,MAC_FMT,eth_ptr->h_source[0],eth_ptr->h_source[1],eth_ptr->h_source[2],
                eth_ptr->h_source[3],eth_ptr->h_source[4],eth_ptr->h_source[5]);
    ZVAL_STRING(&dest_mac_zval,dest_mac);
    zend_hash_str_add(table,MAC_DEST,strlen(MAC_DEST),&dest_mac_zval);
    //以太网类型
    ether_type = eth_ptr->h_proto;

    if(ether_type == ETH_P_8021Q) {
        vptr = (struct vlan_8021q_header*) (packet + sizeof(ether_header));
        ether_type = vptr->ether_type;
        ip_offset += sizeof(struct vlan_8021q_header);
    }
    //是ipv4或者ipv6的
    if(ether_type == ETH_P_IP || ether_type == ETH_P_IPV6) {
        ipptr = (struct ip*) (packet+ip_offset);
    }
    zval* hook = zend_read_property(pcap_ce,this_object,PCAP_RECV,strlen(PCAP_RECV),0,&rv);
    call_user_function_ex(EG(function_table), NULL, hook,
                          &return_result, 1, args, 0, NULL);
}

//执行捕捉循环
PHP_METHOD(Pcap,loop)
{
    zval* config;

    zval zv;

    PCAP_BOOL res;

    config = zend_read_property(pcap_ce,getThis(),PCAP_CONFIG,strlen(PCAP_CONFIG),0,&zv);

    pcap_t* pcap_handle;

    char errbuf[PCAP_ERRBUF_SIZE];


    bzero(errbuf,sizeof(errbuf));
    bzero(pcap_factory.err_buf,sizeof(pcap_factory.err_buf));
    //检查配置文件
    res = zend_pcap_tree.pcap_config_check(config);
    if(EXPECTED(res == PCAP_FALSE))
    {
        RETURN_FALSE;
    }
    pcap_handle = pcap_create(ZSTR_VAL(pcap_factory.dev_name),errbuf);
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
    res = pcap_loop(pcap_handle,pcap_factory.max_packet_num,zend_pcaket_handle,NULL);
    if(EXPECTED(res != 0))
    {
        zend_throw_error(NULL,"%s\n",pcap_geterr(pcap_handle));
        RETURN_FALSE
    }
}

//停止循环
PHP_METHOD(Pcap,stop)
{
}

//发现所有设备
PHP_METHOD(Pcap,findAllDevs)
{
    PCAP_BOOL res;

    pcap_if_t* all_devs_handle = pcap_factory.find_all_devs();
    if(EXPECTED(all_devs_handle))
    {
        zval array;

        array_init(&array);
        res = zend_pcap_tree.pcap_if_t_to_zend_hash(all_devs_handle,Z_ARRVAL_P(&array));
        pcap_factory.free_all_devs(all_devs_handle);
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

//将entry加载入模块
void class_Pcap_load()
{
   zend_class_entry entry;

   //初始化
    INIT_CLASS_ENTRY(entry,"Pcap",pcap_function_list);
    //注册类
    pcap_ce = zend_register_internal_class(&entry);
    zend_declare_property_null(pcap_ce,ERROR_BUF,strlen(ERROR_BUF),ZEND_ACC_PRIVATE);//错误信息
    zend_declare_property_null(pcap_ce,PCAP_CONFIG,strlen(PCAP_CONFIG),ZEND_ACC_PUBLIC);//配置
    zend_declare_property_null(pcap_ce,PCAP_DEV,strlen(PCAP_DEV),ZEND_ACC_PUBLIC);//配置
}