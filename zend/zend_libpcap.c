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

void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;
//
//    /* offset */
//    printf("%05d   ", offset);
//
//    /* hex */
//    ch = payload;
//    for(i = 0; i < len; i++) {
//        printf("%02x ", *ch);
//        ch++;
//        /* print extra space after 8th byte for visual aid */
//        if (i == 7)
//            printf(" ");
//    }
//    /* print space to handle line less than 8 bytes */
//    if (len < 8)
//        printf(" ");
//
//    /* fill hex gap with spaces if not full line */
//    if (len < 16) {
//        gap = 16 - len;
//        for (i = 0; i < gap; i++) {
//            printf("   ");
//        }
//    }
//    printf("   ");

    /* ascii (if printable) */
    printf("payload:");
    ch = payload;
    register u_char s;
    for(i = 0; i < len; i++) {
        s = *ch++;

        if(s == '\r') {
            if(*ch != '\n')
            {
                php_printf(".");
            }


        }else{
            if(!isprint(s) && s != '\t' && s!= ' ' && s!= '\n')
            {
                php_printf(".");
            }else{
                php_printf("%c",s);
            }
        }
    }

    printf("\r\n\r\n");

    return;
}


void
print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16;                        /* 每行的字节数 | number of bytes per line */
    int line_len;
    int offset = 0;                                        /* 从0开始的偏移计数器 | zero-based offset counter */
    const u_char *ch = payload;
//
//    if (len <= 0)
//        return;
//
//    /* data fits on one line */
//    if (len <= line_width) {
//        print_hex_ascii_line(ch, len, offset);
//        return;
//    }
//
//    /* 数据跨越多行 data spans multiple lines */
//    for ( ;; ) {
//        /* 计算当前行的长度 | compute current line length */
//        line_len = line_width % len_rem;
//
//        /* 显示分割线 | print line */
//        print_hex_ascii_line(ch, line_len, offset);
//
//        /* 计算总剩余 | compute total remaining */
//        len_rem = len_rem - line_len;
//
//        /* 转移到打印的剩余字节的指针
//           shift pointer to remaining bytes to print */
//        ch = ch + line_len;
//
//        /* 添加偏移 | add offset */
//        offset = offset + line_width;
//
//        /* 检查是否有线宽字符或更少
//           check if we have line width chars or less */
//        if (len_rem <= line_width) {
//            /* print last line and get out */
//            print_hex_ascii_line(ch, len_rem, offset);
//            break;
//        }
//    }
    print_hex_ascii_line(ch, len, offset);
    return;
}

//将u_char转换为char
static void convert_u_char_to_char(const u_char *payload, char* buf)
{

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

    zval unit;

    //传入的对象参数
    zval args[1];

    //call_user_function_ex的返回结果
    zval return_result;

    user_param* params = (user_param*)(param);

    zval hook = params->hook;

    zval object = params->object;

    zval eth_header_info;//以太网头

    zval ip_header_info;//ip的结构体

    zval tcp_header_info;//tcp信息



    //802.1Q帧格式
    struct vlan_8021q_header* vptr;

    //这个是ethhdr之后到达ip结构体的偏移量
    int ip_offset = 0;

    //ip的包
    ip_header * ipptr;
    struct ip6_hdr* ipv6ptr;

    eth_ptr = (ether_header*)packet;
    //初始化一个数组
    array_init(&args[0]);

    //初始化以太网头信息
    array_init(&eth_header_info);

    //ip头信息
    array_init(&ip_header_info);

    table = Z_ARRVAL_P(&args[0]);

    /*=====================================以太网头部的添加=================================================*/
    HashTable* ether_header_table = Z_ARRVAL_P(&eth_header_info);
    //格式化mac地址
    php_sprintf(source_mac,MAC_FMT,eth_ptr->h_source[0],eth_ptr->h_source[1],eth_ptr->h_source[2],
            eth_ptr->h_source[3],eth_ptr->h_source[4],eth_ptr->h_source[5]);
    ZVAL_STRING(&unit,source_mac);
    zend_hash_str_add(ether_header_table,MAC_SOURCE,strlen(MAC_SOURCE),&unit);
    //格式化mac
    php_sprintf(dest_mac,MAC_FMT,eth_ptr->h_dest[0],eth_ptr->h_dest[1],eth_ptr->h_dest[2],
                eth_ptr->h_dest[3],eth_ptr->h_dest[4],eth_ptr->h_dest[5]);
    ZVAL_STRING(&unit,dest_mac);
    zend_hash_str_add(ether_header_table,MAC_DEST,strlen(MAC_DEST),&unit);

    //以太网类型,要把网络字节序转化为主机字节序
    ether_type = ntohs(eth_ptr->h_proto);
    ZVAL_LONG(&unit,ether_type);
    zend_hash_str_add(ether_header_table,ETH_PROTO,strlen(ETH_PROTO),&unit);

    //将容器加入到返回的数组中
    zend_hash_str_add(table,ETHER_HEADER,strlen(ETHER_HEADER),&eth_header_info);
    /*=========================================================================================================*/

    if(ether_type == ETH_P_8021Q) {
        vptr = (struct vlan_8021q_header*) (packet + sizeof(ether_header));
        ether_type = vptr->ether_type;
        ip_offset += sizeof(struct vlan_8021q_header);
    }else{
        ip_offset = ETHER_HEADER_LEN;
    }


    HashTable* ip_header_table = Z_ARRVAL_P(&ip_header_info);

    //ipv4
    if(ether_type == ETH_P_IP)
    {
        /*======================================IP结构体部分解析======================================================*/
        //ipv4
        char ipv4_str[INET_ADDRSTRLEN];

        ipptr = (struct ip*) (packet+ip_offset);

        //ipv4的长是前4个字节
        unsigned int ipv4_header_len = ipptr->ip_hl*4;
        if(ipv4_header_len < 20)
        {
            return;
        }

        ZVAL_LONG(&unit,ipv4_header_len);
        zend_hash_str_add(ip_header_table,IP_HEADER_LEN,strlen(IP_HEADER_LEN),&unit);

        //ip结构体版本号
        ZVAL_LONG(&unit,ntohl(ipptr->ip_v));
        zend_hash_str_add(ip_header_table,IP_VERSION,strlen(IP_VERSION),&unit);

        //ttl
        ZVAL_LONG(&unit,(ipptr->ip_ttl));
        zend_hash_str_add(ip_header_table,_TTL,strlen(_TTL),&unit);

        //ip tos
        ZVAL_LONG(&unit,(ipptr->ip_tos));
        zend_hash_str_add(ip_header_table,_IP_TOS,strlen(_IP_TOS),&unit);

        //ip_len
        ZVAL_LONG(&unit,ntohs(ipptr->ip_len));
        zend_hash_str_add(ip_header_table,_IP_LEN,strlen(_IP_LEN),&unit);

        //ip id
        ZVAL_LONG(&unit,ntohs(ipptr->ip_id));
        zend_hash_str_add(ip_header_table,_IP_ID,strlen(_IP_ID),&unit);

        //IP SUM
        ZVAL_LONG(&unit,ntohs(ipptr->ip_sum));
        zend_hash_str_add(ip_header_table,_IP_SUM,strlen(_IP_SUM),&unit);

        //ip地址往来
        ZVAL_STRING(&unit,ipv4_str);
        inet_ntop(AF_INET,&ipptr->ip_src,ipv4_str,sizeof(ipv4_str));
        zend_hash_str_add(ip_header_table,IP_SRC,strlen(IP_SRC),&unit);
        inet_ntop(AF_INET,&ipptr->ip_dst,ipv4_str,sizeof(ipv4_str));
        ZVAL_STRING(&unit,ipv4_str);
        zend_hash_str_add(ip_header_table,IP_DST,strlen(IP_DST),&unit);

        switch (ipptr->ip_p)
        {
            //ip
            case IPPROTO_TCP: {
                //记录tcp信息加入到zval变量容器
                array_init(&tcp_header_info);
                HashTable* tcp_header_table = Z_ARRVAL_P(&tcp_header_info);

                //端口往来
                tcp_header* _tcphdr = (tcp_header*)(packet+ETHER_HEADER_LEN+ sizeof(ip_header));

                //主机端口,目的地的
                ZVAL_LONG(&unit,ntohs(_tcphdr->dest));
                zend_hash_str_add(tcp_header_table,_TCP_SPORT,strlen(_TCP_SPORT),&unit);

                //主机端口来源地的
                ZVAL_LONG(&unit,ntohs(_tcphdr->source));
                zend_hash_str_add(tcp_header_table,_TCP_DPORT,strlen(_TCP_DPORT),&unit);

                /*--------------------------------------*/
                //         source     |      dest       |
                /*--------------------------------------*/
                //             ack_seq                  |
                //--------------------------------------
                //  doff|res1|        |   window        |
                //         check      |    urg_ptr      |
                //              options                 |
                //---------------------------------------
                //序列码
                ZVAL_LONG(&unit,ntohl(_tcphdr->seq));
                zend_hash_str_add(tcp_header_table,_TCP_TH_SEQ,strlen(_TCP_TH_SEQ),&unit);

                //确认码
                ZVAL_LONG(&unit,ntohs(_tcphdr->ack));
                zend_hash_str_add(tcp_header_table,_TCP_TH_ACK,strlen(_TCP_TH_ACK),&unit);

                //窗口
                ZVAL_LONG(&unit,ntohs(_tcphdr->window));
                zend_hash_str_add(tcp_header_table,_TCP_WINDOW,strlen(_TCP_WINDOW),&unit);

                //检测
                ZVAL_LONG(&unit,ntohs(_tcphdr->check));
                zend_hash_str_add(tcp_header_table,_TCP_CHECK,strlen(_TCP_CHECK),&unit);

                //urg_ptr
                ZVAL_LONG(&unit,ntohs(_tcphdr->urg_ptr));
                zend_hash_str_add(tcp_header_table,_TCP_URG_PTR,strlen(_TCP_URG_PTR),&unit);

                //计算出tcp长度
                int tcp_len = sizeof(ip_header);

                const u_char *payload = (packet+ETHER_HEADER_LEN+sizeof(ip_header)+sizeof(tcp_header));
                size_t payload_size = ntohs(ipptr->ip_len)-(sizeof(ip_header)+tcp_len);
                ZVAL_LONG(&unit,payload_size);
                zend_hash_str_add(tcp_header_table,SEGMENT_SIZE,strlen(SEGMENT_SIZE),&unit);


                if(payload_size <= 0)
                {
                    break;
                }
                size_t i = 0;

                char buf[65535];
                strcpy(buf,(char*)payload);
                for(i=0;i<payload_size;i++)
                {
                    if(isprint(payload[i])) {
                        buf[i] = payload[i];
                    }else{
                        //检查是否是一些特殊符号
                        if(payload[i] == '\t' || payload[i] == '\n' || payload[i]=='\r')
                        {
                            buf[i] = payload[i];
                        }else{
                            buf[i] = '.';
                        }
                    }
                }
                buf[payload_size] = '\0';

                ZVAL_STRING(&unit,buf);
                zend_hash_str_add(tcp_header_table,TCP_BODY,strlen(TCP_BODY),&unit);
                //打印payload,对payload数据进行进一步处理
                zend_hash_str_add(table,TCP_HEADER,strlen(TCP_HEADER),&tcp_header_info);
            }
                break;
            //udp
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
    }else if(ether_type == ETH_P_IPV6)
    {
        return;
        ipv6ptr = (struct ip6_hdr*) (packet+ip_offset);
        ZVAL_STRING(&unit,"ipv6");
        zend_hash_str_add(table,MAC_TYPE,strlen(MAC_TYPE),&unit);
    }else{
        return;
    }

    zend_hash_str_add(table,_IP_HEADER,strlen(_IP_HEADER),&ip_header_info);
    /*======================================--------------======================================================*/
    //运行php闭包
    call_user_function_ex(EG(function_table), NULL, &hook,
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

    struct bpf_program fp;
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
    bpf_u_int32 net;
    user_param param = {
            .hook = *zend_read_property(pcap_ce,this_object,PCAP_RECV,strlen(PCAP_RECV),0,&zv),
            .object = *getThis()
    };
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
    res = pcap_loop(pcap_handle,pcap_factory.max_packet_num,zend_pcaket_handle,(u_char*)&param);
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