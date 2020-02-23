#如何使用httpSentry

####注意

扩展开发时间较短 没有做内存安全测试 和压力测试，对http解包的完整性还没有完全开发完成

本次只是解析了chunked 编码 以及 http请求 其他的并未做解析

####如何安装这个扩展?

######安装(注意本人是使用php7.3作为php版本,开发环境为ubuntu)

```
    phpize && ./configure --with-php-config 地址 && make && make install
```

最后在php.ini中加入 libpcap.so

####如何使用这个扩展?

```
    <?php
    ini_set("display_errors",true);
    $pcap = new HttpSentry();
    $list = $pcap->findAllDevs();
    $pcap->setConfig([
        "dev"=>"wlp2s0",
        "rule"=>"port 80",
        "max_packet_num"=>10000
    ]);
    $pcap->onReceive(function($data) use($pcap){
        if(isset($data["http"]["html"])){
            var_dump($data["http"]["html"]);
        }
    });
    $r = $pcap->monitor();
    //var_dump($r);

```