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
