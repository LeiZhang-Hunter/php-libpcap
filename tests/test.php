<?php
$pcap = new HttpSentry();
$list = $pcap->findAllDevs();
$pcap->setConfig([
    "dev"=>"eno1",
    "rule"=>"port 80",
    "max_packet_num"=>100
]);
$pcap->onReceive(function($data) use($pcap){
});
$r = $pcap->monitor();
var_dump($r);
