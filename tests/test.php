<?php
$pcap = new HttpSentry();
$list = $pcap->findAllDevs();
$pcap->setConfig([
    "dev"=>"eno1",
    "rule"=>"port 80",
    "max_packet_num"=>10000
]);
$pcap->onReceive(function($data) use($pcap){
    var_dump($data);
});
$r = $pcap->monitor();
