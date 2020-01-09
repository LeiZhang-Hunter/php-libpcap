<?php
$pcap = new Pcap();
$list = $pcap->findAllDevs();
$pcap->setConfig([
    "dev"=>"eno1",
    "rule"=>"port 80",
    "max_packet_num"=>5000
]);
$pcap->onReceive(function($data) use($pcap){
	var_dump($data);
});
$r = $pcap->loop();
var_dump($r);
