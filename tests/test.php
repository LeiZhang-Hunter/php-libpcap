<?php
$pcap = new Pcap();
$list = $pcap->findAllDevs();
$pcap->setConfig([
    "dev"=>"eno1",
    "rule"=>"port 80",
    "max_packet_num"=>100
]);
$pcap->onReceive(function($data) use($pcap){
		var_dump($data["tcp_header"]);
});
$r = $pcap->loop();
var_dump($r);
