<?php
$pcap = new Pcap();
$list = $pcap->findAllDevs();
$pcap->setConfig([
    "dev"=>"eno1",
    "max_packet_num"=>5000
]);
$pcap->onReceive(function($data) use($pcap){
	var_dump($data);die;
});
$r = $pcap->loop();
var_dump($r);
