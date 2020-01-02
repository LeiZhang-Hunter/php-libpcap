--TEST--
libpcap_test1() Basic test
--SKIPIF--
<?php
if (!extension_loaded('libpcap')) {
	echo 'skip';
}
?>
--FILE--
<?php
$ret = libpcap_test1();

var_dump($ret);
?>
--EXPECT--
The extension libpcap is loaded and working!
NULL
