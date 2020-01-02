--TEST--
Check if libpcap is loaded
--SKIPIF--
<?php
if (!extension_loaded('libpcap')) {
	echo 'skip';
}
?>
--FILE--
<?php
echo 'The extension "libpcap" is available';
?>
--EXPECT--
The extension "libpcap" is available
