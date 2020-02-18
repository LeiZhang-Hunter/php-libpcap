cmake_minimum_required(VERSION 3.7)

project(libpcap)

set(CMAKE_CXX_STANDARD 11)


#定义php源码路径，这里根据自己的真实路径来更改
set(PHP_SOURCE /home/zhanglei/ourc/php-7.3.11)
# Add -O0 to remove optimizations when using gcc
IF(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

#引入php需要的扩展源码，这里也是根据自己需要的来更改
include_directories(${PHP_SOURCE}/main/)
include_directories(${PHP_SOURCE}/Zend/)
include_directories(${PHP_SOURCE}/sapi/)
include_directories(${PHP_SOURCE}/pear/)
include_directories(${PHP_SOURCE}/sapi/)
include_directories(${PHP_SOURCE}/TSRM/)
include_directories(${PHP_SOURCE}/)
include_directories(./zend)
include_directories(./common)
include_directories(./pcap_tool)

set(SOURCE_FILES
        libpcap.c
        zend/zend_libpcap.c
        zend/zend_pcap.c
        pcap_tool/pcap_lib.c
        common/ether.h common/ip_struct.h common/tcp_struct.h pcap_tool/http_parse.h pcap_tool/http_parse.c pcap_tool/gzip_tool.h pcap_tool/gzip_tool.c)

add_executable(libpcap ${SOURCE_FILES})
#CFLAGS='-g -O0'
add_custom_target(makefile COMMAND  make clean && phpize && ./configure CFLAGS='-g -O0'  && make && make install WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
