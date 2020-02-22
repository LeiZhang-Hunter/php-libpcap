/* libpcap extension for PHP */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "ext/standard/info.h"
#include "php_libpcap.h"
#include "common.h"

/* For compatibility with older PHP versions */
#ifndef ZEND_PARSE_PARAMETERS_NONE
#define ZEND_PARSE_PARAMETERS_NONE() \
	ZEND_PARSE_PARAMETERS_START(0, 0) \
	ZEND_PARSE_PARAMETERS_END()
#endif

/* {{{ void libpcap_test1()
 */
PHP_FUNCTION(libpcap_test1)
{
	ZEND_PARSE_PARAMETERS_NONE();

	php_printf("The extension %s is loaded and working!\r\n", "libpcap");
}
/* }}} */

/* {{{ string libpcap_test2( [ string $var ] )
 */
PHP_FUNCTION(libpcap_test2)
{
	char *var = "World";
	size_t var_len = sizeof("World") - 1;
	zend_string *retval;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		Z_PARAM_STRING(var, var_len)
	ZEND_PARSE_PARAMETERS_END();

	retval = strpprintf(0, "Hello %s", var);

	RETURN_STR(retval);
}
/* }}}*/

/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(libpcap)
{
#if defined(ZTS) && defined(COMPILE_DL_LIBPCAP)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif

	return SUCCESS;
}




//扩展模块初始化的函数
PHP_MINIT_FUNCTION(libpcap)
{
    //装载我的类
	CLASS_LOAD(Pcap);
}

/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(libpcap)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "libpcap support", "enabled");
	php_info_print_table_end();
}
/* }}} */

/* {{{ arginfo
 */
ZEND_BEGIN_ARG_INFO(arginfo_libpcap_test1, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_libpcap_test2, 0)
	ZEND_ARG_INFO(0, str)
ZEND_END_ARG_INFO()
/* }}} */

/* {{{ libpcap_functions[]
 */
static const zend_function_entry libpcap_functions[] = {
	PHP_FE(libpcap_test1,		arginfo_libpcap_test1)
	PHP_FE(libpcap_test2,		arginfo_libpcap_test2)
	PHP_FE_END
};
/* }}} */

/* {{{ libpcap_module_entry
 */
zend_module_entry libpcap_module_entry = {
	STANDARD_MODULE_HEADER,
	"libpcap",					/* Extension name */
	libpcap_functions,			/* zend_function_entry */
    PHP_MINIT(libpcap),							/* PHP_MINIT - Module initialization */
	NULL,							/* PHP_MSHUTDOWN - Module shutdown */
	PHP_RINIT(libpcap),			/* PHP_RINIT - Request initialization */
	NULL,							/* PHP_RSHUTDOWN - Request shutdown */
	PHP_MINFO(libpcap),			/* PHP_MINFO - Module info */
	PHP_LIBPCAP_VERSION,		/* Version */
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_LIBPCAP
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(libpcap)
#endif

