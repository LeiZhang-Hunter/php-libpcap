/* libpcap extension for PHP */

#ifndef PHP_LIBPCAP_H
# define PHP_LIBPCAP_H

extern zend_module_entry libpcap_module_entry;
# define phpext_libpcap_ptr &libpcap_module_entry

# define PHP_LIBPCAP_VERSION "0.1.0"

# if defined(ZTS) && defined(COMPILE_DL_LIBPCAP)
ZEND_TSRMLS_CACHE_EXTERN()
# endif

#endif	/* PHP_LIBPCAP_H */

