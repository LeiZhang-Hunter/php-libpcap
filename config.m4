dnl config.m4 for extension libpcap

dnl Comments in this file start with the string 'dnl'.
dnl Remove where necessary.

dnl If your extension references something external, use with:

dnl PHP_ARG_WITH(libpcap, for libpcap support,
dnl Make sure that the comment is aligned:
dnl [  --with-libpcap             Include libpcap support])

dnl Otherwise use enable:

PHP_ARG_ENABLE(libpcap, whether to enable libpcap support,
dnl Make sure that the comment is aligned:
[  --enable-libpcap          Enable libpcap support], no)

if test "$PHP_LIBPCAP" != "no"; then
  dnl Write more examples of tests here...

  dnl # get library FOO build options from pkg-config output
  dnl AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
  dnl AC_MSG_CHECKING(for libfoo)
  dnl if test -x "$PKG_CONFIG" && $PKG_CONFIG --exists foo; then
  dnl   if $PKG_CONFIG foo --atleast-version 1.2.3; then
  dnl     LIBFOO_CFLAGS=\`$PKG_CONFIG foo --cflags\`
  dnl     LIBFOO_LIBDIR=\`$PKG_CONFIG foo --libs\`
  dnl     LIBFOO_VERSON=\`$PKG_CONFIG foo --modversion\`
  dnl     AC_MSG_RESULT(from pkgconfig: version $LIBFOO_VERSON)
  dnl   else
  dnl     AC_MSG_ERROR(system libfoo is too old: version 1.2.3 required)
  dnl   fi
  dnl else
  dnl   AC_MSG_ERROR(pkg-config not found)
  dnl fi
  dnl PHP_EVAL_LIBLINE($LIBFOO_LIBDIR, LIBPCAP_SHARED_LIBADD)
  dnl PHP_EVAL_INCLINE($LIBFOO_CFLAGS)

  dnl # --with-libpcap -> check with-path
  dnl SEARCH_PATH="/usr/local /usr"     # you might want to change this
  dnl SEARCH_FOR="/include/libpcap.h"  # you most likely want to change this
  dnl if test -r $PHP_LIBPCAP/$SEARCH_FOR; then # path given as parameter
  dnl   LIBPCAP_DIR=$PHP_LIBPCAP
  dnl else # search default path list
  dnl   AC_MSG_CHECKING([for libpcap files in default path])
  dnl   for i in $SEARCH_PATH ; do
  dnl     if test -r $i/$SEARCH_FOR; then
  dnl       LIBPCAP_DIR=$i
  dnl       AC_MSG_RESULT(found in $i)
  dnl     fi
  dnl   done
  dnl fi
  dnl
  dnl if test -z "$LIBPCAP_DIR"; then
  dnl   AC_MSG_RESULT([not found])
  dnl   AC_MSG_ERROR([Please reinstall the libpcap distribution])
  dnl fi

  dnl # --with-libpcap -> add include path
  dnl PHP_ADD_INCLUDE($LIBPCAP_DIR/include)

  dnl # --with-libpcap -> check for lib and symbol presence
  dnl LIBNAME=LIBPCAP # you may want to change this
  dnl LIBSYMBOL=LIBPCAP # you most likely want to change this

  dnl PHP_CHECK_LIBRARY($LIBNAME,$LIBSYMBOL,
  dnl [
  dnl   PHP_ADD_LIBRARY_WITH_PATH($LIBNAME, $LIBPCAP_DIR/$PHP_LIBDIR, LIBPCAP_SHARED_LIBADD)
  dnl   AC_DEFINE(HAVE_LIBPCAPLIB,1,[ ])
  dnl ],[
  dnl   AC_MSG_ERROR([wrong libpcap lib version or lib not found])
  dnl ],[
  dnl   -L$LIBPCAP_DIR/$PHP_LIBDIR -lm
  dnl ])
  dnl
  dnl PHP_SUBST(LIBPCAP_SHARED_LIBADD)

  dnl # In case of no dependencies
  AC_DEFINE(HAVE_LIBPCAP, 1, [ Have libpcap support ])
  PHP_ADD_INCLUDE(./common)
  PHP_ADD_INCLUDE(./zend)
  PHP_ADD_INCLUDE(./pcap_tool)
  PHP_ADD_LIBRARY(pcap,1,LIBPCAP_SHARED_LIBADD)
  PHP_SUBST(LIBPCAP_SHARED_LIBADD)
  PHP_NEW_EXTENSION(libpcap, libpcap.c \
  zend/zend_libpcap.c \
  zend/zend_pcap.c \
  pcap_tool/pcap_lib.c \
  pcap_tool/http_parse.c, $ext_shared)
fi
