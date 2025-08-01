##########################################################################
#
# Copyright 2016 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# SPDX-License-Identifier: Apache-2.0
##########################################################################
#                                              -*- Autoconf -*-
# Process this file with autoconf to produce configure script.
#

AC_PREREQ([2.65])
AC_INIT([CcspAdvSecurity], [1.0], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE([foreign])
LT_INIT

AC_ARG_ENABLE([unitTestDockerSupport],
             AS_HELP_STRING([--enable-unitTestDockerSupport],[enable Docker support for unit testing (default is no)]),
             [
              case "${enableval}" in
                yes)
                  UNIT_TEST_DOCKER_SUPPORT=true
                  m4_if(m4_sysval,[0],[AC_CONFIG_FILES([source/test/Makefile source/test/CcspAdvSecurityDmlTest/Makefile])])
                  ;;
                no)
                  UNIT_TEST_DOCKER_SUPPORT=false
                  AC_MSG_WARN([Docker support is disabled])
                  ;;
                *)
                  AC_MSG_ERROR([bad value ${enableval} for --enable-unitTestDockerSupport])
                  ;;
              esac
             ],
             [AC_MSG_WARN([Docker support is disabled])])

AM_CONDITIONAL([UNIT_TEST_DOCKER_SUPPORT], [test x$UNIT_TEST_DOCKER_SUPPORT = xtrue])

AC_PREFIX_DEFAULT(`pwd`)
AC_ENABLE_SHARED
AC_DISABLE_STATIC

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_CC_C_O
AM_PROG_LIBTOOL(libtool)

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC

AC_ARG_WITH([ccsp-arch],
[AC_HELP_STRING([--with-ccsp-arch={arm,atom,pc,mips}],
                [specify the ccsp board CPU platform])],
[case x"$withval" in
   xarm)
     CCSP_ARCH=arm
     ;;
   xatom)
     CCSP_ARCH=atom
     ;;
   xpc)
     CCSP_ARCH=pc
     ;;
   xmips)
     CCSP_ARCH=mips
     ;;
   *)
     AC_MSG_ERROR([$withval is an invalid option to --with-ccsp-arch])
     ;;
 esac],
[CCSP_ARCH=''])
if test x"${CCSP_ARCH}" != x; then
  AC_DEFINE_UNQUOTED(CCSP_ARCH, "$CCSP_ARCH",
                     [The board CPU architecture])
fi

AM_CONDITIONAL(CCSP_ARCH_ARM, test "x$CCSP_ARCH" = xarm)
AM_CONDITIONAL(CCSP_ARCH_ATOM, test "x$CCSP_ARCH" = xatom)
AM_CONDITIONAL(CCSP_ARCH_PC, test "x$CCSP_ARCH" = xpc)
AM_CONDITIONAL(CCSP_ARCH_MIPS, test "x$CCSP_ARCH" = xmips)

AC_ARG_ENABLE([downloadmodule],
[  --enable-downloadmodule    Turn on downloadable module],
[case "${enableval}" in
  yes) DOWNLOADMODULE=true ;;
  no)  DOWNLOADMODULE=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-downloadmodule]) ;;
esac],[DOWNLOADMODULE=false])
AM_CONDITIONAL([DOWNLOADMODULE], [test x$DOWNLOADMODULE = xtrue])

AC_ARG_ENABLE([wifidcl],
AS_HELP_STRING([--enable-wifidcl],
               [enable wifi data collection]),
[case "${enableval}" in
    yes) wifidcl=true ;;
    no) wifidcl=false ;;
    *) AC_MSG_ERROR([bad value ${enableval} for --enable-wifidcl]) ;;
esac],
[wifidcl=false])
AM_CONDITIONAL([WIFI_DATA_COLLECTION], [test x$wifidcl = xtrue])

AC_CONFIG_FILES(
	source/AdvSecuritySsp/Makefile
	source/AdvSecurityDml/Makefile
	source/Makefile
	Makefile
)

AC_SUBST([UNIT_TEST_DOCKER_SUPPORT])

AC_OUTPUT