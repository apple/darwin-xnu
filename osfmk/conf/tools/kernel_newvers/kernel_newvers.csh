#!/bin/sh -
#
# Mach Operating System
# Copyright (c) 1990 Carnegie-Mellon University
# Copyright (c) 1989 Carnegie-Mellon University
# All rights reserved.  The CMU software License Agreement specifies
# the terms and conditions for use and redistribution.
#

#
# kernel_newvers.sh	copyright major minor variant
#

major="$1"; minor="$2"; variant="$3"
version="${major}.${minor}"
if [ -n "$variant" ]; then version="${version}.${variant}"; fi

objdir="${OBJROOT}/${KERNEL_CONFIG}_${ARCH_CONFIG}"
  time=`date`
   who=`whoami`

if [ -z "${objdir}" ] || [ -z "${time}" ]; then exit 1; fi

CONFIG=`expr "${objdir}" : '.*/\([^/]*\)$'`
objdir=`expr "${objdir}" : '.*/\([^/]*/[^/]*/[^/]*\)$'`
(
  /bin/echo "int  version_major      = ${major};" ;
  /bin/echo "int  version_minor      = ${minor};" ;
  /bin/echo "char version_variant[]  = \"${variant}\";" ;
  /bin/echo "char version[] = \"Darwin Kernel Version ${version}:\\n${time}; ${who}:${objdir}\\n\\n\";" ;
  /bin/echo "char osrelease[] = \"${version}\";" ;
  /bin/echo "char ostype[] = \"Darwin\";" ;
) > kernel_vers.c

if [ -s vers.suffix -o ! -f vers.suffix ]; then
    rm -f vers.suffix
    echo ".${variant}.${CONFIG}" > vers.suffix
fi
exit 0
