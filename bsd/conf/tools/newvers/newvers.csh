#!/bin/sh -
#
# Mach Operating System
# Copyright (c) 1990 Carnegie-Mellon University
# Copyright (c) 1989 Carnegie-Mellon University
# All rights reserved.  The CMU software License Agreement specifies
# the terms and conditions for use and redistribution.
#

#
# newvers.sh	copyright major minor variant
#

major="$1"; minor="$2"; variant="$3"
v="${major}.${minor}" d=`pwd` h="rcbuilder" t=`date` w=`whoami`
if [ -z "$d" -o -z "$h" -o -z "$t" ]; then
    exit 1
fi
CONFIG=`expr "$d" : '.*/\([^/]*\)$'`
d=`expr "$d" : '.*/\([^/]*/[^/]*/[^/]*\)$'`
(
  /bin/echo "int  ${COMPONENT}_version_major      = ${major};" ;
  /bin/echo "int  ${COMPONENT}_version_minor      = ${minor};" ;
  /bin/echo "char ${COMPONENT}_version_variant[]  = \"${variant}\";" ;
  /bin/echo "char ${COMPONENT}_version[] = \"BSD Component Version ${v}:\\n${t}; $w($h):$d\\n\";" ;
  /bin/echo "char ${COMPONENT}_osrelease[] = \"${major}.${minor}\";" ;
  /bin/echo "char ${COMPONENT}_ostype[] = \"BSD\";" ;
) > vers.c
if [ -s vers.suffix -o ! -f vers.suffix ]; then
    rm -f vers.suffix
    echo ".${variant}.${CONFIG}" > vers.suffix
fi
exit 0
