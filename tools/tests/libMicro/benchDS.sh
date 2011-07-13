#!/bin/sh
#
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms
# of the Common Development and Distribution License
# (the "License").  You may not use this file except
# in compliance with the License.
#
# You can obtain a copy of the license at
# src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing
# permissions and limitations under the License.
#
# When distributing Covered Code, include this CDDL
# HEADER in each file and include the License file at
# usr/src/OPENSOLARIS.LICENSE.  If applicable,
# add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your
# own identifying information: Portions Copyright [yyyy]
# [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

function usage {
    echo "Usage"
    echo "$0 [-l] [-h] <#-of-users> nodename [test match pattern]"
    echo "-l                    : disable libinfo L1 cache"
    echo "-h                    : Help. This option displays information on how to run the script. "
    echo "[test match pattern]  : This option runs only the test that is specified"
    echo                                                                                                                                                                                                       
    echo "You must have set up users, groups, and SACLs with od_account_create"
    echo "with the same number of user accounts."                                                                                                                                                               
    echo "Supply a pattern to match to run a subset of tests"
    exit 1
}

# default to libinfo cache enabled
L1CACHE="1"

while getopts "lh" OPT_LIST
do
    case $OPT_LIST in 
        l) L1CACHE="0";;    # to run the libmicro tests with l1cache disabled
        h) usage;;
        *) usage;;
    esac
done

shift `expr $OPTIND - 1`

if [ $# -lt 2 -o $# -gt 3 ]; then
    usage
fi

tattle="./tattle"

bench_version=0.4.0
libmicro_version=`$tattle -V`

case $libmicro_version in
$bench_version)
	;;
*)
	echo "ERROR: libMicro version doesn't match 'bench' script version"
	exit 1
esac

TMPROOT=/private/tmp/libmicro.$$
VARROOT=/private/var/tmp/libmicro.$$
mkdir -p $TMPROOT
mkdir -p $VARROOT
trap "rm -rf $TMPROOT $VARROOT && exit" 0 2

TFILE=$TMPROOT/data
IFILE=$TMPROOT/ifile
TDIR1=$TMPROOT/0/1/2/3/4/5/6/7/8/9
TDIR2=$TMPROOT/1/2/3/4/5/6/7/8/9/0
VFILE=$VARROOT/data
VDIR1=$VARROOT/0/1/2/3/4/5/6/7/8/9
VDIR2=$VARROOT/1/2/3/4/5/6/7/8/9/0

OPTS="-E -C 200 -L -S -W"

dd if=/dev/zero of=$TFILE bs=1024k count=10 2>/dev/null
dd if=/dev/zero of=$VFILE bs=1024k count=10 2>/dev/null
mkdir -p $TDIR1 $TDIR2
mkdir -p $VDIR1 $VDIR2

touch $IFILE
/usr/bin/touch /private/var/tmp/lmbench


# produce benchmark header for easier comparisons

hostname=`uname -n`

if [ -f /usr/sbin/psrinfo ]; then
	p_count=`psrinfo|wc -l`
	p_mhz=`psrinfo -v | awk '/operates/{print $6 "MHz"; exit }'`
	p_type=`psrinfo -vp 2>/dev/null | awk '{if (NR == 3) {print $0; exit}}'` 
	p_ipaddr=`getent hosts $hostname | awk '{print $1}'`
fi

if [ -f /proc/cpuinfo ]; then
	p_count=`egrep processor /proc/cpuinfo | wc -l`
	p_mhz=`awk -F: '/cpu MHz/{printf("%5.0f00Mhz\n",$2/100); exit}' /proc/cpuinfo`
	p_type=`awk -F: '/model name/{print $2; exit}' /proc/cpuinfo`
	p_ipaddr=`getent hosts $hostname | awk '{print $1}'`
else
## Mac OS X specific stuff
# first, get ugly output, in case pretty output isn't available
#
	p_count=`sysctl -n hw.physicalcpu`
	p_mhz=`sysctl -n hw.cpufrequency`
	p_type=`sysctl -n hw.model`

if [ -x /usr/sbin/system_profiler ]; then
	# <rdar://4655981> requires this hunk of work-around
	# grep the XML for the characteristic we need. The key appears twice, so grep for the useful key (with 'string')
	# use sed to strip off the <string></string> and the tabs in front of the string.  So much work for so little result.
	#
		p_mhz=`system_profiler -xml -detailLevel mini SPHardwareDataType | \
			grep -A1 current_processor_speed | grep string | \
			sed -E 's/<string>(.+)<\/string>/\1/' | sed 's-	--g'`
		p_type=`system_profiler -xml -detailLevel mini SPHardwareDataType | \
			grep -A1 cpu_type | grep string | \
			sed -E 's/<string>(.+)<\/string>/\1/' | sed 's-	--g'`
fi

# look for en0 (usually ethernet) if that isn't there try en1 (usually wireless) else give up
	p_ipaddr=`ipconfig getpacket en0 | grep yiaddr | tr "= " "\n" | grep [0-9]`
	if [ ! $p_ipaddr  ]; then
		p_ipaddr=`ipconfig getpacket en1 | grep yiaddr | tr "= " "\n" | grep [0-9]`
	elif [ ! $p_ipaddr ]; then
		p_ipaddr="unknown"
	fi
fi

printf "\n\n!Libmicro_#:   %30s\n" $libmicro_version
printf "!Options:      %30s\n" "$OPTS"
printf "!Machine_name: %30s\n" "$hostname"
printf "!OS_name:      %30s\n" `uname -s`
printf "!OS_release:   %30s\n" `sw_vers -productVersion`
printf "!OS_build:     %30.18s\n" "`sw_vers -buildVersion`"
printf "!Processor:    %30s\n" `arch`
printf "!#CPUs:        %30s\n" $p_count
printf "!CPU_MHz:      %30s\n" "$p_mhz"
printf "!CPU_NAME:     %30s\n" "$p_type"
printf "!IP_address:   %30s\n" "$p_ipaddr"
printf "!Run_by:       %30s\n" $LOGNAME
printf "!Date:	       %30s\n" "`date '+%D %R'`"
printf "!Compiler:     %30s\n" `$tattle -c`
printf "!Compiler Ver.:%30s\n" "`$tattle -v`"
printf "!sizeof(long): %30s\n" `$tattle -s`
printf "!extra_CFLAGS: %30s\n" "`$tattle -f`"
printf "!TimerRes:     %30s\n\n\n" "`$tattle -r`"
 
bin_dir="$TMPROOT/bin"

mkdir -p $bin_dir
cp bin-*/exec_bin $bin_dir/$A

cp ./apple/bin-*/posix_spawn_bin $bin_dir/$A

newline=0

# We commonly want to adjust this script for the number of users
# and configuration of the accounts and configuration being tested.
#
# Users:
NUSERS=$1
NODENAME=$2
UID_BASE=5000
UID_END=`expr $UID_BASE + $NUSERS - 1`
USER_PREFIX=od_test_
#
# Groups:
GID_ALL_USERS=1211
GID_NO_USERS=1212
GROUP_BASE=od_test_group
#
# getaddrinfo on hosts:
HOST_BASE=sfs0
HOST_RANGE=1-8

#
# Everything below the while loop is input for the while loop
# if you have any tests which can't run in the while loop, put
# them above this comment
#
while read A B
do
	# $A contains the command, $B contains the arguments
	# we echo blank lines and comments
	# we skip anything which fails to match *$1* (useful
	# if we only want to test one case, but a nasty hack)

	case $A in
	\#*)
		echo "$A $B"
		newline=1
		continue
		;;
	
	"")
		if [ $newline -eq 1 ]
		then
			newline=0
			echo
			echo
		fi

		continue
		;;

	*$3*)
		;;

	*)
		continue
		;;
	esac

	if [ ! -f $bin_dir/$A ]
	then
		cp bin-*/$A $bin_dir/$A
	fi

	echo

	(cd $TMPROOT && eval "bin/$A $B")

	echo
	echo
done <<.

# -P <# procs>
# -T <# threads> - exclusive!

# mbr_check_service_membership()
mbr_check_service_membership	$OPTS -N "mbr_check_service_membership" -s libMicro -u ${USER_PREFIX} -r ${NUSERS}
mbr_check_service_membership	$OPTS -N "mbr_check_service_membership_t2" -T 2 -s libMicro -u ${USER_PREFIX} -r ${NUSERS}
mbr_check_service_membership	$OPTS -N "mbr_check_service_membership_t4" -T 4 -s libMicro -u ${USER_PREFIX} -r ${NUSERS}
mbr_check_service_membership	$OPTS -N "mbr_check_service_membership_p2" -P 2 -s libMicro -u ${USER_PREFIX} -r ${NUSERS}
mbr_check_service_membership	$OPTS -N "mbr_check_service_membership_p4" -P 4 -s libMicro -u ${USER_PREFIX} -r ${NUSERS}

# getpwnam()
getpwnam			$OPTS -N "getpwnam" -l ${L1CACHE} -r ${NUSERS} -u ${USER_PREFIX}
getpwnam			$OPTS -N "getpwnam_t2" -T 2 -l ${L1CACHE} -r ${NUSERS} -u ${USER_PREFIX}
getpwnam			$OPTS -N "getpwnam_p2" -P 2 -l ${L1CACHE} -r ${NUSERS} -u ${USER_PREFIX}

# mbr_check_membership()
mbr_check_membership		$OPTS -N "mbr_check_membership" -u ${UID_BASE}-${UID_END} -g ${GID_ALL_USERS}-${GID_NO_USERS}
mbr_check_membership		$OPTS -N "mbr_check_membership_t2" -u ${UID_BASE}-${UID_END} -g ${GID_ALL_USERS}-${GID_NO_USERS} -T 2
mbr_check_membership		$OPTS -N "mbr_check_membership_t4" -u ${UID_BASE}-${UID_END} -g ${GID_ALL_USERS}-${GID_NO_USERS} -T 4
mbr_check_membership		$OPTS -N "mbr_check_membership_p2" -u ${UID_BASE}-${UID_END} -g ${GID_ALL_USERS}-${GID_NO_USERS} -P 2
mbr_check_membership		$OPTS -N "mbr_check_membership_p4" -u ${UID_BASE}-${UID_END} -g ${GID_ALL_USERS}-${GID_NO_USERS} -P 4

# getpwuid()
getpwuid			$OPTS -N "getpwuid" -l ${L1CACHE} -u ${UID_BASE}-${UID_END}
getpwuid			$OPTS -N "getpwuid_t2" -l ${L1CACHE} -u ${UID_BASE}-${UID_END} -T 2
getpwuid			$OPTS -N "getpwuid_t4" -l ${L1CACHE} -u ${UID_BASE}-${UID_END} -T 4
getpwuid			$OPTS -N "getpwuid_p2" -l ${L1CACHE} -u ${UID_BASE}-${UID_END} -P 2
getpwuid			$OPTS -N "getpwuid_p4" -l ${L1CACHE} -u ${UID_BASE}-${UID_END} -P 4

# getgrgid()
getgrgid			$OPTS -N "getgrgid" -l ${L1CACHE} -g ${GID_ALL_USERS}-${GID_NO_USERS}
getgrgid			$OPTS -N "getgrgid_t2" -l ${L1CACHE} -g ${GID_ALL_USERS}-${GID_NO_USERS} -T 2
getgrgid			$OPTS -N "getgrgid_t4" -l ${L1CACHE} -g ${GID_ALL_USERS}-${GID_NO_USERS} -T 4
getgrgid			$OPTS -N "getgrgid_p2" -l ${L1CACHE} -g ${GID_ALL_USERS}-${GID_NO_USERS} -P 2
getgrgid			$OPTS -N "getgrgid_p4" -l ${L1CACHE} -g ${GID_ALL_USERS}-${GID_NO_USERS} -P 4

# getpwent()
getpwent			$OPTS -N "getpwent" -l ${L1CACHE} 
getpwent			$OPTS -N "getpwent_t2" -l ${L1CACHE} -T 2
getpwent			$OPTS -N "getpwent_t4" -l ${L1CACHE} -T 4
getpwent			$OPTS -N "getpwent_p2" -l ${L1CACHE} -P 2
getpwent			$OPTS -N "getpwent_p4" -l ${L1CACHE} -P 4

# getgrent()
getgrent			$OPTS -N "getgrent" -l ${L1CACHE} 
getgrent			$OPTS -N "getgrent_t2" -l ${L1CACHE} -T 2
getgrent			$OPTS -N "getgrent_t4" -l ${L1CACHE} -T 4
getgrent			$OPTS -N "getgrent_p2" -l ${L1CACHE} -P 2
getgrent			$OPTS -N "getgrent_p4" -l ${L1CACHE} -P 4

# getaddrinfo() host
#getaddrinfo_host		$OPTS -N "getaddrinfo_host" -r ${HOST_RANGE} -h ${HOST_BASE}%d
#getaddrinfo_host		$OPTS -N "getaddrinfo_host_t2" -r ${HOST_RANGE} -h ${HOST_BASE}%d -T 2
#getaddrinfo_host		$OPTS -N "getaddrinfo_host_t4" -r ${HOST_RANGE} -h ${HOST_BASE}%d -T 4
#getaddrinfo_host		$OPTS -N "getaddrinfo_host_p2" -r ${HOST_RANGE} -h ${HOST_BASE}%d -P 2
#getaddrinfo_host		$OPTS -N "getaddrinfo_host_p4" -r ${HOST_RANGE} -h ${HOST_BASE}%d -P 4

# getaddrinfo() port
getaddrinfo_port		$OPTS -N "getaddrinfo_port" -l ${L1CACHE} 
getaddrinfo_port		$OPTS -N "getaddrinfo_port_t2" -l ${L1CACHE} -T 2
getaddrinfo_port		$OPTS -N "getaddrinfo_port_t4" -l ${L1CACHE} -T 4
getaddrinfo_port		$OPTS -N "getaddrinfo_port_p2" -l ${L1CACHE} -P 2
getaddrinfo_port		$OPTS -N "getaddrinfo_port_p4" -l ${L1CACHE} -P 4

# getgrnam()
getgrnam			$OPTS -N "getgrnam" -l ${L1CACHE} -g ${GROUP_BASE} -r 2
getgrnam			$OPTS -N "getgrnam_t2" -l ${L1CACHE} -T 2 -g ${GROUP_BASE} -r 2
getgrnam			$OPTS -N "getgrnam_t4" -l ${L1CACHE} -T 4 -g ${GROUP_BASE} -r 2
getgrnam			$OPTS -N "getgrnam_p2" -l ${L1CACHE} -P 2 -g ${GROUP_BASE} -r 2
getgrnam			$OPTS -N "getgrnam_p4" -l ${L1CACHE} -P 4 -g ${GROUP_BASE} -r 2

# ODQueryCreateWithNode()
od_query_create_with_node	$OPTS -N "ODQueryCreateWithNode_cache_${NUSERS}u" -c 50 -r ${NUSERS} -t u -B 50 -n ${NODENAME}
od_query_create_with_node	$OPTS -N "ODQueryCreateWithNode_cache_${NUSERS}u_t2" -T 2 -c 50 -r ${NUSERS} -t u -B 50 -n ${NODENAME}
od_query_create_with_node	$OPTS -N "ODQueryCreateWithNode_cache_${NUSERS}u_t4" -T 4 -c 50 -r ${NUSERS} -t u -B 50 -n ${NODENAME}
od_query_create_with_node	$OPTS -N "ODQueryCreateWithNode_cache_${NUSERS}u_p2" -P 2 -c 50 -r ${NUSERS} -t u -B 50 -n ${NODENAME}
od_query_create_with_node	$OPTS -N "ODQueryCreateWithNode_cache_${NUSERS}u_p4" -P 4 -c 50 -r ${NUSERS} -t u -B 50 -n ${NODENAME}

.
