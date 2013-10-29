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


# usage function - defines all the options that can be given to this script.
function usage {
	echo "Usage"
	echo "$0 [-l] [-h] [name of test]"
	echo "-l               : This option runs the lmbench tests along with the default libmicro tests."
	echo "-h               : Help. This option displays information on how to run the script. "
	echo "[name of test]   : This option runs only the test that is specified"
	echo ""
	echo "Examples"
	echo "$0               : This is the defualt execution. This will run only the default libmicro tests."
	echo "$0 -l            : This will run the lmbench tests too "
	echo "$0 getppid       : This will run only the getppid tests"
	exit
	
}

if [ $# -eq 1 ]
then 
	lmbench=2    # to check if only a single test is to be run. e.g, ./bench.sh getppid
else
	lmbench=0    # to run the default libMicro tests, without the lmbench tests.
fi

while getopts "lh" OPT_LIST
do
	case $OPT_LIST in 
		l) lmbench=1;;    # to run the libmicro tests including the lmbench tests.
		h) usage;;
		*) usage;;
	esac
done

if [ -w / ]; then
	#do nothing
	echo "/ is mounted"
else
	echo "ERROR: the test requires that the / directory be read/writable, please mount using the command: 'mount -uw /' "
	exit 1
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

	*$1*)
		# Default execution without the lmbench tests. 
		# checks if there is no argument passed by the user.
		if [  $lmbench -eq 0 ]
		then
			string=lmbench
			if [ "${A:0:7}" == "$string" ]
			then
				continue
			fi
		fi
			
		;;
	
	*)		
		if [ $lmbench -ne 1 ]
		then
			continue
		fi
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

#
# Obligatory null system call: use very short time
# for default since SuSe implements this "syscall" in userland
#

getpid		$OPTS -N "getpid" -I 5
getppid		$OPTS -N "getppid" -I 5

getenv		$OPTS -N "getenv"	-s 100 -I 100	 
getenv		$OPTS -N "getenvT2"	-s 100 -I 100	-T 2 

gettimeofday	$OPTS -N "gettimeofday"          

log		$OPTS -N "log"	-I 20	-B 300000	 
exp		$OPTS -N "exp"	-I 20	-B 100000	 
lrand48		$OPTS -N "lrand48"

memset		$OPTS -N "memset_10"	-s 10	-I 10 
memset		$OPTS -N "memset_256"	-s 256	-I 20
memset		$OPTS -N "memset_256_u"	-s 256	 -a 1 -I 20 
memset		$OPTS -N "memset_1k"	-s 1k	 -I 100 -B 2000
memset		$OPTS -N "memset_4k"    -s 4k    -I 250 -B 500
memset		$OPTS -N "memset_4k_uc" -s 4k    -u -I 400

memset		$OPTS -N "memset_10k"	-s 10k	-I 600 -B 500
memset		$OPTS -N "memset_1m"	-s 1m	-I 200000
memset		$OPTS -N "memset_10m"	-s 10m -I 2000000 
memset		$OPTS -N "memsetP2_10m"	-s 10m -P 2 -I 2000000 

memrand		$OPTS -N "memrand"	-s 40m -B 10000

# This is an elided test and is not ported yet.
# Check Makefile.darwin for list of elided tests  
# cachetocache	$OPTS -N "cachetocache" -s 100k -T 2 -I 200

isatty		$OPTS -N "isatty_yes"   
isatty		$OPTS -N "isatty_no"  -f $IFILE

malloc		$OPTS -N "malloc_10"    -s 10    -g 10 -I 50
malloc		$OPTS -N "malloc_100"   -s 100   -g 10 -I 50
malloc		$OPTS -N "malloc_1k"    -s 1k    -g 10 -I 50
malloc		$OPTS -N "malloc_10k"   -s 10k   -g 10 -I 50
malloc		$OPTS -N "malloc_100k"  -s 100k  -g 10 -I 2000

malloc		$OPTS -N "mallocT2_10"    -s 10   -g 10 -T 2 -I 200
malloc		$OPTS -N "mallocT2_100"   -s 100  -g 10 -T 2 -I 200
malloc		$OPTS -N "mallocT2_1k"    -s 1k   -g 10 -T 2 -I 200
malloc		$OPTS -N "mallocT2_10k"   -s 10k  -g 10 -T 2 -I 200
malloc		$OPTS -N "mallocT2_100k"  -s 100k -g 10 -T 2 -I 10000

close		$OPTS -N "close_bad"		-B 96		-b
close		$OPTS -N "close_tmp"		-B 64		-f $TFILE
close		$OPTS -N "close_usr"		-B 64		-f $VFILE
close		$OPTS -N "close_zero"		-B 64		-f /dev/zero
close_tcp	$OPTS -N "close_tcp"		-B 32  

memcpy		$OPTS -N "memcpy_10"	-s 10	-I 10 
memcpy		$OPTS -N "memcpy_1k"	-s 1k	-I 50
memcpy		$OPTS -N "memcpy_10k"	-s 10k	-I 800
memcpy		$OPTS -N "memcpy_1m"	-s 1m   -I 500000
memcpy		$OPTS -N "memcpy_10m"	-s 10m  -I 5000000

strcpy		$OPTS -N "strcpy_10"	-s 10   -I 5 
strcpy		$OPTS -N "strcpy_1k"	-s 1k   -I 100

strlen		$OPTS -N "strlen_10"	-s 10   -I 5
strlen		$OPTS -N "strlen_1k"	-s 1k   -I 100

strchr		$OPTS -N "strchr_10"	-s 10   -I 5
strchr		$OPTS -N "strchr_1k"	-s 1k   -I 200
strcmp		$OPTS -N "strcmp_10"	-s 10   -I 10
strcmp		$OPTS -N "strcmp_1k"	-s 1k   -I 200

strcasecmp	$OPTS -N "scasecmp_10"	-s 10 -I 50 -B 2000
strcasecmp	$OPTS -N "scasecmp_1k"	-s 1k -I 20000 -B 100

strtol		$OPTS -N "strtol"      -I 20      

# This is an elided test and is not ported yet.     
# Check Makefile.darwin for list of elided tests
# getcontext	$OPTS -N "getcontext"  -I 100

# This is an elided test and is not ported yet.     
# Check Makefile.darwin for list of elided tests
# setcontext	$OPTS -N "setcontext"  -I 100

mutex		$OPTS -N "mutex_st"	-I 10
mutex		$OPTS -N "mutex_mt"	-t -I 10	
mutex		$OPTS -N "mutex_T2"     -T 2  -I 100

longjmp		$OPTS -N "longjmp"	-I 10
siglongjmp	$OPTS -N "siglongjmp"	-I 20

getrusage	$OPTS -N "getrusage"	-I 200

times		$OPTS -N "times"	-I 200
time		$OPTS -N "time"		-I 50
localtime_r	$OPTS -N "localtime_r"	-I 200  
strftime	$OPTS -N "strftime" -I 10000 -B 100 

mktime		$OPTS -N "mktime"       -I 500   
mktime		$OPTS -N "mktimeT2" -T 2 -I 1000 

cascade_mutex	$OPTS -N "c_mutex_1"	-I 50
cascade_mutex	$OPTS -N "c_mutex_10"	-T 10 -I 5000
cascade_mutex	$OPTS -N "c_mutex_200"	-T 200	-I 2000000

cascade_cond	$OPTS -N "c_cond_1"	-I 100
cascade_cond	$OPTS -N "c_cond_10"	-T 10	-I 3000
cascade_cond	$OPTS -N "c_cond_200"	-T 200	-I 2000000

cascade_lockf	$OPTS -N "c_lockf_1"	-I 1000	
cascade_lockf	$OPTS -N "c_lockf_10"	-P 10 -I 50000
#cascade_lockf	$OPTS -N "c_lockf_200"	-P 200 -I 5000000



cascade_flock	$OPTS -N "c_flock"	-I 1000	
cascade_flock	$OPTS -N "c_flock_10"	-P 10   -I 50000
#cascade_flock	$OPTS -N "c_flock_200"	-P 200	-I 5000000



cascade_fcntl	$OPTS -N "c_fcntl_1"	-I 2000 	
cascade_fcntl	$OPTS -N "c_fcntl_10"	-P 10 -I 20000
#cascade_fcntl	$OPTS -N "c_fcntl_200"	-P 200	-I 5000000


file_lock	$OPTS -N "file_lock"   -I 1000         

getsockname	$OPTS -N "getsockname"	-I 100
getpeername	$OPTS -N "getpeername"	-I 100

chdir		$OPTS -N "chdir_tmp"	-I 2000		$TDIR1 $TDIR2
chdir		$OPTS -N "chdir_usr"	-I 2000		$VDIR1 $VDIR2

chdir		$OPTS -N "chgetwd_tmp"	-I 3000	-g $TDIR1 $TDIR2
chdir		$OPTS -N "chgetwd_usr"	-I 3000	-g $VDIR1 $VDIR2

realpath	$OPTS -N "realpath_tmp" -I 3000		-f $TDIR1
realpath	$OPTS -N "realpath_usr"	-I 3000	-f $VDIR1

stat		$OPTS -N "stat_tmp" -I 1000		-f $TFILE
stat		$OPTS -N "stat_usr" -I 1000		-f $VFILE

lmbench_stat		$OPTS -N "lmbench_stat_tmp" -I 1000		-f $TFILE
lmbench_stat		$OPTS -N "lmbench_stat_usr" -I 10000 -B 100		-f /private/var/tmp/lmbench

#
# lmbench uses a touched empty file in /private/var/tmp
# libMicro uses a 1M file in a directory off /private/var/tmp
# performance difference is ~ 0.2 usecs/call
#
# why? - walking the dir tree, empty file vs. non-empty file, non-empty dir
# in the case of libMicro, etc., etc.
#

lmbench_stat		$OPTS -N "lmbench_stat_usr - Default" -I 10000 -B 100	-f /private/var/tmp/lmbench

lmbench_fstat		$OPTS -N "lmbench_fstat_tmp" -I 1000		-f $TFILE
lmbench_fstat		$OPTS -N "lmbench_fstat_usr" -I 10000 -B 100		-f /private/var/tmp/lmbench

# see stat test to understand why we are using /private/var/tmp/lmbench

lmbench_fstat		$OPTS -N "lmbench_fstat_usr - Default" -I 10000 -B 100	-f /private/var/tmp/lmbench

lmbench_openclose	$OPTS -N "lmbench_openclose - Default" -I 10000 -B 100	-f /private/var/tmp/lmbench

lmbench_select_file $OPTS -N "lmbench_select_file_10"  -n 10  -B 100
lmbench_select_file $OPTS -N "lmbench_select_file_100" -n 100 -B 100
lmbench_select_file $OPTS -N "lmbench_select_file_250" -n 250 -B 100
lmbench_select_file $OPTS -N "lmbench_select_file_500" -n 500 -B 100

lmbench_select_tcp $OPTS -N "lmbench_select_tcp_10"  -n 10  -B 100
lmbench_select_tcp $OPTS -N "lmbench_select_tcp_100" -n 100 -B 100
lmbench_select_tcp $OPTS -N "lmbench_select_tcp_250" -n 250 -B 100
lmbench_select_tcp $OPTS -N "lmbench_select_tcp_500" -n 500 -B 100

fcntl		$OPTS -N "fcntl_tmp"	-I 100	-f $TFILE
fcntl		$OPTS -N "fcntl_usr"	-I 100	-f $VFILE
fcntl_ndelay	$OPTS -N "fcntl_ndelay"	-I 100	

lseek		$OPTS -N "lseek_t8k"	-s 8k	-I 50	-f $TFILE
lseek		$OPTS -N "lseek_u8k"	-s 8k	-I 50	-f $VFILE

open		$OPTS -N "open_tmp"		-B 256		-f $TFILE
open		$OPTS -N "open_usr"		-B 256		-f $VFILE
open		$OPTS -N "open_zero"		-B 256		-f /dev/zero

dup		$OPTS -N "dup"			-B 512   

socket		$OPTS -N "socket_u"		-B 256
socket		$OPTS -N "socket_i"		-B 256		-f PF_INET

socketpair	$OPTS -N "socketpair"		-B 256

setsockopt	$OPTS -N "setsockopt"		-I 200

bind		$OPTS -N "bind"			-B 100

listen		$OPTS -N "listen"		-B 100

#connection	$OPTS -N "connection"		-B 256 

poll		$OPTS -N "poll_10"	-n 10	-I 500
poll		$OPTS -N "poll_100"	-n 100	-I 1000
poll		$OPTS -N "poll_1000"	-n 1000	-I 5000

poll		$OPTS -N "poll_w10"	-n 10	-I 500		-w 1
poll		$OPTS -N "poll_w100"	-n 100	-I 2000		-w 10
poll		$OPTS -N "poll_w1000"	-n 1000	-I 40000	-w 100

select		$OPTS -N "select_10"	-n 10	-I 500
select		$OPTS -N "select_100"	-n 100	-I 1000
select		$OPTS -N "select_1000"	-n 1000	-I 5000

select		$OPTS -N "select_w10"	-n 10	-I 500		-w 1
select		$OPTS -N "select_w100"	-n 100	-I 2000		-w 10
select		$OPTS -N "select_w1000"	-n 1000	-I 40000        -w 100

semop		$OPTS -N "semop" -I 200

sigaction	$OPTS -N "sigaction" -I 100
signal		$OPTS -N "signal" -I 1000
sigprocmask	$OPTS -N "sigprocmask" -I 200

lmbench_lat_sig_install	$OPTS -N "lmbench_siginstall"
# sigcatch and sigsend need to be evaluated together
# lmbench framework will allow multiple measurements within the same
# benchmark test which allow them to factor out the cost of sending
# a signal from catching one
#
# for our purposes sigcatch results - sigsend results yield
# lmbench sig handler overhead measurements
lmbench_lat_sig_catch	$OPTS -N "lmbench_sigcatch" 
lmbench_lat_sig_send	$OPTS -N "lmbench_sigsend" 


pthread_create  $OPTS -N "pthread_8"		-B 8
pthread_create  $OPTS -N "pthread_32"		-B 32
pthread_create  $OPTS -N "pthread_128"		-B 128
pthread_create  $OPTS -N "pthread_512"		-B 512

fork		$OPTS -N "fork_10"		-B 10
#fork		$OPTS -N "fork_100"		-B 100  -C 100

#fork		$OPTS -N "fork_1000"		-B 1000 -C 50

exit		$OPTS -N "exit_10"		-B 10
##exit		$OPTS -N "exit_100"		-B 100

#exit		$OPTS -N "exit_1000"		-B 1000 -C 50

exit		$OPTS -N "exit_10_nolibc"	-e -B 10

exec		$OPTS -N "exec" -B 10

posix_spawn	$OPTS -N "posix_spawn" -B 10

system		$OPTS -N "system" -I 1000000

recurse		$OPTS -N "recurse"		-B 512

read		$OPTS -N "read_t1k"	-s 1k -B 50			-f $TFILE
read		$OPTS -N "read_t10k"	-s 10k	-B 16		-f $TFILE
read		$OPTS -N "read_t100k"	-s 100k	-B 4		-f $TFILE

read		$OPTS -N "read_u1k"	-s 1k	-B 50		-f $VFILE
read		$OPTS -N "read_u10k"	-s 10k	-B 16		-f $VFILE
read		$OPTS -N "read_u100k"	-s 100k	-B 4		-f $VFILE

read		$OPTS -N "read_z1k"	-s 1k	-B 100		-f /dev/zero 
read		$OPTS -N "read_z10k"	-s 10k	-B 30		-f /dev/zero 
read		$OPTS -N "read_z100k"	-s 100k	-B 4		-f /dev/zero 
read		$OPTS -N "read_zw100k"	-s 100k	-B 4         -w	-f /dev/zero 

lmbench_read		$OPTS -N "read_t1b"	-s 1 -B 50			-f $TFILE
lmbench_read		$OPTS -N "read_t1k"	-s 1k -B 50			-f $TFILE
lmbench_read		$OPTS -N "read_t10k"	-s 10k	-B 16		-f $TFILE
lmbench_read		$OPTS -N "read_t100k"	-s 100k	-B 4		-f $TFILE

lmbench_read		$OPTS -N "read_u1b"	-s 1	-B 50		-f $VFILE
lmbench_read		$OPTS -N "read_u1k"	-s 1k	-B 50		-f $VFILE
lmbench_read		$OPTS -N "read_u10k"	-s 10k	-B 16		-f $VFILE
lmbench_read		$OPTS -N "read_u100k"	-s 100k	-B 4		-f $VFILE

lmbench_read		$OPTS -N "read_z1b - Default"	-s 1	-B 100		-f /dev/zero 
lmbench_read		$OPTS -N "read_z1k"	-s 1k	-B 100		-f /dev/zero 
lmbench_read		$OPTS -N "read_z10k"	-s 10k	-B 30		-f /dev/zero 
lmbench_read		$OPTS -N "read_z100k"	-s 100k	-B 4		-f /dev/zero 
lmbench_read		$OPTS -N "read_zw100k"	-s 100k	-B 4         -w	-f /dev/zero 

write		$OPTS -N "write_t1k"	-s 1k	-B 50		-f $TFILE
write		$OPTS -N "write_t10k"	-s 10k	-B 25		-f $TFILE
write		$OPTS -N "write_t100k"	-s 100k	-B 4		-f $TFILE

write		$OPTS -N "write_u1k"	-s 1k	-B 50		-f $VFILE
write		$OPTS -N "write_u10k"	-s 10k	-B 25		-f $VFILE
write		$OPTS -N "write_u100k"	-s 100k	-B 4		-f $VFILE

write		$OPTS -N "write_n1k"	-s 1k	-I 100 -B 0	-f /dev/null 
write		$OPTS -N "write_n10k"	-s 10k	-I 100 -B 0	-f /dev/null 
write		$OPTS -N "write_n100k"	-s 100k	-I 100 -B 0	-f /dev/null 

lmbench_write		$OPTS -N "lmbench_write_t1b"	-s 1	-B 50		-f $TFILE
lmbench_write		$OPTS -N "lmbench_write_t1k"	-s 1k	-B 50		-f $TFILE
lmbench_write		$OPTS -N "lmbench_write_t10k"	-s 10k	-B 25		-f $TFILE
lmbench_write		$OPTS -N "lmbench_write_t100k"	-s 100k	-B 4		-f $TFILE

lmbench_write		$OPTS -N "lmbench_write_u1b"	-s 1	-B 50		-f $VFILE
lmbench_write		$OPTS -N "lmbench_write_u1k"	-s 1k	-B 50		-f $VFILE
lmbench_write		$OPTS -N "lmbench_write_u10k"	-s 10k	-B 25		-f $VFILE
lmbench_write		$OPTS -N "lmbench_write_u100k"	-s 100k	-B 4		-f $VFILE

lmbench_write		$OPTS -N "lmbench_write_n1b - Default"	-s 1	-I 100 -B 0	-f /dev/null 
lmbench_write		$OPTS -N "lmbench_write_n1k"	-s 1k	-I 100 -B 0	-f /dev/null 
lmbench_write		$OPTS -N "lmbench_write_n10k"	-s 10k	-I 100 -B 0	-f /dev/null 
lmbench_write		$OPTS -N "lmbench_write_n100k"	-s 100k	-I 100 -B 0	-f /dev/null 

writev		$OPTS -N "writev_t1k"	-s 1k	-B 20		-f $TFILE
writev		$OPTS -N "writev_t10k"	-s 10k	-B 4	        -f $TFILE
writev		$OPTS -N "writev_t100k"	-s 100k			-f $TFILE

writev		$OPTS -N "writev_u1k"	-s 1k	-B 20		-f $VFILE
writev		$OPTS -N "writev_u10k"	-s 10k	-B 4		-f $VFILE
writev		$OPTS -N "writev_u100k"	-s 100k			-f $VFILE

writev		$OPTS -N "writev_n1k"	-s 1k	-I 100 -B 0	-f /dev/null 
writev		$OPTS -N "writev_n10k"	-s 10k	-I 100 -B 0	-f /dev/null 
writev		$OPTS -N "writev_n100k"	-s 100k	-I 100 -B 0	-f /dev/null 

pread		$OPTS -N "pread_t1k"	-s 1k	-I 300		-f $TFILE
pread		$OPTS -N "pread_t10k"	-s 10k	-I 1000		-f $TFILE
pread		$OPTS -N "pread_t100k"	-s 100k	-I 10000	-f $TFILE

pread		$OPTS -N "pread_u1k"	-s 1k	-I 300		-f $VFILE
pread		$OPTS -N "pread_u10k"	-s 10k	-I 1000		-f $VFILE
pread		$OPTS -N "pread_u100k"	-s 100k	-I 10000	-f $VFILE

pread		$OPTS -N "pread_z1k"	-s 1k	-I 300		-f /dev/zero 
pread		$OPTS -N "pread_z10k"	-s 10k	-I 1000		-f /dev/zero 
pread		$OPTS -N "pread_z100k"	-s 100k	-I 2000	-f /dev/zero 
pread		$OPTS -N "pread_zw100k"	-s 100k	-w -I 10000	-f /dev/zero 

pwrite		$OPTS -N "pwrite_t1k"	-s 1k	-I 500		-f $TFILE
pwrite		$OPTS -N "pwrite_t10k"	-s 10k	-I 1000		-f $TFILE
pwrite		$OPTS -N "pwrite_t100k"	-s 100k	-I 10000	-f $TFILE

pwrite		$OPTS -N "pwrite_u1k"	-s 1k	-I 500		-f $VFILE
pwrite		$OPTS -N "pwrite_u10k"	-s 10k	-I 1000		-f $VFILE
pwrite		$OPTS -N "pwrite_u100k"	-s 100k	-I 20000	-f $VFILE

pwrite		$OPTS -N "pwrite_n1k"	-s 1k	-I 100		-f /dev/null 
pwrite		$OPTS -N "pwrite_n10k"	-s 10k	-I 100		-f /dev/null 
pwrite		$OPTS -N "pwrite_n100k"	-s 100k	-I 100		-f /dev/null 


mmap		$OPTS -N "mmap_t8k"	-l 8k	-I 1000		-f $TFILE
mmap		$OPTS -N "mmap_t128k"	-l 128k	-I 1000		-f $TFILE
mmap		$OPTS -N "mmap_u8k"	-l 8k	-I 1000		-f $VFILE
mmap		$OPTS -N "mmap_u128k"	-l 128k	-I 1000		-f $VFILE
mmap		$OPTS -N "mmap_a8k"	-l 8k	-I 200		-f MAP_ANON
mmap		$OPTS -N "mmap_a128k"	-l 128k	-I 200		-f MAP_ANON



mmap		$OPTS -N "mmap_rt8k"	-l 8k	-I 2000 -r	-f $TFILE
mmap		$OPTS -N "mmap_rt128k"	-l 128k	-I 20000 -r	-f $TFILE
mmap		$OPTS -N "mmap_ru8k"	-l 8k	-I 2000 -r	-f $VFILE
mmap		$OPTS -N "mmap_ru128k"	-l 128k	-I 20000 -r	-f $VFILE
mmap		$OPTS -N "mmap_ra8k"	-l 8k	-I 2000 -r	-f MAP_ANON
mmap		$OPTS -N "mmap_ra128k"	-l 128k	-I 20000 -r	-f MAP_ANON


mmap		$OPTS -N "mmap_wt8k"	-l 8k	-I 5000 -w	-f $TFILE
mmap		$OPTS -N "mmap_wt128k"	-l 128k	-I 50000 -w	-f $TFILE
mmap		$OPTS -N "mmap_wu8k"	-l 8k	-I 5000 -w	-f $VFILE
mmap		$OPTS -N "mmap_wu128k"	-l 128k	-I 500000 -w	-f $VFILE
mmap		$OPTS -N "mmap_wa8k"	-l 8k	-I 3000 -w	-f MAP_ANON
mmap		$OPTS -N "mmap_wa128k"	-l 128k	-I 50000 -w	-f MAP_ANON


munmap		$OPTS -N "unmap_t8k"	-l 8k	-I 500		-f $TFILE
munmap		$OPTS -N "unmap_t128k"	-l 128k	-I 500		-f $TFILE
munmap		$OPTS -N "unmap_u8k"	-l 8k	-I 500		-f $VFILE
munmap		$OPTS -N "unmap_u128k"	-l 128k	-I 500		-f $VFILE
munmap		$OPTS -N "unmap_a8k"	-l 8k	-I 500		-f MAP_ANON
munmap		$OPTS -N "unmap_a128k"	-l 128k	-I 500		-f MAP_ANON


munmap		$OPTS -N "unmap_rt8k"	-l 8k	-I 1000	-r	-f $TFILE
munmap		$OPTS -N "unmap_rt128k"	-l 128k	-I 3000	-r	-f $TFILE
munmap		$OPTS -N "unmap_ru8k"	-l 8k	-I 1000	-r	-f $VFILE
munmap		$OPTS -N "unmap_ru128k"	-l 128k	-I 3000	-r	-f $VFILE
munmap		$OPTS -N "unmap_ra8k"	-l 8k	-I 1000	-r	-f MAP_ANON
munmap		$OPTS -N "unmap_ra128k"	-l 128k	-I 2000	-r	-f MAP_ANON

connection	$OPTS -N "conn_connect"		-B 256 	-c


munmap		$OPTS -N "unmap_wt8k"	-l 8k	-I 1000	-w	-f $TFILE
munmap		$OPTS -N "unmap_wt128k"	-l 128k	-I 10000	-w	-f $TFILE
munmap		$OPTS -N "unmap_wu8k"	-l 8k	-I 1000	-w	-f $VFILE
munmap		$OPTS -N "unmap_wu128k"	-l 128k	-I 50000	-w -B 10	-f $VFILE
munmap		$OPTS -N "unmap_wa8k"	-l 8k	-I 1000	-w	-f MAP_ANON
munmap		$OPTS -N "unmap_wa128k"	-l 128k	-I 10000	-w	-f MAP_ANON

mprotect	$OPTS -N "mprot_z8k"	-l 8k  -I 300			-f /dev/zero
mprotect	$OPTS -N "mprot_z128k"	-l 128k	-I 500		-f /dev/zero
mprotect	$OPTS -N "mprot_wz8k"	-l 8k	-I 500	-w	-f /dev/zero
mprotect	$OPTS -N "mprot_wz128k"	-l 128k	-I 1000	-w	-f /dev/zero
mprotect	$OPTS -N "mprot_twz8k"  -l 8k   -I 1000 -w -t   -f /dev/zero
mprotect	$OPTS -N "mprot_tw128k" -l 128k -I 2000 -w -t   -f /dev/zero
mprotect	$OPTS -N "mprot_tw4m"   -l 4m   -w -t -B 1  -f /dev/zero

pipe		$OPTS -N "pipe_pst1"	-s 1	-I 1000	-x pipe -m st
pipe		$OPTS -N "pipe_pmt1"	-s 1	-I 8000	-x pipe -m mt
pipe		$OPTS -N "pipe_pmp1"	-s 1	-I 8000	-x pipe -m mp
pipe		$OPTS -N "pipe_pst4k"	-s 4k	-I 1000	-x pipe -m st
pipe		$OPTS -N "pipe_pmt4k"	-s 4k	-I 8000	-x pipe -m mt
pipe		$OPTS -N "pipe_pmp4k"	-s 4k	-I 8000	-x pipe -m mp

pipe		$OPTS -N "pipe_sst1"	-s 1	-I 1000	-x sock -m st
pipe		$OPTS -N "pipe_smt1"	-s 1	-I 8000	-x sock -m mt
pipe		$OPTS -N "pipe_smp1"	-s 1	-I 8000	-x sock -m mp
pipe		$OPTS -N "pipe_sst4k"	-s 4k	-I 1000	-x sock -m st
pipe		$OPTS -N "pipe_smt4k"	-s 4k	-I 8000	-x sock -m mt
pipe		$OPTS -N "pipe_smp4k"	-s 4k	-I 8000	-x sock -m mp

pipe		$OPTS -N "pipe_tst1"	-s 1	-I 1000	-x tcp  -m st
pipe		$OPTS -N "pipe_tmt1"	-s 1	-I 8000	-x tcp  -m mt
pipe		$OPTS -N "pipe_tmp1"	-s 1	-I 8000	-x tcp  -m mp
pipe		$OPTS -N "pipe_tst4k"	-s 4k	-I 1000	-x tcp  -m st
pipe		$OPTS -N "pipe_tmt4k"	-s 4k	-I 8000	-x tcp  -m mt
pipe		$OPTS -N "pipe_tmp4k"	-s 4k	-I 8000	-x tcp  -m mp

#connection	$OPTS -N "conn_accept"		-B 256      -a

lmbench_bw_unix -B 11 -L -W

lmbench_bw_mem $OPTS -N lmbench_bcopy_512 -s 512 -x bcopy
lmbench_bw_mem $OPTS -N lmbench_bcopy_1k -s 1k -x bcopy
lmbench_bw_mem $OPTS -N lmbench_bcopy_2k -s 2k -x bcopy
lmbench_bw_mem $OPTS -N lmbench_bcopy_4k -s 4k -x bcopy
lmbench_bw_mem $OPTS -N lmbench_bcopy_8k -s 8k -x bcopy
lmbench_bw_mem $OPTS -N lmbench_bcopy_16k -s 16k -x bcopy
lmbench_bw_mem $OPTS -N lmbench_bcopy_32k -s 32k -x bcopy
lmbench_bw_mem $OPTS -N lmbench_bcopy_64k -s 64k -x bcopy
lmbench_bw_mem $OPTS -N lmbench_bcopy_128k -s 128k -x bcopy
lmbench_bw_mem $OPTS -N lmbench_bcopy_256k -s 256k -x bcopy
lmbench_bw_mem $OPTS -N lmbench_bcopy_512k -s 512k -x bcopy
lmbench_bw_mem $OPTS -N lmbench_bcopy_1m -s 1m -x bcopy
lmbench_bw_mem $OPTS -N lmbench_bzero_512 -s 512 -x bzero
lmbench_bw_mem $OPTS -N lmbench_bzero_1k -s 1k -x bzero
lmbench_bw_mem $OPTS -N lmbench_bzero_2k -s 2k -x bzero
lmbench_bw_mem $OPTS -N lmbench_bzero_4k -s 4k -x bzero
lmbench_bw_mem $OPTS -N lmbench_bzero_8k -s 8k -x bzero
lmbench_bw_mem $OPTS -N lmbench_bzero_16k -s 16k -x bzero
lmbench_bw_mem $OPTS -N lmbench_bzero_32k -s 32k -x bzero
lmbench_bw_mem $OPTS -N lmbench_bzero_64k -s 64k -x bzero
lmbench_bw_mem $OPTS -N lmbench_bzero_128k -s 128k -x bzero
lmbench_bw_mem $OPTS -N lmbench_bzero_256k -s 256k -x bzero
lmbench_bw_mem $OPTS -N lmbench_bzero_512k -s 512k -x bzero
lmbench_bw_mem $OPTS -N lmbench_bzero_1m -s 1m -x bzero
lmbench_bw_mem $OPTS -N lmbench_bzero_512 -s 512 -x fcp
lmbench_bw_mem $OPTS -N lmbench_bzero_1k -s 1k -x fcp
lmbench_bw_mem $OPTS -N lmbench_bzero_2k -s 2k -x fcp
lmbench_bw_mem $OPTS -N lmbench_bzero_4k -s 4k -x fcp
lmbench_bw_mem $OPTS -N lmbench_bzero_8k -s 8k -x fcp
lmbench_bw_mem $OPTS -N lmbench_bzero_16k -s 16k -x fcp
lmbench_bw_mem $OPTS -N lmbench_bzero_32k -s 32k -x fcp
lmbench_bw_mem $OPTS -N lmbench_bzero_64k -s 64k -x fcp
lmbench_bw_mem $OPTS -N lmbench_bzero_128k -s 128k -x fcp
lmbench_bw_mem $OPTS -N lmbench_bzero_256k -s 256k -x fcp
lmbench_bw_mem $OPTS -N lmbench_bzero_512k -s 512k -x fcp
lmbench_bw_mem $OPTS -N lmbench_bzero_1m -s 1m -x fcp
lmbench_bw_mem $OPTS -N lmbench_cp_512 -s 512 -x cp
lmbench_bw_mem $OPTS -N lmbench_cp_1k -s 1k -x cp
lmbench_bw_mem $OPTS -N lmbench_cp_2k -s 2k -x cp
lmbench_bw_mem $OPTS -N lmbench_cp_4k -s 4k -x cp
lmbench_bw_mem $OPTS -N lmbench_cp_8k -s 8k -x cp
lmbench_bw_mem $OPTS -N lmbench_cp_16k -s 16k -x cp
lmbench_bw_mem $OPTS -N lmbench_cp_32k -s 32k -x cp
lmbench_bw_mem $OPTS -N lmbench_cp_64k -s 64k -x cp
lmbench_bw_mem $OPTS -N lmbench_cp_128k -s 128k -x cp
lmbench_bw_mem $OPTS -N lmbench_cp_256k -s 256k -x cp
lmbench_bw_mem $OPTS -N lmbench_cp_512k -s 512k -x cp
lmbench_bw_mem $OPTS -N lmbench_cp_1m -s 1m -x cp
lmbench_bw_mem $OPTS -N lmbench_frd_512 -s 512 -x frd
lmbench_bw_mem $OPTS -N lmbench_frd_1k -s 1k -x frd
lmbench_bw_mem $OPTS -N lmbench_frd_2k -s 2k -x frd
lmbench_bw_mem $OPTS -N lmbench_frd_4k -s 4k -x frd
lmbench_bw_mem $OPTS -N lmbench_frd_8k -s 8k -x frd
lmbench_bw_mem $OPTS -N lmbench_frd_16k -s 16k -x frd
lmbench_bw_mem $OPTS -N lmbench_frd_32k -s 32k -x frd
lmbench_bw_mem $OPTS -N lmbench_frd_64k -s 64k -x frd
lmbench_bw_mem $OPTS -N lmbench_frd_128k -s 128k -x frd
lmbench_bw_mem $OPTS -N lmbench_frd_256k -s 256k -x frd
lmbench_bw_mem $OPTS -N lmbench_frd_512k -s 512k -x frd
lmbench_bw_mem $OPTS -N lmbench_frd_1m -s 1m -x frd
lmbench_bw_mem $OPTS -N lmbench_rd_512 -s 512 -x rd
lmbench_bw_mem $OPTS -N lmbench_rd_1k -s 1k -x rd
lmbench_bw_mem $OPTS -N lmbench_rd_2k -s 2k -x rd
lmbench_bw_mem $OPTS -N lmbench_rd_4k -s 4k -x rd
lmbench_bw_mem $OPTS -N lmbench_rd_8k -s 8k -x rd
lmbench_bw_mem $OPTS -N lmbench_rd_16k -s 16k -x rd
lmbench_bw_mem $OPTS -N lmbench_rd_32k -s 32k -x rd
lmbench_bw_mem $OPTS -N lmbench_rd_64k -s 64k -x rd
lmbench_bw_mem $OPTS -N lmbench_rd_128k -s 128k -x rd
lmbench_bw_mem $OPTS -N lmbench_rd_256k -s 256k -x rd
lmbench_bw_mem $OPTS -N lmbench_rd_512k -s 512k -x rd
lmbench_bw_mem $OPTS -N lmbench_rd_1m -s 1m -x rd
lmbench_bw_mem $OPTS -N lmbench_fwr_512 -s 512 -x fwr
lmbench_bw_mem $OPTS -N lmbench_fwr_1k -s 1k -x fwr
lmbench_bw_mem $OPTS -N lmbench_fwr_2k -s 2k -x fwr
lmbench_bw_mem $OPTS -N lmbench_fwr_4k -s 4k -x fwr
lmbench_bw_mem $OPTS -N lmbench_fwr_8k -s 8k -x fwr
lmbench_bw_mem $OPTS -N lmbench_fwr_16k -s 16k -x fwr
lmbench_bw_mem $OPTS -N lmbench_fwr_32k -s 32k -x fwr
lmbench_bw_mem $OPTS -N lmbench_fwr_64k -s 64k -x fwr
lmbench_bw_mem $OPTS -N lmbench_fwr_128k -s 128k -x fwr
lmbench_bw_mem $OPTS -N lmbench_fwr_256k -s 256k -x fwr
lmbench_bw_mem $OPTS -N lmbench_fwr_512k -s 512k -x fwr
lmbench_bw_mem $OPTS -N lmbench_fwr_1m -s 1m -x fwr
lmbench_bw_mem $OPTS -N lmbench_wr_512 -s 512 -x wr
lmbench_bw_mem $OPTS -N lmbench_wr_1k -s 1k -x wr
lmbench_bw_mem $OPTS -N lmbench_wr_2k -s 2k -x wr
lmbench_bw_mem $OPTS -N lmbench_wr_4k -s 4k -x wr
lmbench_bw_mem $OPTS -N lmbench_wr_8k -s 8k -x wr
lmbench_bw_mem $OPTS -N lmbench_wr_16k -s 16k -x wr
lmbench_bw_mem $OPTS -N lmbench_wr_32k -s 32k -x wr
lmbench_bw_mem $OPTS -N lmbench_wr_64k -s 64k -x wr
lmbench_bw_mem $OPTS -N lmbench_wr_128k -s 128k -x wr
lmbench_bw_mem $OPTS -N lmbench_wr_256k -s 256k -x wr
lmbench_bw_mem $OPTS -N lmbench_wr_512k -s 512k -x wr
lmbench_bw_mem $OPTS -N lmbench_wr_1m -s 1m -x wr
lmbench_bw_mem $OPTS -N lmbench_rdwr_512 -s 512 -x rdwr
lmbench_bw_mem $OPTS -N lmbench_rdwr_1k -s 1k -x rdwr
lmbench_bw_mem $OPTS -N lmbench_rdwr_2k -s 2k -x rdwr
lmbench_bw_mem $OPTS -N lmbench_rdwr_4k -s 4k -x rdwr
lmbench_bw_mem $OPTS -N lmbench_rdwr_8k -s 8k -x rdwr
lmbench_bw_mem $OPTS -N lmbench_rdwr_16k -s 16k -x rdwr
lmbench_bw_mem $OPTS -N lmbench_rdwr_32k -s 32k -x rdwr
lmbench_bw_mem $OPTS -N lmbench_rdwr_64k -s 64k -x rdwr
lmbench_bw_mem $OPTS -N lmbench_rdwr_128k -s 128k -x rdwr
lmbench_bw_mem $OPTS -N lmbench_rdwr_256k -s 256k -x rdwr
lmbench_bw_mem $OPTS -N lmbench_rdwr_512k -s 512k -x rdwr
lmbench_bw_mem $OPTS -N lmbench_rdwr_1m -s 1m -x rdwr

lmbench_bw_mmap_rd $OPTS -N bw_mmap_rd_512 -s 512 -f $TFILE
lmbench_bw_mmap_rd $OPTS -N bw_mmap_rd_1k -s 1k -f $TFILE
lmbench_bw_mmap_rd $OPTS -N bw_mmap_rd_2k -s 2k -f $TFILE
lmbench_bw_mmap_rd $OPTS -N bw_mmap_rd_4k -s 4k -f $TFILE
lmbench_bw_mmap_rd $OPTS -N bw_mmap_rd_8k -s 8k -f $TFILE
lmbench_bw_mmap_rd $OPTS -N bw_mmap_rd_16k -s 16k -f $TFILE
lmbench_bw_mmap_rd $OPTS -N bw_mmap_rd_32k -s 32k -f $TFILE
lmbench_bw_mmap_rd $OPTS -N bw_mmap_rd_64k -s 64k -f $TFILE
lmbench_bw_mmap_rd $OPTS -N bw_mmap_rd_128k -s 128k -f $TFILE
lmbench_bw_mmap_rd $OPTS -N bw_mmap_rd_256k -s 256k -f $TFILE
lmbench_bw_mmap_rd $OPTS -N bw_mmap_rd_512k -s 512k -f $TFILE
lmbench_bw_mmap_rd $OPTS -N bw_mmap_rd_1m -s 1m -f $TFILE

.
