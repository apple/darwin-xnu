#!/bin/csh -f
set path = ($path .)
######################################################################
# HISTORY
#  1-Dec-87  Michael Young (mwyoung) at Carnegie-Mellon University
#	Added "-verbose" switch, so this script produces no output
#	in the normal case.
#
# 10-Oct-87  Mike Accetta (mja) at Carnegie-Mellon University
#	Flushed cmu_*.h and spin_locks.h
#	[ V5.1(XF18) ]
#
#  6-Apr-87  Avadis Tevanian (avie) at Carnegie-Mellon University
#	Use MASTER.local and MASTER.<machine>.local for generation of
#	configuration files in addition to MASTER and MASTER.<machine>.
#
# 25-Mar-87  Mike Accetta (mja) at Carnegie-Mellon University
#	Removed use of obsolete wb_*.h files when building the feature
#	list;  modified to save the previous configuration file and
#	display the differences between it and the new file.
#	[ V5.1(F8) ]
#
# 25-Mar-87  Avadis Tevanian (avie) at Carnegie-Mellon University
#	If there is no /etc/machine just print out a message telling
#	user to use the -cpu option.  I thought this script was supposed
#	to work even without a /etc/machine, but it doesn't... and this
#	is the easiest way out.
#
# 13-Mar-87  Mike Accetta (mja) at Carnegie-Mellon University
#	Added "romp_fpa.h" file to extra features for the RT.
#	[ V5.1(F7) ]
#
# 11-Mar-87  Mike Accetta (mja) at Carnegie-Mellon University
#	Updated to maintain the appropriate configuration features file
#	in the "machine" directory whenever the corresponding
#	configuration is generated.  This replaces the old mechanism of
#	storing this directly in the <sys/features.h> file since it was
#	machine dependent and also precluded building programs for more
#	than one configuration from the same set of sources.
#	[ V5.1(F6) ]
#
# 21-Feb-87  Mike Accetta (mja) at Carnegie-Mellon University
#	Fixed to require wired-in cpu type names for only those
#	machines where the kernel name differs from that provided by
#	/etc/machine (i.e. IBMRT => ca and SUN => sun3);  updated to
#	permit configuration descriptions in both machine indepedent
#	and dependent master configuration files so that attributes can
#	be grouped accordingly.
#	[ V5.1(F3) ]
#
# 17-Jan-87  Mike Accetta (mja) at Carnegie-Mellon University
#	Updated to work from any directory at the same level as
#	"conf"; generate configuration from both MASTER and
#	MASTER.<machine-type> files; added -cpu switch.
#	[ V5.1(F1) ]
#
# 18-Aug-86  Mike Accetta (mja) at Carnegie-Mellon University
#	Added -make switch and changed meaning of -config;  upgraded to
#	allow multiple attributes per configuration and to define
#	configurations in terms of these attributes within MASTER.
#
# 14-Apr-83  Mike Accetta (mja) at Carnegie-Mellon University
#	Added -config switch to only run /etc/config without 
#	"make depend" and "make".
#
######################################################################

set prog=$0
set prog=$prog:t
set nonomatch
set OBJDIR=../BUILD
if ("`/usr/bin/uname`" == "Rhapsody" ) then
set CONFIG_DIR=/usr/local/bin
else
set CONFIG_DIR=/usr/bin
endif

unset domake
unset doconfig
unset beverbose
unset MACHINE
unset profile

while ($#argv >= 1)
    if ("$argv[1]" =~ -*) then
        switch ("$argv[1]")
	case "-c":
	case "-config":
	    set doconfig
	    breaksw
	case "-m":
	case "-make":
	    set domake
	    breaksw
	case "-cpu":
	    if ($#argv < 2) then
		echo "${prog}: missing argument to ${argv[1]}"
		exit 1
	    endif
	    set MACHINE="$argv[2]"
	    shift
	    breaksw
	case "-d":
	    if ($#argv < 2) then
		echo "${prog}: missing argument to ${argv[1]}"
		exit 1
	    endif
	    set OBJDIR="$argv[2]"
	    shift
	    breaksw
	case "-verbose":
	    set beverbose
	    breaksw
	case "-p":
	case "-profile":
	    set profile
	    breaksw
	default:
	    echo "${prog}: ${argv[1]}: unknown switch"
	    exit 1
	    breaksw
	endsw
	shift
    else
	break
    endif
end

if ($#argv == 0) set argv=(GENERIC)

if (! $?MACHINE) then
    if (-d /NextApps) then
	set MACHINE=`hostinfo | awk '/MC680x0/ { printf("m68k") } /MC880x0/ { printf("m88k") }'`
    endif
endif

if (! $?MACHINE) then
    if (-f /etc/machine) then
	    set MACHINE="`/etc/machine`"
    else
	    echo "${prog}: no /etc/machine, specify machine type with -cpu"
	    echo "${prog}: e.g. ${prog} -cpu VAX CONFIGURATION"
	    exit 1
    endif
endif

set FEATURES_EXTRA=

switch ("$MACHINE")
    case IBMRT:
	set cpu=ca
	set ID=RT
	set FEATURES_EXTRA="romp_dualcall.h romp_fpa.h"
	breaksw
    case SUN:
	set cpu=sun3
	set ID=SUN3
	breaksw
    default:
	set cpu=`echo $MACHINE | tr A-Z a-z`
	set ID=`echo $MACHINE | tr a-z A-Z`
	breaksw
endsw
set FEATURES=../h/features.h
set FEATURES_H=(cs_*.h mach_*.h net_*.h\
	        cputypes.h cpus.h vice.h\
	        $FEATURES_EXTRA)
set MASTER_DIR=../conf
set MASTER =   ${MASTER_DIR}/MASTER
set MASTER_CPU=${MASTER}.${cpu}

set MASTER_LOCAL = ${MASTER}.local
set MASTER_CPU_LOCAL = ${MASTER_CPU}.local
if (! -f $MASTER_LOCAL) set MASTER_LOCAL = ""
if (! -f $MASTER_CPU_LOCAL) set MASTER_CPU_LOCAL = ""

if (! -d $OBJDIR) then
    echo "[ creating $OBJDIR ]"
    mkdir -p $OBJDIR
endif

foreach SYS ($argv)
    set SYSID=${SYS}_${ID}
    set SYSCONF=$OBJDIR/config.$SYSID
    set BLDDIR=$OBJDIR
    if ($?beverbose) then
	echo "[ generating $SYSID from $MASTER_DIR/MASTER{,.$cpu}{,.local} ]"
    endif
    echo +$SYS \
    | \
    cat $MASTER $MASTER_LOCAL $MASTER_CPU $MASTER_CPU_LOCAL - \
        $MASTER $MASTER_LOCAL $MASTER_CPU $MASTER_CPU_LOCAL \
    | \
    sed -n \
	-e "/^+/{" \
	   -e "s;[-+];#&;gp" \
	      -e 't loop' \
	   -e ': loop' \
           -e 'n' \
	   -e '/^#/b loop' \
	   -e '/^$/b loop' \
	   -e 's;^\([^#]*\).*#[ 	]*<\(.*\)>[ 	]*$;\2#\1;' \
	      -e 't not' \
	   -e 's;\([^#]*\).*;#\1;' \
	      -e 't not' \
	   -e ': not' \
	   -e 's;[ 	]*$;;' \
	   -e 's;^\!\(.*\);\1#\!;' \
	   -e 'p' \
	      -e 't loop' \
           -e 'b loop' \
	-e '}' \
	-e "/^[^#]/d" \
	-e 's;	; ;g' \
	-e "s;^# *\([^ ]*\)[ ]*=[ ]*\[\(.*\)\].*;\1#\2;p" \
    | \
    awk '-F#' '\
part == 0 && $1 != "" {\
	m[$1]=m[$1] " " $2;\
	next;\
}\
part == 0 && $1 == "" {\
	for (i=NF;i>1;i--){\
		s=substr($i,2);\
		c[++na]=substr($i,1,1);\
		a[na]=s;\
	}\
	while (na > 0){\
		s=a[na];\
		d=c[na--];\
		if (m[s] == "") {\
			f[s]=d;\
		} else {\
			nx=split(m[s],x," ");\
			for (j=nx;j>0;j--) {\
				z=x[j];\
				a[++na]=z;\
				c[na]=d;\
			}\
		}\
	}\
	part=1;\
	next;\
}\
part != 0 {\
	if ($1 != "") {\
		n=split($1,x,",");\
		ok=0;\
		for (i=1;i<=n;i++) {\
			if (f[x[i]] == "+") {\
				ok=1;\
			}\
		}\
		if (NF > 2 && ok == 0 || NF <= 2 && ok != 0) {\
			print $2; \
		}\
	} else { \
		print $2; \
	}\
}\
' >$SYSCONF.new
    if (-z $SYSCONF.new) then
	echo "${prog}: ${$SYSID}: no such configuration in $MASTER_DIR/MASTER{,.$cpu}"
	rm -f $SYSCONF.new
    endif
    if (! -d $BLDDIR) then
	echo "[ creating $BLDDIR ]"
	mkdir -p $BLDDIR
    endif
#
# These paths are used by config.
#
# "builddir" is the name of the directory where kernel binaries
# are put.  It is a single path element, never absolute, and is
# always relative to "objectdir".  "builddir" is used by config
# solely to determine where to put files created by "config" (e.g.
# the created Makefile and *.h's.)
#
# "objectdir" is the name of the directory which will hold "builddir".
# It is a path; if relative, it is relative to the current directory
# where config is run.  It's sole use is to be prepended to "builddir"
# to indicate where config-created files are to be placed (see above).
#
# "sourcedir" is the location of the sources used to build the kernel.
# It is a path; if relative, it is relative to the directory specified
# by the concatenation of "objectdir" and "builddir" (i.e. where the
# kernel binaries are put).
#
    echo 'builddir	"."'			>> $SYSCONF.new
    set OBJRELDIR=`$RELPATH $OBJROOT $OBJDIR`
    echo 'objectdir	"'$OBJROOT'/'$OBJRELDIR'"'		>> $SYSCONF.new
    set SRCDIR=`dirname $SOURCE`
    echo 'sourcedir	"'$SRCROOT'"'		>> $SYSCONF.new
    if (-f $SYSCONF) then
	diff $SYSCONF $SYSCONF.new
	rm -f $SYSCONF.old
	mv $SYSCONF $SYSCONF.old
    endif
    rm -f $SYSCONF
    mv $SYSCONF.new $SYSCONF
    if ($?doconfig) then
	echo "[ configuring $SYSID ]"
	if ($?profile) then
	    $CONFIG_DIR/config -c $MASTER_DIR -p $SYSCONF
	else
	    $CONFIG_DIR/config -c $MASTER_DIR $SYSCONF
	endif
    endif
    if ($?domake) then
        echo "[ making $SYSID ]"
        (cd $BLDDIR; make)
    endif
end
