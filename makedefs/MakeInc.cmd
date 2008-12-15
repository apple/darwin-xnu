#
# Commands for the build environment
#
MIG =  $(NEXT_ROOT)/usr/bin/mig

MD=     /usr/bin/md

RM = /bin/rm -f
CP = /bin/cp
LN = /bin/ln -fs
CAT = /bin/cat
MKDIR = /bin/mkdir -p
FIND = /usr/bin/find
INSTALL = /usr/bin/install

TAR = /usr/bin/gnutar
STRIP = /usr/bin/strip
LIPO = /usr/bin/lipo

BASENAME = /usr/bin/basename
export RELPATH = $(NEXT_ROOT)/usr/local/bin/relpath
TR = /usr/bin/tr
SEG_HACK = $(NEXT_ROOT)/usr/local/bin/seg_hack

UNIFDEF   = /usr/bin/unifdef
DECOMMENT = /usr/local/bin/decomment

DSYMUTIL = /usr/bin/dsymutil
CTFCONVERT = /usr/local/bin/ctfconvert
CTFMERGE = /usr/local/bin/ctfmerge
CTFSCRUB = /usr/local/bin/ctfdump -r

# vim: set ft=make:
