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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include ../Makefile.benchmarks

EXTRA_CFILES= \
		exec_bin.c 	\
		elided.c	\
		tattle.c

#
# some definitions to make getting compiler versions possible - avoid quotes
#
COMPILER_VERSION_CMD_cc=cc -V 2>&1 | egrep Sun
COMPILER_VERSION_CMD_gcc=gcc -dumpversion
COMPILER_VERSION_CMD=$(COMPILER_VERSION_CMD_$(CC))

default: $(ALL) tattle

cstyle:	
	for file in $(ALL:%=../%.c) $(EXTRA_CFILES:%=../%) ; \
	do cstyle -p $$file ;\
	done


lint:	libmicro.ln $(ALL:%=%.lint) $(EXTRA_CFILES:%.c=%.lint)


$(EXTRA_CFILES:%.c=%.lint):
	$(LINT) ../$(@:%.lint=%.c) -I. -mu -lc libmicro.ln -lm

%.lint:	../%.c libmicro.ln
	$(LINT) -mu $(CPPFLAGS) $< libmicro.ln -lpthread -lsocket -lnsl -lm

%.o:	../%.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

libmicro.ln: ../libmicro.c ../libmicro_main.c ../libmicro.h ../benchmark_*.c
	$(LINT) -muc $(CPPFLAGS) ../libmicro.c ../libmicro_main.c ../benchmark_*.c

CPPFLAGS+= -D_REENTRANT

bind_EXTRA_LIBS=$(NSLLIB) $(SOCKLIB)
cascade_flock_EXTRA_LIBS=$(UCBLIB)
close_tcp_EXTRA_LIBS=$(NSLLIB) $(SOCKLIB)
connection_EXTRA_LIBS=$(NSLLIB) $(SOCKLIB)
fcntl_ndelay_EXTRA_LIBS=$(SOCKLIB)
getpeername_EXTRA_LIBS=$(NSLLIB) $(SOCKLIB)
getsockname_EXTRA_LIBS=$(NSLLIB) $(SOCKLIB)
listen_EXTRA_LIBS=$(NSLLIB) $(SOCKLIB)
log_EXTRA_LIBS=$(MATHLIB)
pipe_EXTRA_LIBS=$(NSLLIB) $(SOCKLIB)
poll_EXTRA_LIBS=$(SOCKLIB)
select_EXTRA_LIBS=$(SOCKLIB)
setsockopt_EXTRA_LIBS=$(NSLLIB) $(SOCKLIB)
socket_EXTRA_LIBS=$(SOCKLIB)
socketpair_EXTRA_LIBS=$(SOCKLIB)

BENCHMARK_FUNCS=		\
	benchmark_init.o	\
	benchmark_fini.o	\
	benchmark_initrun.o	\
	benchmark_finirun.o	\
	benchmark_initbatch.o	\
	benchmark_finibatch.o	\
	benchmark_initworker.o	\
	benchmark_finiworker.o	\
	benchmark_optswitch.o	\
	benchmark_result.o

recurse_EXTRA_DEPS=recurse2.o


recurse:	$(recurse_EXTRA_DEPS)

libmicro.a:	libmicro.o libmicro_main.o $(BENCHMARK_FUNCS)
		$(AR) -cr libmicro.a libmicro.o libmicro_main.o $(BENCHMARK_FUNCS)

tattle:		../tattle.c	libmicro.a
	echo "char * compiler_version = \""`$(COMPILER_VERSION_CMD)`"\";" > tattle.h
	echo "char * CC = \""$(CC)"\";" >> tattle.h
	echo "char * extra_compiler_flags = \""$(extra_CFLAGS)"\";" >> tattle.h
	$(CC) -o tattle $(CFLAGS) -I. ../tattle.c libmicro.a -lrt -lm
	cp tattle ../tattle

$(ELIDED_BENCHMARKS):	../elided.c
	$(CC) -o $(@) ../elided.c

%: libmicro.a %.o 
	$(CC) -o $(@) $(@).o $($(@)_EXTRA_DEPS) $(CFLAGS) libmicro.a $($(@)_EXTRA_LIBS) $(EXTRA_LIBS) -lpthread -lm

exec:	exec_bin

exec_bin:	exec_bin.o
	$(CC) -o exec_bin $(CFLAGS) exec_bin.o

FORCE:


._KEEP_STATE:

