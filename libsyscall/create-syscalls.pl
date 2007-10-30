#!/usr/bin/perl
#
# Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
#
# @APPLE_OSREFERENCE_LICENSE_HEADER_START@
# 
# This file contains Original Code and/or Modifications of Original Code
# as defined in and that are subject to the Apple Public Source License
# Version 2.0 (the 'License'). You may not use this file except in
# compliance with the License. Please obtain a copy of the License at
# http://www.opensource.apple.com/apsl/ and read it before using this
# file.
# 
# The Original Code and all software distributed under the License are
# distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
# EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
# INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
# Please see the License for the specific language governing rights and
# limitations under the License.
# 
# @APPLE_OSREFERENCE_LICENSE_HEADER_END@
#
##########################################################################
#
# % create-syscalls.pl syscalls.master custom-directory out-directory
#
# This script fills the the out-directory with a Makefile.inc and *.s
# files to create the double-underbar syscall stubs.  It reads the
# syscall.master file to get the symbol names and number of arguments,
# and whether Libsystem should automatically create the (non-double-underbar)
# stubs if Libc doesn't provide a wrapper.  Which system calls will get
# the automatic treatment is writen to the libsyscall.list file, also
# written to the out-directory.
#
# The custom-directory contains:
# 1. SYS.h - used by the automatically created *.s and custom files
# 2. custom.s - contains architecture specific additional system calls and
#    auxilliary routines (like cerror)
# 3. special case double-underbar stub files - which are copied into
#    the out-directory
#
# The BSDmakefile copies /usr/include/architecture/ppc/emode_independent_asm.h
# and /usr/include/architecture/i386/asm_help.h to $(OBJDIR)/include,
# replacing .globl with .private_extern.  These headers, along with SYS.h
# make the double-underbar syscall stub private_extern, so that then become
# static in the resulting libSystem.dylib.
#
##########################################################################

use strict;
use File::Basename ();
use File::Copy ();
use File::Spec;
use IO::File;

my $MyName = File::Basename::basename($0);

my @CustomSrc = qw(custom.s);

my @Copy = (qw(SYS.h), @CustomSrc);
my $CustomDir;
my %NoStub;
my $OutDir;
my %Stub = (
    quota => [4, 0],	# unimplemented
    setquota => [2, 0],	# unimplemented
    syscall => [0, 0],	# custom/__syscall.s will be used
);
my $StubFile = 'libsyscall.list';
# size in bytes of known types (only used for i386)
my %TypeBytes = (
    'caddr_t'		=> 4,
    'gid_t'		=> 4,
    'id_t'		=> 4,
    'idtype_t'		=> 4,
    'int'		=> 4,
    'int32_t'		=> 4,
    'int64_t'		=> 8,
    'key_t'		=> 4,
    'long'		=> 4,
    'mode_t'		=> 4,
    'off_t'		=> 8,
    'pid_t'		=> 4,
    'semun_t'		=> 4,
    'sigset_t'		=> 4,
    'size_t'		=> 4,
    'socklen_t'		=> 4,
    'ssize_t'		=> 4,
    'time_t'		=> 4,
    'u_int'		=> 4,
    'u_long'		=> 4,
    'uid_t'		=> 4,
    'uint32_t'		=> 4,
    'uint64_t'		=> 8,
    'user_addr_t'	=> 4,
    'user_long_t'	=> 4,
    'user_size_t'	=> 4,
    'user_ssize_t'	=> 4,
    'user_ulong_t'	=> 4,
);

##########################################################################
# Make a __xxx.s file: if it exists in the $CustomDir, just copy it, otherwise
# create one.  We define the macro __SYSCALL_I386_ARG_BYTES so that SYS.h could
# use that to define __SYSCALL dependent on the arguments' total size.
##########################################################################
sub make_s {
    my($name, $args, $bytes) = @_;
    local $_;
    my $pseudo = $name;
    $pseudo = '__' . $pseudo unless $pseudo =~ /^__/;
    my $file = $pseudo . '.s';
    my $custom = File::Spec->join($CustomDir, $file);
    my $path = File::Spec->join($OutDir, $file);
    if(-f $custom) {
	File::Copy::copy($custom, $path) || die "$MyName: copy($custom, $path): $!\n";
	print "Copying $path\n";
    } else {
	my $f = IO::File->new($path, 'w');
	die "$MyName: $path: $!\n" unless defined($f);
	print $f "#define __SYSCALL_I386_ARG_BYTES $bytes\n\n";
	print $f "#include \"SYS.h\"\n\n";
	print $f "__SYSCALL($pseudo, $name, $args)\n";
	print "Creating $path\n";
    }
    return $file;
}

sub usage {
    die "Usage: $MyName syscalls.master custom-directory out-directory\n";
}

##########################################################################
# Read the syscall.master file and collect the system call names and number
# of arguments.  It looks for the NO_SYSCALL_STUB quailifier following the
# prototype to determine if no automatic stub should be created by Libsystem.
# System call name that are already prefixed with double-underbar are set as
# if the NO_SYSCALL_STUB qualifier were specified (whether it is or not).
#
# For the #if lines in syscall.master, all macros are assumed to be defined,
# except COMPAT_GETFSSTAT (assumed undefined).
##########################################################################
sub readmaster {
    my $file = shift;
    local $_;
    my $f = IO::File->new($file, 'r');
    die "$MyName: $file: $!\n" unless defined($f);
    my $line = 0;
    my $skip = 0;
    while(<$f>) {
	$line++;
	if(/^#\s*endif/) {
	    $skip = 0;
	    next;
	}
	if(/^#\s*else/) {
	    $skip = -$skip;
	    next;
	}
	chomp;
	if(/^#\s*if\s+(\S+)$/) {
	    $skip = ($1 eq 'COMPAT_GETFSSTAT') ? -1 : 1;
	    next;
	}
	next if $skip < 0;
	next unless /^\d/;
	s/^[^{]*{\s*//;
	s/\s*}.*$//; # }
	die "$MyName: no function prototype on line $line\n" unless length($_) > 0 && /;$/;
	my $no_syscall_stub = /\)\s*NO_SYSCALL_STUB\s*;/;
	my($name, $args) = /\s(\S+)\s*\(([^)]*)\)/;
	next if $name =~ /e?nosys/;
	$args =~ s/^\s+//;
	$args =~ s/\s+$//;
	my $argbytes = 0;
	my $nargs = 0;
	if($args ne '' && $args ne 'void') {
	    my @a = split(',', $args);
	    $nargs = scalar(@a);
	    # Calculate the size of all the arguments (only used for i386)
	    for my $type (@a) {
		$type =~ s/\s*\w+$//; # remove the argument name
		if($type =~ /\*$/) {
		    $argbytes += 4; # a pointer type
		} else {
		    $type =~ s/^.*\s//; # remove any type qualifier, like unsigned
		    my $b = $TypeBytes{$type};
		    die "$MyName: $name: unknown type '$type'\n" unless defined($b);
		    $argbytes += $b;
		}
	    }
	}
	if($no_syscall_stub || $name =~ /^__/) {
	    $NoStub{$name} = [$nargs, $argbytes];
	} else {
	    $Stub{$name} = [$nargs, $argbytes];
	}
    }
}

usage() unless scalar(@ARGV) == 3;
$CustomDir = $ARGV[1];
die "$MyName: $CustomDir: No such directory\n" unless -d $CustomDir;
$OutDir = $ARGV[2];
die "$MyName: $OutDir: No such directory\n" unless -d $OutDir;

readmaster($ARGV[0]);

##########################################################################
# copy the files specified in @Copy from the $CustomDir to $OutDir
##########################################################################
for(@Copy) {
    my $custom = File::Spec->join($CustomDir, $_);
    my $path = File::Spec->join($OutDir, $_);
    File::Copy::copy($custom, $path) || die "$MyName: copy($custom, $path): $!\n";
}

##########################################################################
# make all the *.s files
##########################################################################
my @src;
my($k, $v);
while(($k, $v) = each(%Stub)) {
    push(@src, make_s($k, @$v));
}
while(($k, $v) = each(%NoStub)) {
    push(@src, make_s($k, @$v));
}

##########################################################################
# create the Makefile.inc file from the list for files in @src and @CustomSrc
##########################################################################
my $path = File::Spec->join($OutDir, 'Makefile.inc');
my $f = IO::File->new($path, 'w');
die "$MyName: $path: $!\n" unless defined($f);
print $f ".PATH: $OutDir\n\n";
print $f "SYSCALLSRCS= " . join(" \\\n\t", sort(@src, @CustomSrc)) . "\n\n";
print $f "MDSRCS+= \$(SYSCALLSRCS)\n\n";
print $f ".for S in \$(SYSCALLSRCS)\n";
print $f "PRECFLAGS-\$(S)+= -I\$(OBJROOT)/include\n";
print $f ".endfor\n";
undef $f;

##########################################################################
# create the libsyscall.list file for Libsystem to use.  For the one that
# should not have auto-generated stubs, the line begins with #.
##########################################################################
$path = File::Spec->join($OutDir, $StubFile);
$f = IO::File->new($path, 'w');
die "$MyName: $path: $!\n" unless defined($f);
# Add the %NoStub entries to %Stub, appending '#' to the name, so we can sort
while(($k, $v) = each(%NoStub)) {
    $k =~ s/^__//;
    $Stub{"$k#"} = $v;
}
for(sort(keys(%Stub))) {
    $k = $_;
    if($k =~ s/#$//) {
	printf $f "#___%s\t%s\n", $k, $Stub{$_}->[0];
    } else {
	printf $f "___%s\t%s\n", $_, $Stub{$_}->[0];
    }
}
undef $f;
