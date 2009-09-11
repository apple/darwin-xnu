#!/usr/bin/perl
# Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
#
# @APPLE_LICENSE_HEADER_START@
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
# @APPLE_LICENSE_HEADER_END@

use strict;
use File::Basename ();
use File::Find ();
use Getopt::Std ();

my $MyName = File::Basename::basename($0);
my $N = 100;
my $MinSize = 64;
my %inodes;
my @symlinks;
our $opt_d = '';

sub wanted {
    return unless /\.[\dn][a-z]*$/;
    if(-l $_) {
	push(@symlinks, $_);
    } elsif(-f _) {
	return if -s _ < $MinSize;
	my($dev, $ino) = stat(_);
	my $list = $inodes{$ino};
	$list = $inodes{$ino} = [] unless defined($list);
	push(@$list, $_);
    }
}

sub usage {
    die "Usage: $MyName [-d prefix] dir ...\n";
}

Getopt::Std::getopts('d:');
usage() unless scalar(@ARGV) > 0;

for my $dir (@ARGV) {
    $dir = $opt_d . $dir if $opt_d ne '';
    next unless -e $dir;
    die "$dir: no such directory\n" unless -d _;

    %inodes = ();
    @symlinks = ();
    File::Find::find({
	wanted => \&wanted,
	no_chdir => 1,
    }, $dir);

    my(@compress, @links);
    for(values(%inodes)) {
	push(@compress, $_->[0]);
	push(@links, $_) if scalar(@$_) > 1;
    }

    my $count;
    while(($count = scalar(@compress)) > 0) {
	$_ = $count > $N ? $N : $count;
	my @args = splice(@compress, 0, $_);
	print "gzip -f -n @args\n";
	system('gzip', '-f', '-n', @args) == 0 or die "gzip failed\n";;
    }
    foreach my $list (@links) {
	my $main = shift(@$list);
	for(@$list) {
	    printf "rm $_; ln $main.gz $_.gz\n";
	    unlink $_ or die "Can't unlink: $!\n";
	    unlink "$_.gz";
	    link("$main.gz", "$_.gz") or die "Can't link: $!\n";;
	}
    }
    for(@symlinks) {
	my $link = readlink($_);
	printf "rm $_; ln -s $link.gz $_.gz\n";
	unlink $_ or die "Can't unlink: $!\n";
	symlink("$link.gz", "$_.gz") or die "Can't symlink: $!\n";
    }
}
