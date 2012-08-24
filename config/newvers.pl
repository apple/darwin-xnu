#!/usr/bin/perl
#
# This tool is used to stamp kernel version information into files at kernel
# build time.  Each argument provided on the command line is the path to a file
# that needs to be updated with the current verison information.  The file
# xnu/config/MasterVersion is read to determine the version number to use.
# Each file is read, and all occurrences of the following strings are replaced
# in-place like so:
#   ###KERNEL_VERSION_LONG###               1.2.3b4
#   ###KERNEL_VERSION_SHORT###              1.2.3
#   ###KERNEL_VERSION_MAJOR###              1
#   ###KERNEL_VERSION_MINOR###              2
#   ###KERNEL_VERSION_VARIANT###            3b4
#   ###KERNEL_VERSION_REVISION###           3
#   ###KERNEL_VERSION_STAGE###              VERSION_STAGE_BETA	(see libkern/version.h)
#   ###KERNEL_VERSION_PRERELEASE_LEVEL###   4
#   ###KERNEL_BUILDER###                    root
#   ###KERNEL_BUILD_OBJROOT###              xnu/xnu-690.obj~2/RELEASE_PPC
#   ###KERNEL_BUILD_DATE###                 Sun Oct 24 05:33:28 PDT 2004

use File::Basename;

use strict;

sub ReadFile {
  my ($fileName) = @_;
  my $data;
  local $/ = undef;   # Read complete files

  if (open(IN, "<$fileName")) {
    $data=<IN>;
    close IN;
    return $data;
  }
  die "newvers: Can't read file \"$fileName\"\n";
}

sub WriteFile {
  my ($fileName, $data) = @_;

  open (OUT, ">$fileName") or die "newvers: Can't write file \"$fileName\"\n";
  print OUT  $data;
  close(OUT);
}

die("SRCROOT not defined") unless defined($ENV{'SRCROOT'});
die("OBJROOT not defined") unless defined($ENV{'OBJROOT'});

my $versfile = "MasterVersion";
$versfile = "$ENV{'SRCROOT'}/config/$versfile";
my $BUILD_SRCROOT=$ENV{'SRCROOT'};
$BUILD_SRCROOT =~ s,/+$,,;
my $BUILD_OBJROOT=$ENV{'OBJROOT'};
$BUILD_OBJROOT =~ s,/+$,,;
my $BUILD_OBJPATH=$ENV{'OBJPATH'} || $ENV{'OBJROOT'};
$BUILD_OBJPATH =~ s,/+$,,;
my $BUILD_DATE = `date`;
$BUILD_DATE =~ s/[\n\t]//g;
my $BUILDER=`whoami`;
$BUILDER =~ s/[\n\t]//g;

# Handle two scenarios:
# SRCROOT=/tmp/xnu
# OBJROOT=/tmp/xnu/BUILD/obj
# OBJPATH=/tmp/xnu/BUILD/obj/RELEASE_X86_64
#
# SRCROOT=/SourceCache/xnu/xnu-1234
# OBJROOT=/tmp/xnu/xnu-1234~1.obj
# OBJPATH=/tmp/xnu/xnu-1234~1.obj/RELEASE_X86_64
#
# If SRCROOT is a strict prefix of OBJPATH, we
# want to preserve the "interesting" part
# starting with "xnu". If it's not a prefix,
# the basename of OBJROOT itself is "interesting".

if ($BUILD_OBJPATH =~ m,^$BUILD_SRCROOT/(.*)$,) {
    $BUILD_OBJROOT = basename($BUILD_SRCROOT) . "/" . $1;
} elsif ($BUILD_OBJPATH =~ m,^$BUILD_OBJROOT/(.*)$,) {
    $BUILD_OBJROOT = basename($BUILD_OBJROOT) . "/" . $1;
} else {
    # Use original OBJROOT
}

my $rawvers = &ReadFile($versfile);
#$rawvers =~ s/\s//g;
($rawvers) = split "\n", $rawvers;
my ($VERSION_MAJOR, $VERSION_MINOR, $VERSION_VARIANT) = split /\./, $rawvers;
die "newvers: Invalid MasterVersion \"$rawvers\"!!! " if (!$VERSION_MAJOR);
$VERSION_MINOR = "0" unless ($VERSION_MINOR);
$VERSION_VARIANT = "0" unless ($VERSION_VARIANT);
$VERSION_VARIANT =~ tr/A-Z/a-z/;
$VERSION_VARIANT =~ m/(\d+)((?:d|a|b|r|fc)?)(\d*)/;
my $VERSION_REVISION = $1;
my $stage = $2;
my $VERSION_PRERELEASE_LEVEL = $3;
$VERSION_REVISION ="0" unless ($VERSION_REVISION);
$stage = "r" if (!$stage || ($stage eq "fc"));
$VERSION_PRERELEASE_LEVEL = "0" unless ($VERSION_PRERELEASE_LEVEL);

my $VERSION_STAGE;
$VERSION_STAGE = 'VERSION_STAGE_DEV'     if ($stage eq 'd');
$VERSION_STAGE = 'VERSION_STAGE_ALPHA'   if ($stage eq 'a');
$VERSION_STAGE = 'VERSION_STAGE_BETA'    if ($stage eq 'b');
$VERSION_STAGE = 'VERSION_STAGE_RELEASE' if ($stage eq 'r');

my $VERSION_SHORT = "$VERSION_MAJOR.$VERSION_MINOR.$VERSION_REVISION";
my $VERSION_LONG = $VERSION_SHORT;
$VERSION_LONG .= "$stage$VERSION_PRERELEASE_LEVEL" if (($stage ne "r") || ($VERSION_PRERELEASE_LEVEL != 0));

my $file;
foreach $file (@ARGV) {
  print "newvers.pl: Stamping version \"$VERSION_LONG\" into \"$file\" ...";
  my $data = &ReadFile($file);
  my $count=0;
  $count += $data =~ s/###KERNEL_VERSION_LONG###/$VERSION_LONG/g;
  $count += $data =~ s/###KERNEL_VERSION_SHORT###/$VERSION_SHORT/g;
  $count += $data =~ s/###KERNEL_VERSION_MAJOR###/$VERSION_MAJOR/g;
  $count += $data =~ s/###KERNEL_VERSION_MINOR###/$VERSION_MINOR/g;
  $count += $data =~ s/###KERNEL_VERSION_VARIANT###/$VERSION_VARIANT/g;
  $count += $data =~ s/###KERNEL_VERSION_REVISION###/$VERSION_REVISION/g;
  $count += $data =~ s/###KERNEL_VERSION_STAGE###/$VERSION_STAGE/g;
  $count += $data =~ s/###KERNEL_VERSION_PRERELEASE_LEVEL###/$VERSION_PRERELEASE_LEVEL/g;
  $count += $data =~ s/###KERNEL_BUILDER###/$BUILDER/g;
  $count += $data =~ s/###KERNEL_BUILD_OBJROOT###/$BUILD_OBJROOT/g;
  $count += $data =~ s/###KERNEL_BUILD_DATE###/$BUILD_DATE/g;
  print " $count replacements\n";
  &WriteFile($file, $data);
}

if (0==scalar @ARGV) {
  print "newvers.pl: read version \"$rawvers\" from \"$versfile\"\n";
  print "newvers.pl: ###KERNEL_VERSION_LONG### = $VERSION_LONG\n";
  print "newvers.pl: ###KERNEL_VERSION_SHORT### = $VERSION_SHORT\n";
  print "newvers.pl: ###KERNEL_VERSION_MAJOR### = $VERSION_MAJOR\n";
  print "newvers.pl: ###KERNEL_VERSION_MINOR### = $VERSION_MINOR\n";
  print "newvers.pl: ###KERNEL_VERSION_VARIANT### = $VERSION_VARIANT\n";
  print "newvers.pl: ###KERNEL_VERSION_REVISION### = $VERSION_REVISION\n";
  print "newvers.pl: ###KERNEL_VERSION_STAGE### = $VERSION_STAGE\n";
  print "newvers.pl: ###KERNEL_VERSION_PRERELEASE_LEVEL### = $VERSION_PRERELEASE_LEVEL\n";
  print "newvers.pl: ###KERNEL_BUILDER### = $BUILDER\n";
  print "newvers.pl: ###KERNEL_BUILD_OBJROOT### = $BUILD_OBJROOT\n";
  print "newvers.pl: ###KERNEL_BUILD_DATE### = $BUILD_DATE\n";
}
