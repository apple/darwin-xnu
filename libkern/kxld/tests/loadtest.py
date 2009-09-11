#!/usr/bin/env python

import sys
from subprocess import call, Popen, PIPE

kexts = []
pipe = Popen("/usr/sbin/kextfind \( -l -and -x -and -arch i386 \)", shell=True, stdout=PIPE).stdout

line = pipe.readline()
while line:
    kexts.append(line.strip())
    line = pipe.readline()

NULL = open("/dev/null")

for kext in kexts:
    try:
        print "Processing", kext
#cmd = "/sbin/kextload -ns /tmp/syms \"%s\"" % kext
        cmd = "/sbin/kextload \"%s\"" % kext
        kextload = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE)
        for i in range(20):
            kextload.stdin.write("0x1000\n");
        retcode = kextload.wait()
        if retcode < 0:
            print >>sys.stderr, "*** kextload of %s was terminated by signal %d" % (kext, -retcode)
        elif retcode > 0:
            print >>sys.stderr, "*** kextload of %s failed with return code %d" % (kext, retcode)
    except OSError, e:
        print >>sys.stderr, "Execution failed:", e
        sys.exit(1)

