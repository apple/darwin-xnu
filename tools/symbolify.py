#!/usr/bin/env python
from subprocess import Popen, PIPE, call
import re
import sys
import os

SLIDE = 0

NM_FORMAT = "([0-9a-f]+) ([UuAaTtDdBbCcSsIi]) (.*)"

nm_re = re.compile(NM_FORMAT)

def parse_nm_output(str):
    "returns (start, type, name)"
    m = nm_re.match(str)
    if m:
        start = int(m.group(1), 16)
        return (start, m.group(2), m.group(3))
    else:
        return None

def nm(file):
    cmd = "nm %s" % file
    p = Popen(cmd, shell=True, stdout=PIPE)
    return p.stdout

class SymbolLookup:
    def __init__(self, file, min_width=16):
        self.min_width = min_width
        self.symbols = [parse_nm_output(l) for l in nm(file)]
        self.symbols.sort(key=lambda x: x[0])

    def padded(self, str):
        return ("%%%ds" % self.min_width) % str

    def __call__(self, saddr):
        addr = int(saddr.group(0), 16)
        last = (0, ' ', '<start of file>')
        if( addr > SLIDE ):
            addr -= SLIDE
        # stupid linear search... feel free to improve
        for s in self.symbols:
            if s[0] == addr:
                return self.padded(s[2])
            elif s[0] > addr:
                if last[2] == "_last_kernel_symbol":
                    return saddr.group(0)
                return self.padded("<%s>+%x" % (last[2], addr - last[0]))
            else:
                last = s
        if last[2] == "_last_kernel_symbol":
            return saddr.group(0)
        return self.padded("<%s>+%x" % (last[2], addr - last[0]))

def symbolify(objfile, input, *args, **kargs):
    replacer = SymbolLookup(objfile, *args, **kargs)
    for l in input:
        print re.sub("(0x)?[0-9a-f]{6,16}", replacer, l),


def usage():
    
    print "usage: %s [filename] [slide]" % sys.argv[0]
    print "\tor speficy a filename in your SYMBOLIFY_KERNEL environment variable"

    # die now
    sys.exit(1)

KERNEL_FILE = None

if( len(sys.argv) > 3 ):
    usage()

if( len(sys.argv) == 3 ):
    SLIDE = int(sys.argv[2], 16)

if( len(sys.argv) >= 2 ):
    KERNEL_FILE = sys.argv[1]

if( KERNEL_FILE is None ):
    KERNEL_FILE = os.environ.get("SYMBOLIFY_KERNEL")

if( KERNEL_FILE is None ):
    usage()

print "using kernel file '%s', slide 0x%x" % (KERNEL_FILE, SLIDE)

symbolify(KERNEL_FILE, sys.stdin, min_width=40)

