#!/usr/bin/env python

helpdoc = """
A simple utility that verifies the syntax for python scripts.
The checks it does are :
  * Check for 'tab' characters in .py files
  * Compile errors in py sources
Usage:
  python syntax_checker.py <python_source_file> [<python_source_file> ..] 
"""
import py_compile
import sys
import os
import re

tabs_search_rex = re.compile("^\s*\t+",re.MULTILINE|re.DOTALL)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print >>sys.stderr, "Error: Unknown arguments"
        print helpdoc
        sys.exit(1)
    for fname in sys.argv[1:]:
        if not os.path.exists(fname):
            print >>sys.stderr, "Error: Cannot recognize %s as a file" % fname
            sys.exit(1)
        if fname.split('.')[-1] != 'py':
            print "Note: %s is not a valid python file. Skipping." % fname
            continue
        fh = open(fname)
        strdata = fh.readlines()
        lineno = 0
        tab_check_status = True
        for linedata in strdata:
            lineno += 1
            if len(tabs_search_rex.findall(linedata)) > 0 :
                print >>sys.stderr, "Error: Found a TAB character at %s:%d" % (fname, lineno)
                tab_check_status = False
        if tab_check_status == False:
            print >>sys.stderr, "Error: Syntax check failed. Please fix the errors and try again."
            sys.exit(1)
        #now check for error in compilation
        try:
            compile_result = py_compile.compile(fname, cfile="/dev/null", doraise=True)
        except py_compile.PyCompileError as exc:
            print str(exc)
            print >>sys.stderr, "Error: Compilation failed. Please fix the errors and try again."
            sys.exit(1)
        print "Success: Checked %s. No syntax errors found." % fname
    sys.exit(0)

