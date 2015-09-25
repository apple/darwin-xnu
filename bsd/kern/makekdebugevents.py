#!/usr/bin/python
#
# This script scans the trace.codes file, containing a mapping of event id to
# event name for all events, and writes to stdout a C declaration for a table
# named kd_events[] or these mappings.
# Required to generate a header file used by DEVELOPMENT and DEBUG kernels.
#
 
import sys
import re

# we expect one arg specifying the path to the trace.codes file
if (len(sys.argv) < 2):
    exit(1)
trace_code_file = sys.argv[1]

# regular expression pattern to match <hex_id> <string>
id_name_pattern = re.compile('0x([0-9a-fA-F]+)\s+([^\s]*)')
code_table = []

# scan file to generate internal table
with open(trace_code_file, 'rt') as codes:
    for line in codes:
	m = id_name_pattern.match(line)
	if m:
            code_table += [(int(m.group(1),base=16), m.group(2))]

# emit typedef:
print "typedef struct {"
print "        uint32_t   id;"
print "        const char *name;"
print "} kd_event_t;"
# emit structure declaration and sorted initialization:
print "kd_event_t kd_events[] = {"
for mapping in sorted(code_table, key=lambda x: x[0]):
        print "        {0x%x, \"%s\"}," % mapping
print "};"

