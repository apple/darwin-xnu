#!/usr/bin/env python

import sys
import re

def type_map(x):
	return "TYPE_" + x.upper()

re_comments=re.compile(r'#.*$')

nentries = 0
extra_entries = 5
bl = file(sys.argv[1])

print r'struct blacklist_entry blacklist[] = {'

for line in bl.readlines():
	line = re_comments.sub("", line).strip()

	if not line:
		continue

	fields = line.split(":")
	if len(fields) != 3:
		continue

	(kext, func, ty) = fields

	if kext == "":
		kext = "NULL";
	else:
		kext = '"' + kext + '"'

	if func == "":
		func = "NULL";
	else:
		func = '"' + func + '"'

	if ty == "":
		ty = "normal";

	print """	{{
		.kext_name = {},
		.func_name = {},
		.type_mask = {},
	}},""".format(kext, func, type_map(ty))
	nentries += 1

# add space for new entries added at runtime
print ''
print r'	/* Unused entries that can be populated at runtime */'
for i in xrange(0, extra_entries):
	print """	{{
		.kext_name = {},
		.func_name = {},
		.type_mask = {},
	}},""".format("NULL", "NULL", 0)

print r'};'
print

print 'static size_t blacklist_entries = {};'.format(nentries)
print 'static const size_t blacklist_max_entries = {};'.format(nentries + extra_entries)
