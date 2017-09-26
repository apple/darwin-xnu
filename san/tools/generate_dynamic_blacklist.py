#!/usr/bin/env python

import sys
import re

def type_map(x):
	return "TYPE_" + x.upper()

re_comments=re.compile(r'#.*$')

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
		ty = "all";

	print """	{{
		.kext_name = {},
		.func_name = {},
		.type_mask = {},
	}},""".format(kext, func, type_map(ty))

print r'};'
