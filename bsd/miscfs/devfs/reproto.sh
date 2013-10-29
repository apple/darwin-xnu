#!/bin/sh
#
# This used to be a shell script, but had to become more sophisticated
# to allow for KNF function definitions.  So rewrote in perl, but wrapped
# as a shell script.
#
exec /usr/bin/perl << *EOF*
open(PROTO, ">devfs_proto.h") || die "Cannot open devfs_proto.h\n";

print PROTO "" .
"/*\n" .
" * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.\n" .
" *\n" .
" * \@APPLE_OSREFERENCE_LICENSE_HEADER_START\@\n" .
" *\n" .
" * The contents of this file constitute Original Code as defined in and\n" .
" * are subject to the Apple Public Source License Version 1.1 (the\n" .
" * \"License\").  You may not use this file except in compliance with the\n" .
" * License.  Please obtain a copy of the License at\n" .
" * http://www.apple.com/publicsource and read it before using this file.\n" .
" *\n" .
" * This Original Code and all software distributed under the License are\n" .
" * distributed on an \"AS IS\" basis, WITHOUT WARRANTY OF ANY KIND, EITHER\n" .
" * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,\n" .
" * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,\n" .
" * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the\n" .
" * License for the specific language governing rights and limitations\n" .
" * under the License.\n" .
" *\n" .
" * \@APPLE_OSREFERENCE_LICENSE_HEADER_END\@\n" .
" */\n"; 

print PROTO "/* THIS FILE HAS BEEN PRODUCED AUTOMATICALLY */\n";

print PROTO "#ifndef __DEVFS_DEVFS_PROTO_H__\n";
print PROTO "#define __DEVFS_DEVFS_PROTO_H__\n";
print PROTO "\n#include  <sys/appleapiopts.h>\n";
print PROTO "\n#ifdef __APPLE_API_PRIVATE\n";

while (\$file = <*.c>) {
    if(open(F, \$file) == 0) {
	warn "Cannot open \$file.\n";
	next;
    }

    while(<F>) {
	chop;
	if (m|/\*proto\*/|) {
	    \$collecting = 1;
	    \$idx = 0;
	} elsif (\$collecting) {
	    if (/^{/) {
		\$text[\$idx - 1] .= ';';
		for (\$i = 0; \$i < \$idx; \$i++) {
		    print PROTO "\$text[\$i]";
		    print PROTO \$i == 0? "\t": "\n";
		}
		\$collecting = 0;
		next;
	    }
	    \$text[\$idx++] = \$_;
	}
    }
    close F;
}

print PROTO "\n#endif /* __APPLE_API_PRIVATE */\n";
print PROTO "#endif /* __DEVFS_DEVFS_PROTO_H__ */\n";

print PROTO  "/* THIS FILE PRODUCED AUTOMATICALLY */\n" .
    "/* DO NOT EDIT (see reproto.sh) */\n";

*EOF*
