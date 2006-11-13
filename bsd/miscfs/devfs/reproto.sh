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
" * \@APPLE_LICENSE_OSREFERENCE_HEADER_START\@\n" .
" *\n" .
" * This file contains Original Code and/or Modifications of Original Code\n" .
" * as defined in and that are subject to the Apple Public Source License\n" .
" * Version 2.0 (the \"License\"). You may not use this file except in\n" .
" * compliance with the License.  The rights granted to you under the\n" .
" * License may not be used to create, or enable the creation or\n" .
" * redistribution of, unlawful or unlicensed copies of an Apple operating\n" .
" * system, or to circumvent, violate, or enable the circumvention or\n" .
" * violation of, any terms of an Apple operating system software license\n" .
" * agreement.\n" .
" *\n" .
" * Please obtain a copy of the License at\n" .
" * http://www.opensource.apple.com/apsl/ and read it before using this\n" .
" * file.\n" .
" *\n" .
" * The Original Code and all software distributed under the License are\n" .
" * distributed on an \"AS IS\" basis, WITHOUT WARRANTY OF ANY KIND, EITHER\n" .
" * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,\n" .
" * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,\n" .
" * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.\n" .
" * Please see the License for the specific language governing rights and\n" .
" * limitations under the License.\n" .
" *\n" .
" * \@APPLE_LICENSE_OSREFERENCE_HEADER_END\@\n" .
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
