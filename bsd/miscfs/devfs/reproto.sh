#!/bin/sh
#
# This used to be a shell script, but had to become more sophisticated
# to allow for KNF function definitions.  So rewrote in perl, but wrapped
# as a shell script.
#
exec /usr/bin/perl << *EOF*
open(PROTO, ">devfs_proto.h") || die "Cannot open devfs_proto.h\n";

print PROTO "/* THIS FILE HAS BEEN PRODUCED AUTOMATICALLY */\n";

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

print PROTO  "/* THIS FILE PRODUCED AUTOMATICALLY */\n" .
    "/* DO NOT EDIT (see reproto.sh) */\n";

*EOF*
