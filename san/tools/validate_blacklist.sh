#!/bin/bash

# Ensure all blacklisted files exist. Paths with wildcards are ignored.
# Run against a blacklist with fully-qualified paths.

IFS=$'\n'

blacklist_files=`sed -n -e '
	# ignore paths with wildcards
	/\*/ d

	# strip leading 'src:'
	/^src/ {
		s/^src://
		p
	}
' $1`

ret=0

for f in $blacklist_files ; do
	if ! [[ -e $f ]] ; then
		echo "KASan: blacklisted file $f not found" >&2
		ret=1
	fi
done

exit $ret
