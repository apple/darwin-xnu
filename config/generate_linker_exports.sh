#!/bin/sh

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 output.exp input1 [input2 ... ]" 1>&2
    exit 1
fi

OUTPUT="$1"
shift

# Note: we used to export both sides of the alias since forever
# for now keep doing this

( grep -h -v ":" "$@"; grep -h ":" "$@" | awk -F: '{print $1; print $2}' ) | sort -u > "$OUTPUT"

exit 0
