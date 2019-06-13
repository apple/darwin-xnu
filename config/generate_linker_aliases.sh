#!/bin/sh

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 output.exp input1 [input2 ... ]" 1>&2
    exit 1
fi

OUTPUT="$1"
shift

( grep -h ":" "$@" | awk -F: '{print $2 "  " $1}' ) | sort -u > "$OUTPUT"

exit 0
