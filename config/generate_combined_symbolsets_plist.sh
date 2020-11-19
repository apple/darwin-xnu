#!/bin/sh

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 output.plist input1.plist [input2.plist ... ]" 1>&2
    exit 1
fi

OUTPUT="$1"
shift

printf \
'<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>SymbolsSets</key>
	<array>
' > "$OUTPUT"

for f in "$@"; do
awk '
	BEGIN {
		print "		<dict>"
	}
	/^\t/ {
		print "		" $0
		next
	}
	END {
		print "		</dict>"
	}
' "$f" >> "$OUTPUT"
done

printf \
'	</array>
	<key>WeakRefFallbackSymbol</key>
	<dict>
		<key>SymbolName</key>
		<string>_gOSKextUnresolved</string>
	</dict>
</dict>
</plist>
' >> "$OUTPUT"

exit 0
