#!/bin/sh

set -e

if [ $# -lt 3 ]; then
    echo "Usage: $0 output.plist Info.plist input1.exports [input2.exports ... ]" 1>&2
    exit 1
fi

OUTPUT="$1"
PLIST="$2"
if [ "${OUTPUT##*.}" != "plist" -o "${PLIST##*.}" != "plist" ]; then
    echo "Usage: $0 output.plist Info.plist input1.exports [input2.exports ... ]" 1>&2
    exit 1
fi
shift 2

printf \
'<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
' > "$OUTPUT"

awk '
	/CFBundleIdentifier|OSBundleCompatibleVersion|CFBundleVersion/ {
		print; getline; print
	}
' $PLIST >> "$OUTPUT"

sort -u "$@" | awk -F: '
	BEGIN {
		print "	<key>Symbols</key>"
		print "	<array>"
	}
	$2 ~ /^_/ {
		print "		<dict>"
		print "			<key>SymbolName</key>"
		print "			<string>"$1"</string>"
		print "			<key>AliasTarget</key>"
		print "			<string>"$2"</string>"
		print "		</dict>"
		next
	}
	$1 ~ /^_.*\*$/ {
		print "		<dict>"
		print "			<key>SymbolPrefix</key>"
		print "			<string>"substr($1, 1, length($1) - 1)"</string>"
		print "		</dict>"
		next
	}
	$1 ~ /^_/ {
		print "		<dict>"
		print "			<key>SymbolName</key>"
		print "			<string>"$1"</string>"
		print "		</dict>"
		next
	}
	END {
		print "	</array>"
	}
' >> "$OUTPUT"

printf \
'</dict>
</plist>
' >> "$OUTPUT"

exit 0
