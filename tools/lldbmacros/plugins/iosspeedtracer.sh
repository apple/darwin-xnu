#!/bin/sh

TMPFILE=$(mktemp /var/tmp/iosspeedtracer-$$-XXXXXX)
TMPFILE2=$(mktemp /var/tmp/iosspeedtracer2-$$-XXXXXX)
trap 'rm -f $TMPFILE $TMPFILE2' 0

# save stack log for curl
cat > $TMPFILE

if security find-internet-password -s ios.apple.com > $TMPFILE2; then
    USER=$(sed -n -E -e 's/"acct"<blob>="([^"]*)"/\1/p' < $TMPFILE2)
    PW=$(security find-internet-password -a $USER -s ios.apple.com -w)
    if [[ $? = 0 ]]; then
	curl -u $USER:$PW -X POST -H "Content-Type: text/plain" -H "Accept: text/plain" --data-binary @${TMPFILE} https://ios.apple.com/speedtracer/services/logs
    else
	echo "security failed -- try security unlock-keychain"
    fi
else
    echo "no internet password keychain item for ios.apple.com?!"
fi
