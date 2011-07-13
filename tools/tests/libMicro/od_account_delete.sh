#!/bin/bash

function sighandler {
  echo 
  echo "Interrupting account creation"
  rm -f $TMPF
  exit 2
}

trap sighandler INT TERM

# Fixed parameters
#
NAME=`basename $0`
COUNT=$1
PREFIX="od_test_"
GROUP_NAME='od_test_group'
TMPF=/tmp/.${NAME}.$$
NODE=$2

usage () {
  echo
  echo "Usage: ${NAME} count nodename"
  echo 
  echo "   ie. ${NAME} 1000 /Local/Default"
  echo
  echo "       will delete ${GROUPNAME} and 1000 users "
  echo "       from '${PREFIX}1' to '${PREFIX}1000'"
  echo
  echo "This tool assumes user 'diradmin' with password 'admin' for OD admin"
  echo "when talking to anything other than /Local/Default"
  exit 85 # WRONGARGS
}

if [ $# -ne 2 ]; then
  usage
fi

# if local node we don't need credentials
if [ $NODE != "/Local/Default" ]; then
  OD_ADMIN="diradmin"
  OD_PASS="admin"
fi

echo "Deleting users ${PREFIX}1 to ${PREFIX}$COUNT"

# Using a script file and feed it into dscl is much faster than
# calling dscl everytime.
# 
i=1
echo "Writing a temporary script ..."
if [ -n "$OD_ADMIN" ]; then
  echo "auth $OD_ADMIN $OD_PASS" >> $TMPF
fi

while [ $i -le $COUNT ]
do
  result=`dscl $NODE -list Users/${PREFIX}${i} 2> /dev/null`
  if [ $? -eq 0 ]; then
    echo "delete Users/${PREFIX}${i}" >> $TMPF
    printf "\r${PREFIX}${i} / ${COUNT}"
  fi
  i=`expr $i + 1` 
done
echo 

echo "Deleting temporary test groups"
if [ -n "$OD_ADMIN" ]; then
  result=`dseditgroup -q -o delete -n $NODE -u $OD_ADMIN -P $OD_PASS ${GROUP_NAME}1 2>&1 /dev/null`
  result=`dseditgroup -q -o delete -n $NODE -u $OD_ADMIN -P $OD_PASS ${GROUP_NAME}2 2>&1 /dev/null`
else
  result=`dseditgroup -q -o delete -n $NODE ${GROUP_NAME}1 2>&1 /dev/null`
  result=`dseditgroup -q -o delete -n $NODE ${GROUP_NAME}2 2>&1 /dev/null`
fi

result=`dseditgroup -q -o delete com.apple.access_libMicro 2>&1 /dev/null`

# Now do the real work
#
if [[ -f $TMPF ]]; then
  echo "Running dscl to delete users. Please be patient. This takes a while ..."
  if [[ -x /usr/sbin/slapconfig ]]; then
    /usr/sbin/slapconfig -setfullsyncmode no
  fi

  /usr/bin/time dscl ${NODE} < $TMPF

  if [[ -x /usr/sbin/slapconfig ]]; then
    /usr/sbin/slapconfig -setfullsyncmode yes
  fi
fi

# and now delete the temp file
#
rm -f $TMPF

echo 'Finished'

