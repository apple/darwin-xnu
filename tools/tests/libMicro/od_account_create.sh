#!/bin/bash


function sighandler {
  echo 
  echo "Interrupting account creation"
  rm -f $TMPF
  exit 1
}

trap sighandler INT TERM

# Fixed parameters
#
NAME=`basename $0`
COUNT=$1
NODE=$2
PREFIX="od_test_"
GROUP_ID=1211	# A group everybody's in
GROUP_ID2=1212	# A group nobody's in
GROUP_NAME='od_test_group'
UID_BASE=5000
TMPF=/tmp/.${NAME}.$$

usage () {
  echo
  echo "Usage: ${NAME} count nodename"
  echo 
  echo "   ie. ${NAME} 1000 /Local/Default"
  echo
  echo "       will create users 1000 users (from '${PREFIX}1' to '${PREFIX}1000')"
  echo "       Default password is set to 'test'"
  echo "       User ID starts from 5000"
  echo "       Default group is '${GROUP_NAME}', Group ID 1211"
  echo
  echo "This tool assumes user 'diradmin' with password 'admin' for OD admin"
  echo
  exit 85 # WRONGARGS
}

if [ $# -ne 2 ]; then
  usage
fi

# we don't need credentials if its a local node
if [ $NODE != "/Local/Default" ]; then
  OD_ADMIN="diradmin"
  OD_PASS="admin"
fi

echo "Creating users ${PREFIX}1 to ${PREFIX}$COUNT"

# check to see if od_test_group exist. if not, create one
#
result=`dscl $NODE -list Groups/${GROUP_NAME}1 2> /dev/null`
if [ $? -ne 0 ]; then
  echo "Group \"${GROUP_NAME}\" does not exist. Creating ${GROUP_NAME}"
  if [ -n "$OD_ADMIN" ]; then
    dseditgroup -q -o create -n $NODE -u $OD_ADMIN -P $OD_PASS -i ${GROUP_ID} ${GROUP_NAME}1
    dseditgroup -q -o create -n $NODE -u $OD_ADMIN -P $OD_PASS -i ${GROUP_ID2} ${GROUP_NAME}2
  else
    dseditgroup -q -o create -n $NODE -i ${GROUP_ID} ${GROUP_NAME}1
    dseditgroup -q -o create -n $NODE -i ${GROUP_ID2} ${GROUP_NAME}2
  fi
fi

if [ $? -ne 0 ]; then
	echo "Failed to create test_group"
	exit 1
fi

# using dsimport is faster than using dscl
i=1
uid=$UID_BASE
echo "Writing a temporary import file ..."
while [ $i -le $COUNT ]
do
  result=`dscl $NODE -list Users/${PREFIX}${i} 2> /dev/null`
  if [ $? -ne 0 ]; then 
    # Uses standard template
	# RecordName:Password:UniqueID:PrimaryGroupID:DistinguishedName:NFSHomeDirectory:UserShell
	echo "${PREFIX}${i}:test:${uid}:1211:${PREFIX}${i}:/Users/${PREFIX}${i}:/bin/bash" >> $TMPF
    printf "\r${PREFIX}${i} / ${COUNT}"
  else
    echo "account $PREFIX$i already exist. skipping"
  fi
  i=`expr $i + 1` 
  uid=`expr $uid + 1` 
done
echo 

# Now do the real work
#
if [[ -f $TMPF ]]; then
  echo "Running dsimport to create users. Please be patient. This takes a while ..."
  # assume if admin is provided that slapconfig exists
  if [ -n "$OD_ADMIN" ]; then
    if [[ -x "/usr/sbin/slapconfig" ]]; then
      /usr/sbin/slapconfig -setfullsyncmode no
      sleep 2
    fi
    /usr/bin/time dsimport $TMPF $NODE I --username $OD_ADMIN --password $OD_PASS --template StandardUser
    sleep 2
    if [[ -x "/usr/sbin/slapconfig" ]]; then
      /usr/sbin/slapconfig -setfullsyncmode yes
    fi
  else
    /usr/bin/time dsimport $TMPF $NODE I --template StandardUser
    sleep 2
  fi
  
  # and now delete the temp file
  #
  rm -f $TMPF
else
  echo "Nothing done. All users already exist"
fi 

echo Create a SACL group for libMicro
# Create a sample SACL group
dseditgroup -q -o create -r "libMicro ACL" com.apple.access_libMicro
i=1
while [ $i -le $COUNT ]; do
	dseditgroup -q -o edit -a ${PREFIX}${i} -t user com.apple.access_libMicro 
	i=`expr $i + 1` 
done

echo 'Finished'

