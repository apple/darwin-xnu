#!/bin/bash

TESTDIR=$PWD/
MPMMTEST="${TESTDIR}/MPMMtest"
MPMMTEST_64="${TESTDIR}/MPMMtest_64"
KQMPMMTEST="${TESTDIR}/KQMPMMtest"
KQMPMMTEST_64="${TESTDIR}/KQMPMMtest_64"

is_64_bit_env()
{
	ARCHOUT=`file /bin/ls`
	if [[ $ARCHOUT == *"64-bit"* ]]; then
		return 1
	fi
	return 0
}

is_64_bit_env;
IS_64BIT_BOOTED_OS=$?

if [ -e $MPMMTEST ] && [ -x $MPMMTEST ]
then
	# Tentatively test for 32-bit support
	$MPMMTEST -count 0 -servers 0 -clients 0 &> /dev/null

	if [ $? == 0 ] || [ $IS_64BIT_BOOTED_OS == 0 ]
	then
		# If 32-bit support appears to be present OR if this is not
		# a 64-bit environment, run the test.
		echo ""; echo " Running $MPMMTEST";
		$MPMMTEST -perf || { x=$?; echo "$MPMMTEST failed $x "; exit $x; }
	fi
fi

if [ -e $MPMMTEST_64 ] && [ -x $MPMMTEST_64 ] && [ $IS_64BIT_BOOTED_OS == 1 ]
then
	echo ""; echo " Running $MPMMTEST_64"
	$MPMMTEST_64 -perf || { x=$?; echo "$MPMMTEST_64 failed $x"; exit $x; }
fi

if [ -e $KQMPMMTEST ] && [ -x $KQMPMMTEST ]
then
	# Tentatively test for 32-bit support
	$KQMPMMTEST -count 0 -servers 0 -clients 0 &> /dev/null

	if [ $? == 0 ] || [ $IS_64BIT_BOOTED_OS == 0 ]
	then
		# If 32-bit support appears to be present OR if this is not
		# a 64-bit environment, run the test.
		echo ""; echo " Running $KQMPMMTEST"
		$KQMPMMTEST -perf || { x=$?; echo "$KQMPMMTEST failed $x"; exit $x; }
	fi
fi

if [ -e $KQMPMMTEST_64 ] && [ -x $KQMPMMTEST_64 ] && [ $IS_64BIT_BOOTED_OS == 1 ]
then
	echo ""; echo " Running $KQMPMMTEST_64"
	$KQMPMMTEST_64 -perf || { x=$?; echo "$KQMPMMTEST_64 failed $x"; exit $?; }
fi

echo ""; echo " SUCCESS";
exit 0;


