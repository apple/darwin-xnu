#!/bin/bash

TESTDIR=$PWD/
MPMMTEST="${TESTDIR}/MPMMtest"
MPMMTEST_64="${TESTDIR}/MPMMtest_64"
KQMPMMTEST="${TESTDIR}/KQMPMMtest"
KQMPMMTEST_64="${TESTDIR}/KQMPMMtest_64"

if [ -e $MPMMTEST ] && [ -x $MPMMTEST ]
then
	echo ""; echo " Running $MPMMTEST";
	$MPMMTEST -perf || { x=$?; echo "$MPMMTEST failed $x "; exit $x; }
fi

if [ -e $MPMMTEST_64 ] && [ -x $MPMMTEST_64 ]
then
	echo ""; echo " Running $MPMMTEST_64"
	$MPMMTEST_64 -perf || { x=$?; echo "$MPMMTEST_64 failed $x"; exit $x; }
fi

if [ -e $KQMPMMTEST ] && [ -x $KQMPMMTEST ]
then
	echo ""; echo " Running $KQMPMMTEST"
	$KQMPMMTEST -perf || { x=$?; echo "$KQMPMMTEST failed $x"; exit $x; }
fi

if [ -e $KQMPMMTEST_64 ] && [ -x $KQMPMMTEST_64 ]
then
	echo ""; echo " Running $KQMPMMTEST_64"
	$KQMPMMTEST_64 -perf || { x=$?; echo "$KQMPMMTEST_64 failed $x"; exit $?; }
fi

echo ""; echo " SUCCESS";
exit 0;


