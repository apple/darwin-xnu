#!/bin/sh

EXECUTABLES="exit.nodyld \
        exit.nopie.dyld-but-no-Libsystem exit.pie.dyld-but-no-Libsystem \
        exit.nopie.dyld-and-Libsystem exit.pie.dyld-and-Libsystem \
        exit.nopie exit.pie"
			
RUN=run
PRODUCT=`sw_vers -productName`
COUNT=

case "$PRODUCT" in
    "iPhone OS")
	COUNT=1000
	;;
    *)
	COUNT=10000
	;;
esac

for i in ${EXECUTABLES}; do
    echo "Running $i"
    for j in `jot $(sysctl -n hw.ncpu) 1`; do
	printf "\t%dx\t" $j
	/usr/bin/time ./${RUN} $j $((${COUNT}/$j)) ./$i
	if [ $? -ne 0 ]; then
	    echo "Failed $i, exit status $?"
	    exit 1
	fi
    done
done
