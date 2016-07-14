#!/bin/sh

EXECUTABLES="exit.nodyld \
        exit.nopie.dyld-but-no-Libsystem exit.pie.dyld-but-no-Libsystem \
        exit.nopie.dyld-and-Libsystem exit.pie.dyld-and-Libsystem \
        exit.nopie exit.pie"
			
RUN=run
PRODUCT=`sw_vers -productName`
COUNT=

# params are: record_perf_data(metric, unit, value, description)
function record_perf_data() {
    local METRIC=$1
    local UNIT=$2
    local DATA=$3
    local DESCRIPTION=$4
	echo "{ \"version\" : \"1.0\", \"measurements\" : {\"$METRIC\": {\"description\" : \"$DESCRIPTION\", \"names\":[\"$METRIC\"],  \"units\" : [\"$UNIT\"], \"data\" : [$DATA] }}}"
}

PERFDATA_DIR=$BATS_TMP_DIR
if [ "${PERFDATA_DIR}" == "" ]; then
	PERFDATA_DIR=/tmp/
fi

case "$PRODUCT" in
    "Watch OS")
    COUNT=500
    ;;
    "iPhone OS")
	COUNT=1000
	;;
    "Mac OS X")
    COUNT=6000
    ;;
    *)
	COUNT=1000
	;;
esac

for i in ${EXECUTABLES}; do
    echo "Running $i"
    for j in `jot $(sysctl -n hw.ncpu) 1`; do
	printf "\t%dx\t" $j
    METRIC_NAME="${i}_${j}x"
    TIMEOUT=` /usr/bin/time ./${RUN} $j $((${COUNT}/$j)) ./$i 2>&1`
    echo ${TIMEOUT}
    REALTIME=`echo ${TIMEOUT} | awk '{ print $1 }'`
    TOTALTIME=`echo ${TIMEOUT} | awk '{ print $3 + $5 }'`
    record_perf_data "${METRIC_NAME}_real" "s" $REALTIME "Real time in seconds. Lower is better. This may have variance based on load on system" > ${PERFDATA_DIR}/${METRIC_NAME}_real.perfdata
    record_perf_data "${METRIC_NAME}_sys" "s" $TOTALTIME "User + Sys time in seconds. Lower is better." > /tmp/${METRIC_NAME}_sys.perfdata
	if [ $? -ne 0 ]; then
	    echo "Failed $i, exit status $?"
	    exit 1
	fi
    done
done
