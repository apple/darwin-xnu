#!/usr/bin/env bash

function run_test() {
	local testname="$1"
	local out_status=1
	local out_str=" "

	echo ""
	echo "[TEST] ${testname} "
	if [ -x "./${testname}" ]
	then
		echo "[BEGIN] Executing test ${testname}"
		out_str=$(./"${testname}" 2>&1)
		out_status="$?"
	else
		echo "[FAIL] Failed to execute test with name ${testname}"
		out_status=1
	fi

	if [ "${out_status}" == "0" ] 
	then
		echo "[PASS] Successfully finished ${testname}"
	else
		echo $out_str
		echo "[FAIL] Test failed ${testname} exit value $out_status"
		echo "  *** FAILURE of test ${testname} *** "
		echo ""
	fi
	return $out_status
}

function build_test(){
	local testtarget="$1"
	local out_str=" "
	local out_status=1

	echo "[MAKE] Building test ${testtarget}"
	out_str=$(make ${MAKE_ARGS} ${testtarget} 2>&1)
	out_status=$?
	echo ${out_str} >> ${BUILD_LOG_FILEMAME}

	if [ "${out_status}" == "0" ] 
	then
		echo "[PASS][BUILD] Successfully built ${testtarget}"
	else
		echo ${out_str}
		echo "[FAIL][BUILD] Failed to build ${testtarget}"
	fi
	return ${out_status}
}

CMD=build
TARGET_MODE=$1
TIMESTAMP=`date +%s`
PROGNAME=$0
TARGET_LIST_FILE="xnu_target_executables.list"
BUILD_DIR="${PWD}/BUILD/"
BUILD_LOG_FILEMAME="${BUILD_DIR}/build_${TIMESTAMP}.log"

# load the list of targets to build/run
if [ -f "$TARGET_LIST_FILE" ]
then
	TARGET_NAMES=`cat $TARGET_LIST_FILE`
else
	TARGET_NAMES=`make ${MAKE_ARGS} list_targets`
fi

if [ "$CMD" == "build" ] 
then
	
	# setup make arguments based on target requirements
	if [ "${TARGET_MODE}" == "embedded" ] 
	then
		T_ios=`/usr/bin/xcodebuild -sdk iphoneos.internal -version Path`
		T_ios_name=iphoneos.internal
		if [ "$T_ios" == "" ] 
		then
			T_ios=`/usr/bin/xcodebuild -sdk iphoneos -version Path`
			T_ios_name=iphoneos
		fi

		if [ "$T_ios" == "" ] 
		then
			echo "No iOS SDK found. Exiting."
			exit 1
		fi
		
		MAKE_ARGS="SDKROOT=${T_ios_name}"
	elif [ "${TARGET_MODE}" == "desktop" ]
	then
		MAKE_ARGS=""
	else
		echo "Usage: ${PROGNAME} <desktop|embedded>"
		exit 1
	fi
	
	if [ -d "${BUILD_DIR}" ]
	then
		mkdir -p ${BUILD_DIR}
	fi
	
	echo " "
	echo "=========== Building XNU Unit Tests ========="
	echo " "
	
	for testname_target in ${TARGET_NAMES}
	do
		build_test  ${makefilename} ${testname_target}
		echo ""
	done
	
	echo "Finished building tests. Saving list of targets in  ${BUILD_DIR}/dst/${TARGET_LIST_FILE}"
	echo "${TARGET_NAMES}" > ${BUILD_DIR}/dst/${TARGET_LIST_FILE}
	cat "${PROGNAME}" | sed s/^CMD=build/CMD=run/g  > ${BUILD_DIR}/dst/run_tests.sh
	chmod +x ${BUILD_DIR}/dst/run_tests.sh
	echo "Generated  ${BUILD_DIR}/dst/run_tests.sh for running the tests."
	exit 0
	
fi
# End of Build action

#
if [ "$CMD" == "run" ]
then
	echo " "
	echo "=========== Running XNU Unit Tests ========="
	echo " "
	for testname_target in ${TARGET_NAMES}
	do
		run_test  ${testname_target}
	done
	exit 0	
fi
# End of Run action
