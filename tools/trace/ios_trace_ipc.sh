#!/bin/sh
#
# Initiate tracing
CODE_MACH_KMSG_INFO=0x1200028
CODE_MACH_PROC_EXEC=0x401000C
CODE_MACH_MSG_SEND=0x120000C
CODE_MACH_MSG_RECV=0x1200010
CODE_TRACE_DATA_EXEC=0x7000008

ofile=${1:-ipc.raw}
sleepsec=${2:-3}

trace -i -b 8192
trace -n
trace -g
if [ $sleepsec -gt 0 ]; then
	echo ""
	echo "Sleeping for ${sleepsec}..."
	sleep ${sleepsec}
fi
echo "Tracing!"

ps -Ac | sed 's,\s*\([0-9][0-9]*\) .*[0-9]*:[0-9]*\.[0-9]* \(.*\), 00000000.0  0.0(0.0)  proc_exec  \1 0 0 0 0 0  \2,' > "ps_${ofile}.txt"
trace -L ${ofile} -k ${CODE_MACH_KMSG_INFO} -k ${CODE_MACH_PROC_EXEC} -k ${CODE_MACH_MSG_SEND} -k ${CODE_MACH_MSG_RECV}
