#include <darwintest.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>

#include <stdio.h>
#include <assert.h>
#include <err.h>
#include <libproc.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

T_DECL(proc_info_44873309, "ensure new proc_pidinfo flavor returns correct table sizes",
    T_META_CHECK_LEAKS(false), T_META_ASROOT(true))
{
	mach_port_t port;
	int retval;

	pid_t pid = getpid();
	struct proc_ipctableinfo table_info = {};
	retval = proc_pidinfo(pid, PROC_PIDIPCTABLEINFO, 0, (void *)&table_info, (uint32_t)sizeof(table_info));
	T_WITH_ERRNO; T_EXPECT_GT(retval, 0, "proc_pidinfo(PROC_PIDIPCTABLEINFO) returned %d", retval);
	T_EXPECT_EQ(retval, (int)sizeof(table_info), "proc_pidinfo(PROC_PIDIPCTABLEINFO) table_size = %u, table_free = %u",
	    table_info.table_size, table_info.table_free);

	kern_return_t ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	T_ASSERT_MACH_SUCCESS(ret, "mach_port_allocate MACH_PORT_RIGHT_RECEIVE");

	struct proc_ipctableinfo table_info2 = {};
	retval = proc_pidinfo(pid, PROC_PIDIPCTABLEINFO, 0, (void *)&table_info2, (uint32_t)sizeof(table_info2));
	T_WITH_ERRNO; T_EXPECT_GT(retval, 0, "proc_pidinfo(PROC_PIDIPCTABLEINFO) returned %d", retval);
	T_EXPECT_EQ(retval, (int)sizeof(table_info2), "proc_pidinfo(PROC_PIDIPCTABLEINFO) table_size2 = %u, table_free2 = %u",
	    table_info2.table_size, table_info2.table_free);

	T_EXPECT_EQ(table_info.table_free, table_info2.table_free + 1, "Comparing the table_free values");
}
