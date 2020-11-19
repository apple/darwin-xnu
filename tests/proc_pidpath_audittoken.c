#include <darwintest.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <libproc.h>
#include <bsm/libbsm.h>

#undef USE_AUDIT_TOKEN_FOR_PID

#ifdef USE_AUDIT_TOKEN_FOR_PID
static bool
audit_token_for_pid(pid_t pid, audit_token_t *token)
{
	kern_return_t err;
	task_t task;
	mach_msg_type_number_t info_size = TASK_AUDIT_TOKEN_COUNT;

	err = task_for_pid(mach_task_self(), pid, &task);
	if (err != KERN_SUCCESS) {
		printf("task_for_pid returned %d\n", err);
		return false;
	}

	err = task_info(task, TASK_AUDIT_TOKEN, (integer_t *)token, &info_size);
	if (err != KERN_SUCCESS) {
		printf("task_info returned %d\n", err);
		return false;
	}

	return true;
}

#else

static int
idversion_for_pid(pid_t pid)
{
	struct proc_uniqidentifierinfo uniqidinfo = {0};

	int ret = proc_pidinfo(pid, PROC_PIDUNIQIDENTIFIERINFO, 0, &uniqidinfo, sizeof(uniqidinfo));
	if (ret <= 0) {
		perror("proc_pidinfo(PROC_PIDUNIQIDENTIFIERINFO)");
		T_ASSERT_FAIL("proc_pidinfo(%d, PROC_PIDUNIQIDENTIFIERINFO) failed unexpectedly with errno %d", pid, errno);
	}

#ifdef NOTDEF
	printf("%s>pid = %d, p_uniqueid = %lld\n", __FUNCTION__, pid, uniqidinfo.p_uniqueid);
	printf("%s>pid = %d, p_idversion = %d\n", __FUNCTION__, pid, uniqidinfo.p_idversion);
#endif

	return uniqidinfo.p_idversion;
}
#endif

static void
show_pidpaths(void)
{
	char buffer[PROC_PIDPATHINFO_MAXSIZE] = {};
	int count = 0;

	for (pid_t pid = 1; ((pid < 1000) && (count <= 25)); pid++) {
		int ret = proc_pidpath(pid, buffer, sizeof(buffer));
		if (ret <= 0) {
			if (errno == ESRCH) {
				continue;
			}
			T_ASSERT_FAIL("proc_pidpath(%d) failed unexpectedly with errno %d", pid, errno);
		}
		count++;

		memset(buffer, 0, sizeof(buffer));

		audit_token_t token = { 0 };
#ifdef USE_AUDIT_TOKEN_FOR_PID
		if (!audit_token_for_pid(pid, &token)) {
			T_ASSERT_FAIL("audit_token_for_pid(%d) failed", pid);
			continue;
		}
#else
		token.val[5] = (unsigned int)pid;
		token.val[7] = (unsigned int)idversion_for_pid(pid);
#endif
		ret = proc_pidpath_audittoken(&token, buffer, sizeof(buffer));
		if (ret <= 0) {
			if (errno == ESRCH) {
				continue;
			}
			T_ASSERT_FAIL("proc_pidpath_audittoken(%d) failed unexpectedly with errno %d", pid, errno);
		}
		T_PASS("%5d %s\n", pid, buffer);

		token.val[7]--; /* Change to idversion so the next call fails */
		ret = proc_pidpath_audittoken(&token, buffer, sizeof(buffer));
		T_ASSERT_LE(ret, 0, "proc_pidpath_audittoken() failed as expected due to incorrect idversion");
		T_ASSERT_EQ(errno, ESRCH, "errno is ESRCH as expected");
	}
}

T_DECL(proc_pidpath_audittoken, "Test proc_pidpath_audittoken()", T_META_ASROOT(false))
{
	show_pidpaths();
	T_PASS("Successfully tested prod_pidpath_audittoken()");
	T_END;
}
