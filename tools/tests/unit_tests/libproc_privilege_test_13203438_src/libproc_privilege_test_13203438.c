/*
 * Unit test to verify that PROC_PIDUNIQIDENTIFIERINFO is an unprivilege operation.
 *
 * Test calls PROC_PIDTBSDINFO, PROC_PIDTASKINFO, PROC_PIDT_SHORTBSDINFO, PROC_PIDUNIQIDENTIFIERINFO on the process
 * as well as on launchd to verify that PROC_PIDT_SHORTBSDINFO and PROC_PIDUNIQIDENTIFIERINFO are unpirivilege 
 * operations while PROC_PIDTBSDINFO and PROC_PIDTASKINFO are privelege ones.
 */

#include <System/sys/proc_info.h>
#include <libproc.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>


#define TEST_PASS   1
#define TEST_FAIL   0

int
bsdinfo_test(int pid, int result)
{
	struct proc_bsdinfo bsdinfo;
	int error;


	error = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsdinfo, sizeof(bsdinfo));
	if ((error > 0 && result == TEST_PASS) || (error <= 0 && result == TEST_FAIL)) {
		printf("[PASS]: Privilege test on pid = %d for PROC_PIDTBSDINFO passed\n", pid);
		return 0;
	} else {
		printf("[FAIL]: Privilege test on pid = %d for PROC_PIDTBSDINFO failed\n", pid);
		return 1;
	}

}

int
taskinfo_test(int pid, int result)
{
	struct proc_taskinfo taskinfo;
	int error;


	error = proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &taskinfo, sizeof(taskinfo));
	if ((error > 0 && result == TEST_PASS) || (error <= 0 && result == TEST_FAIL)) {
		printf("[PASS]: Privilege test on pid = %d for PROC_PIDTASKINFO passed\n", pid);
		return 0;
	} else {
		printf("[FAIL] Privilege test on pid = %d for PROC_PIDTASKINFO failed\n", pid);
		return 1;
	}
}

int
bsdshortinfo_test(int pid, int result)
{
	struct proc_bsdshortinfo bsdshortinfo;
	int error;


	error = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &bsdshortinfo, sizeof(bsdshortinfo));
	if ((error > 0 && result == TEST_PASS) || (error <= 0 && result == TEST_FAIL)) {
		printf("[PASS]: Privilege test on pid = %d for PROC_PIDT_SHORTBSDINFO passed\n", pid);
		return 0;
	} else {
		printf("[FAIL]: Privilege test on pid = %d for PROC_PIDT_SHORTBSDINFO failed\n", pid);
		return 1;
	}
}


int
piduniqid_test(int pid, int result)
{
	struct proc_uniqidentifierinfo uniqidinfo;
	int error;


	error = proc_pidinfo(pid, PROC_PIDUNIQIDENTIFIERINFO, 0, &uniqidinfo, sizeof(uniqidinfo));
	if ((error > 0 && result == TEST_PASS) || (error <= 0 && result == TEST_FAIL)) {
		printf("[PASS]: Privilege test on pid = %d for PROC_PIDUNIQIDENTIFIERINFO passed\n", pid);
		return 0;
	} else {
		printf("[FAIL]: Privilege test on pid = %d for PROC_PIDUNIQIDENTIFIERINFO failed\n", pid);
		return 1;
	}

}


int main()
{
	int selfpid, launchdpid;

	selfpid = getpid();
	launchdpid = 1;

	if (bsdinfo_test(selfpid, TEST_PASS))
		goto fail;
	if (bsdinfo_test(launchdpid, TEST_FAIL))
		goto fail;

	if (taskinfo_test(selfpid, TEST_PASS))
		goto fail;
	if (taskinfo_test(launchdpid, TEST_FAIL))
		goto fail;

	if (bsdshortinfo_test(selfpid, TEST_PASS))
		goto fail;
	if (bsdshortinfo_test(launchdpid, TEST_PASS))
		goto fail;

	if (piduniqid_test(selfpid, TEST_PASS))
		goto fail;
	if (piduniqid_test(launchdpid, TEST_PASS))
		goto fail;

	
	printf("Privilege test for libproc passed [PASS] \n");
	return 0;

fail:
	printf("Privilege test for libproc failed [FAIL] \n");
	return 1;
}

