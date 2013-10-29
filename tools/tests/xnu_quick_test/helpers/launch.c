/* 
 *  Part of the execve tests. This program should not be compiled fat. xnu_quick_test
 * will call the various single-architecture builds of this program as helpers to test
 * the exec() transitions it cannot test itself.
 *
 * When running on a 64-bit machine (x86_64 or PPC64), the 32-bit version of 
 * xnu_quick_test will fork and exec a 64-bit helper process that performs 
 * the following tests.
 * 1. 64 bit process forking() 64-bit child, child execing() 64-bit file(4GB pagezero)
 * 2. 64 bit process forking() 64-bit child, child execing() 64-bit file (4KB pagezero)
 * 3. 64 bit process forking() 64-bit child, child execing() 32-bit file
 *
 *  The 64-bit version of xnu_quick_test will fork and exec a 32-bit process 
 * that performs the following tests.
 * 4. 32 bit process forking() 32-bit child, child execing() 32-bit file
 * 5. 32 bit process forking() 32-bit child, child execing() 64 bit file (4GB pagezero) 
 * 6. 32 bit process forking() 32-bit child, child execing() 64 bit file (4KB pagezero)
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

extern int do_execve_test(char * path, char * argv[], void * envp, int killwait);
extern int get_bits(void);

int g_testbots_active = 0;
int main(int argc, const char * argv[])
{
	int	my_err, my_status;
	pid_t	my_pid, my_wait_pid;
	char *	errmsg = NULL; 
	char *	argvs[2] = {"", NULL};
	int 	bits = get_bits();		/* Gets actual processor bit-ness. */

#if defined(__i386__)
	/* 
	 * This is the helper binary for the x86_64 version of  xnu_quick_test. xnu_quick_test 
	 * forks and execs this code to test exec()ing from a 32-bit binary.
	 */
	errmsg = "execve failed: from i386 forking and exec()ing i386 process.\n";
	argvs[0] = "sleep-i386";
	if (do_execve_test("helpers/sleep-i386", argvs, NULL, 0))	goto test_failed_exit;

	errmsg = "execve failed: from i386 forking and exec()ing x86_64 process w/ 4G pagezero.\n";
	argvs[0] = "sleep-x86_64-4G";
	if (do_execve_test("helpers/sleep-x86_64-4G", argvs, NULL, 0))	goto test_failed_exit;

	errmsg = "execve failed: from i386 forking and exec()ing x86_64 process w/ 4K pagezero.\n";
	argvs[0] = "sleep-x86_64-4K";
	if (do_execve_test("helpers/sleep-x86_64-4K", argvs, NULL, 0))	goto test_failed_exit;
#endif


#if defined(__x86_64__)
	/* 
	 * This is the helper binary for the i386 version of xnu_quick_test. xnu_quick_test 
	 * forks and execs this code to test exec()ing from a 64-bit binary.
	 */
	errmsg = "execve failed: from x86_64 forking and exec()ing 64-bit x86_64 process w/ 4G pagezero.\n";
	argvs[0] = "sleep-x86_64-4G";
	if (do_execve_test("helpers/sleep-x86_64-4G", argvs, NULL, 1))		goto test_failed_exit;

	errmsg = "execve failed: from x86_64 forking and exec()ing 64-bit x86_64 process w/ 4K Pagezero.\n";
	argvs[0] = "sleep-x86_64-4K";
	if (do_execve_test("helpers/sleep-x86_64-4K", argvs, NULL, 1))		goto test_failed_exit;

	errmsg = "execve failed: from x64_64 forking and exec()ing 32-bit i386 process.\n";
	argvs[0] = "sleep-i386";
	if (do_execve_test("helpers/sleep-i386", argvs, NULL, 1))		goto test_failed_exit;
#endif


	/* 
	 * We are ourselves launched with do_execve_test, which wants a chance to 
	 * send a SIGKILL
	 */
	sleep(4);
	return 0;

test_failed_exit:
	if (errmsg)
		printf("%s", errmsg);
	return -1;
}

