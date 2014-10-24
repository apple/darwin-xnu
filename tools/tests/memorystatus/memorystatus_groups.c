#include <AvailabilityMacros.h>
#include <mach/thread_policy.h>
#include <mach/mach.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/mach_time.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/errno.h>
#include <sys/kern_memorystatus.h>

#define MAXTESTPIDS  15
#define MAXPRIORITY  JETSAM_PRIORITY_MAX - 1

/*
 * <rdar://problem/15976217> memorystatus_control support for
 * 	reprioritizing multiple processes
 *
 * This test/tool operates in one of two modes.
 *	List mode or Generate mode.
 *
 * In generate mode (the default)
 * Setup:
 *	Spin off some number of child processes.  (Enforce a max)
 *	Generate a random jetsam priority band for each process.
 *	Kill at least one of the processes (this tests the kernel's
 *	   ability to ignore non-existant pid.)
 *	Sprinkle the processes into their randomly assigned band.
 * Test:
 *	Query the kernel for a snapshot of the jetsam priority list,
 *	   (saving the priority and the index into the overall
 *	   priority list for each pid)
 *
 *	Exercise the MEMORYSTATUS_CMD_GRP_SET_PROPERTIES control call.
 *
 *	Properties supported in this exercise?
 *		[1] priority
 *
 *	Query the kernel again for a second snapshot.
 *
 * Verify:
 *	If everything works as expected, all the pids have moved
 *	to the new priority band and relative order before the
 *	move is the same order after the move.
 *
 * In list mode, the user passes in a list of  pids from the command line.
 * We skip the Setup phase, but follow through with the Test and Verify
 * steps.
 *
 * When using generate mode, you can add a delay that takes place just
 * before the control call and then again just after the control call.
 * 	eg: This allows time to manaully introspect the state of
 * 	the device before and after the new property assignments.
 */

/* Globals */
int g_exit_status = 0;
boolean_t generate_flag = FALSE;
boolean_t list_flag     = FALSE;
boolean_t verbose_flag  = FALSE;
boolean_t do_error_flag = FALSE;
uint64_t  delay_seconds = 0;
uint32_t  kill_pid_indx = 0;
uint32_t  g_new_priority = JETSAM_PRIORITY_IDLE;

typedef struct pidinfo {
	pid_t pid;
	int32_t pri_random;    /* random priority for generate path */
	int32_t pri_before;    /* priority before idle move */
	int32_t indx_before;   /* jetsam bucket index before idle move */
	int32_t pri_after;	/* priority found after idle move test */
	int32_t exp_after;	/* Expect priority. Zero if moved to idle band  */
	int32_t indx_after; 	/* order it landed in the idle band */
} pidinfo_t;

static boolean_t do_get_priority_list (boolean_t before, memorystatus_priority_entry_t *mypids, size_t pid_count, pidinfo_t *pidinfo);
static void do_generate_test();
static void do_child_labor();
static int priority_cmp(const void *x, const void *y);
static void do_pidlist_test(memorystatus_priority_entry_t *list, uint32_t pid_count);
static void do_control_list_test(memorystatus_priority_entry_t *list, uint32_t pid_count);
static void dump_info_table(pidinfo_t *info, uint32_t count);
static void print_usage();

static char *g_testname = "GrpSetProperties";

static void
printTestHeader(pid_t testPid, const char *testName, ...)
{
	va_list va;
	printf("=============================================\n");
	printf("[TEST] GrpSetProperty ");
	va_start(va, testName);
	vprintf(testName, va);
	va_end(va);
	printf("\n");
	printf("[PID]  %d\n", testPid);
	printf("=============================================\n");
	printf("[BEGIN]\n");
}

static void
printTestResult(const char *testName, boolean_t didPass, const char *msg, ...)
{
	if (msg != NULL) {
		va_list va;
		printf("\t\t");
		va_start(va, msg);
		vprintf(msg, va);
		va_end(va);
		printf("\n");
	}
	if (didPass) {
		printf("[PASS] GrpSetProperty\t%s\n\n", testName);
	} else {
		printf("[FAIL] GrpSetProperty\t%s\n\n", testName);

		/* Any single failure, fails full test run */
		g_exit_status = -1;
	}
}

static void
do_error_test ()
{
	boolean_t passflag = TRUE;
	int error;
	size_t listsize = 0;
	memorystatus_priority_entry_t list[MAXTESTPIDS];

	listsize = (sizeof(memorystatus_priority_entry_t) * MAXTESTPIDS);
	memset (list, 0, listsize);

	list[0].pid = getpid();
	list[0].priority = JETSAM_PRIORITY_MAX+10;   /* out of range priority */
	
	printTestHeader (getpid(), "NULL pointer test");
	errno=0;
	error = memorystatus_control(MEMORYSTATUS_CMD_GRP_SET_PROPERTIES, 0, 0, NULL, listsize);
	printf("\t Expect: error (-1),  errno (%d)\n", EINVAL);
	printf("\t Actual: error (%d),  errno (%d)\n", error, errno);
	if (error == -1 && errno == EINVAL)
		passflag = TRUE;
	else
		passflag = FALSE;
	printTestResult("NULL pointer test", passflag, NULL);


	printTestHeader (getpid(), "zero size test");
	errno=0;
	error = memorystatus_control(MEMORYSTATUS_CMD_GRP_SET_PROPERTIES, 0, 0, &list, 0);
	printf("\t Expect: error (-1),  errno (%d)\n", EINVAL);
	printf("\t Actual: error (%d),  errno (%d)\n", error, errno);
	if (error == -1 && errno == EINVAL)
		passflag = TRUE;
	else
		passflag = FALSE;
	printTestResult("zero size test", passflag, NULL);


	printTestHeader (getpid(), "bad size test");
	errno=0;
	error = memorystatus_control(MEMORYSTATUS_CMD_GRP_SET_PROPERTIES, 0, 0, &list, (listsize-1));
	printf("\t Expect: error (-1),  errno (%d)\n", EINVAL);
	printf("\t Actual: error (%d),  errno (%d)\n", error, errno);
	if (error == -1 && errno == EINVAL)
		passflag = TRUE;
	else
		passflag = FALSE;
	printTestResult("bad size test", passflag, NULL);

	printTestHeader (getpid(), "bad priority test");
	errno=0;
	error = memorystatus_control(MEMORYSTATUS_CMD_GRP_SET_PROPERTIES, 0, 0, &list, (listsize));
	printf("\t Expect: error (-1),  errno (%d)\n", EINVAL);
	printf("\t Actual: error (%d),  errno (%d)\n", error, errno);
	if (error == -1 && errno == EINVAL)
		passflag = TRUE;
	else
		passflag = FALSE;
	printTestResult("bad priority test", passflag, NULL);
}

int
main(int argc, char *argv[])
{
	kern_return_t        error;
	
	memorystatus_priority_entry_t list[MAXTESTPIDS];
	uint32_t pid_count = MAXTESTPIDS;  /* default */
	size_t listsize = 0;
	int c;
	int i = 0;

	if (geteuid() != 0) {
		printf("\tMust be run as root\n");
		exit(1);
	}

	listsize = sizeof(memorystatus_priority_entry_t) * MAXTESTPIDS;
	memset (list, 0, listsize);

	while ((c = getopt (argc, argv, "p:ed:hvg:l")) != -1) {
		switch (c) {
		case 'p':
			g_new_priority = strtol(optarg, NULL, 10);
			break;
		case 'e':
			do_error_flag = TRUE;
			break;
		case 'v':
			verbose_flag = TRUE;
			break;
		case 'd':
			delay_seconds = strtol(optarg, NULL, 10);
			break;
		case 'l':
			/* means a list of pids follow */
			list_flag = TRUE;
			break;
		case 'g':
			/* dynamicall generate 'n' processes */
			generate_flag = TRUE;
			pid_count = strtol(optarg, NULL, 10);
			break;
		case 'h':
			print_usage();			
			exit(0);
		case '?':
		default:
			print_usage();
			exit(-1);
		}		
	}

	argc -= optind;
	argv += optind;
	errno = 0;

	/*
	 * This core part of this test has two modes only.
	 * Default is to dynamically generate a list of pids to work on.
	 * Else use the -l flag and pass in a list of pids.
	 */
	if (generate_flag && list_flag) {
		printTestResult(g_testname, FALSE, "Can't use both -g and -l options\n");
		exit(g_exit_status);
	}
	
	if (generate_flag) {
		if (pid_count <= 0 || pid_count > MAXTESTPIDS) {
			printTestResult(g_testname, FALSE,
			    "Pid count out of range (actual: %d), (max: %d)\n", pid_count,  MAXTESTPIDS);			
			exit(g_exit_status);
		}
	} else if (list_flag) {
		pid_count=0;
		for (; *argv; ++argv) {
			if (pid_count < MAXTESTPIDS){
				list[pid_count].pid = strtol(*argv, NULL, 10);
				list[pid_count].priority = g_new_priority;
				pid_count++;
				argc--;
				optind++;
			} else {
				printTestResult(g_testname, FALSE,
				    "Too many pids (actual: %d), (max: %d)\n", pid_count,  MAXTESTPIDS);
				exit(g_exit_status);
				break;
			}
		}
		if (pid_count <= 0 ) {
			printTestResult(g_testname, FALSE,
			    "Provide at least one pid (actual: %d),(max: %d)\n", pid_count,  MAXTESTPIDS);
			exit(g_exit_status);				
		}
	} else {
		/* set defaults */
		do_error_flag = TRUE;			
		generate_flag = TRUE;
		pid_count = MAXTESTPIDS;
	}

	if (do_error_flag) {
		do_error_test();
	}
	
	if (generate_flag) {
		do_generate_test(list, pid_count);
	}

	if (list_flag) {
		do_pidlist_test (list, pid_count);
	}

	return(g_exit_status);

}


static void
do_pidlist_test(memorystatus_priority_entry_t *list, uint32_t pid_count)
{
	
	do_control_list_test(list, pid_count);
}

static void
do_control_list_test(memorystatus_priority_entry_t *list, uint32_t pid_count)
{
	int error = 0;
	int i;
	boolean_t passflag;
	pidinfo_t info[MAXTESTPIDS];

	printTestHeader (getpid(), "new priority test");
	memset (info, 0, MAXTESTPIDS * sizeof(pidinfo_t));
	printf ("\tInput: pid_count = %d\n", pid_count);
	printf ("\tInput: new_priority = %d\n", g_new_priority);

	if (generate_flag)
		printf("\tIntentionally killed pid [%d]\n", list[kill_pid_indx].pid);

        /* random value initialization */
	srandom((u_long)time(NULL));

	/* In generate path, we sprinkle pids into random priority buckets */

	/* initialize info structures and properties */
	for (i = 0; i < pid_count; i++) {
		info[i].pid = list[i].pid;
		info[i].pri_random = random() % MAXPRIORITY;   /* generate path only */
		info[i].pri_before = -1;
		info[i].indx_before = -1;
		info[i].pri_after = -1;
		info[i].exp_after = g_new_priority;
		info[i].indx_after = -1;

		if (generate_flag) {
			/* Initialize properties for generated pids */
			memorystatus_priority_properties_t mp;
			mp.priority = info[i].pri_random;
			mp.user_data = 0;
			if(memorystatus_control(MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES, list[i].pid, 0, &mp, sizeof(mp)) == -1) {
				/*
				 * If we cannot set the properties on a given
				 * pid (for whatever reason), we'll ignore it.
				 * But set expectations for verification phase.
				 */
				printf("\tWarning: set properties failed on pid [%d] (%s)\n", list[i].pid, strerror(errno));
				info[i].exp_after = -1;
				errno = 0;
			}
		}
	}

	/* Get the system's current jetsam priority list, init pass */
	if (do_get_priority_list(TRUE, list, pid_count, info) == FALSE) {
		error = 1;
		goto out;
	}

	if (delay_seconds > 0) {
		printf("\tDelay [%llu] seconds... (before move to new band)\n", delay_seconds);
		sleep(delay_seconds);
		errno = 0;
	}	

	error = memorystatus_control(MEMORYSTATUS_CMD_GRP_SET_PROPERTIES, 0, 0,
	    list, (pid_count * sizeof(memorystatus_priority_entry_t)));
	if (error) {
		printf("\tMEMORYSTATUS_CMD_GRP_SET_PROPERTIES failed (%s)\n", strerror(errno));
		goto out;
	}

	/* Get the system's jetsam priority list, after move to new band */
	if (do_get_priority_list(FALSE, list, pid_count, info) == FALSE) {
		error = 1;
		goto out;
	}

	if (delay_seconds > 0) {
		printf("\tDelay [%llu] seconds... (after move to new band)\n", delay_seconds);		
		sleep(delay_seconds);
		errno = 0;
	}		

	qsort ((void *)info, pid_count, sizeof(pidinfo_t),priority_cmp);

	/*
	 * Verify that the list of pids have been placed in new priority band
	 * and that they are in the same relative priority order.
	 * The relative bucket placement before moving to the new priority
	 * band should be the same as that after moving to the new
	 * priority band.
	 */
	error = 0;
	for (i=0; i < pid_count; i++) {
		if (info[i].pri_before == -1){
			/* skip... this pid did not exist */
			continue;
		}

		/* The new priority band must meet expectations */
		if (info[i].pri_after != info[i].exp_after) {
			error++;
		}
		
		if (i+1 == pid_count)
			break;  /* Done traversing list */

		if (info[i].pid == info[i+1].pid) {
			/* skip duplicate pids */
			continue;
		}
			
		if (info[i].indx_before < info[i+1].indx_before &&
		    info[i].indx_after < info[i+1].indx_after &&
		    info[i].pri_before <= info[i+1].pri_before &&
		    info[i].pri_after <= info[i+1].pri_after ) {
			/* yay */
		}
		else {
			error++;
		}
	}

	printf("\tFound [%d] verification errors.\n", error);
	
	if (error || errno || verbose_flag==TRUE) {
		dump_info_table(info, pid_count);
	}

out:	
	printf("\n\tExpect: error (0), errno (0)\n");
	printf("\tActual: error (%d), errno (%d)\n", error, errno);
	if (error != 0 || errno != 0)
		passflag = FALSE;
	else
		passflag = TRUE;
	printTestResult(g_testname, passflag, NULL);
}

/*
 * The concept of jetsam priority order can actually be viewed as
 * the relative index of an item in a bucket from from lowest
 * priority bucket to highest priority bucket and then from
 * head bucket entry to tail bucket entry.
 * In reality, we have a linear, ordered list at any point
 * in time.
 */


static int
priority_cmp(const void *x, const void *y)
{
	pidinfo_t      entry_x = *((pidinfo_t *)x);
	pidinfo_t      entry_y = *((pidinfo_t *)y);

	if (entry_x.pri_before < entry_y.pri_before)
		return -1;
	if (entry_x.pri_before == entry_y.pri_before) {
		/*
		 * Second level ordering.
		 */
		if (entry_x.indx_before < entry_y.indx_before)
			return -1;
		if (entry_x.indx_before == entry_y.indx_before)
			return 0;   /* never */
		return 1;
	}
	return 1;
}


static boolean_t
do_get_priority_list (boolean_t before, memorystatus_priority_entry_t *mypids, size_t pid_count, pidinfo_t *pidinfo)
{
#pragma unused (mypids)
	
	size_t size = 0;
	memorystatus_priority_entry_t *list;
	size_t list_count = 0;
	int found = 0;
	int i, j;

	size = memorystatus_control(MEMORYSTATUS_CMD_GET_PRIORITY_LIST, 0, 0, NULL, 0);
	if (size <= 0 ) {
		printf("\tCan't get jetsam priority list size: %s\n", strerror(errno));
		return(FALSE);
	}

	list = (memorystatus_priority_entry_t *)malloc(size);

	size = memorystatus_control(MEMORYSTATUS_CMD_GET_PRIORITY_LIST, 0, 0, list, size);
	if (size <= 0) {
		printf("\tCould not get jetsam priority list: %s\n", strerror(errno));
		free(list);
		return(FALSE);
	}

	/* recompute number of entries in the list and find the pid's priority*/
	list_count = size / sizeof(memorystatus_priority_entry_t);
	
	printf("\tFound [%d] jetsam bucket entries (%s move to new band).\n",
	    (int)list_count, before? "before" : " after");
	
	for (i=0; i < pid_count; i++) {
		for (j=0; j < list_count; j++) {
			if (list[j].pid == pidinfo[i].pid) {
				if (before) {
					/*
					 * Save process's priority and relative index
					 * before moving to new priority
					 */
					pidinfo[i].pri_before = list[j].priority;
					pidinfo[i].indx_before = j;
				}else {
					/*
					 * Save process's priority and relative index
					 * after moving to new priority
					 */
					pidinfo[i].pri_after = list[j].priority;
					pidinfo[i].indx_after = j;
				}
				break;
			}
		}
	}

	if (list)
		free(list);
	
	return(TRUE);
}



static
void do_generate_test (memorystatus_priority_entry_t *list, uint32_t pid_count)
{
	int launch_errors = 0;
	int i;
	memorystatus_priority_properties_t mp;

	/* Generate mode Setup phase */

	if (pid_count <= 0)
		return;

	for (i=0; i < pid_count; i++) {
		list[i].pid = fork();
		list[i].priority = g_new_priority;     /*XXX introduce multiple
							 new priorities??? */
		switch (list[i].pid) {
		case 0: /* child */
			do_child_labor();
			exit(0);
			break;
		case -1:
			launch_errors++;
			break;
		default:
			continue;
		}
	}

	/*
	 * Parent will set the priority of the
	 * child processes
	 */

	if (verbose_flag && launch_errors > 0)
		printf("\tParent launch errors = %d\n", launch_errors);

	/* Introduce a case where pid is not found */
	kill_pid_indx = pid_count/2 ;
	kill(list[kill_pid_indx].pid, SIGKILL);
	sleep(5);
	
	do_control_list_test (list, pid_count);

	for (i=0; i < pid_count; i++) {
		if (i != kill_pid_indx) {
			kill(list[i].pid, SIGKILL );
		}
	}
}


static void
do_child_labor()
{
	/*
	 * Ideally, the process should be suspended,
	 * but letting it spin doing random
	 * stuff should be harmless for this test.
	 */
	if (verbose_flag)
		printf("\tLaunched child pid [%d]\n", getpid());
	while (TRUE) {
		random();
		sleep(5);
	}
}


static void
dump_info_table(pidinfo_t *info, uint32_t count)
{
	int i;

	/*
	 * The random priority value is only of interest in the
	 * generate_flag path, and even then, it's not really 
	 * that interesting!  So, not dumped here.
	 * But it is evident in the Jetsam Priority 'before' column.
	 */

	printf("\n%10s \t%s \t\t%20s\n", "Pid", "Jetsam Priority", "Relative Bucket Index");
	printf("%10s \t%s %20s\n", "", "(before | after | expected)", "(before | after)");
	
	for (i=0; i < count; i++) {
		printf("%10d",       info[i].pid);
		printf("\t(%4d |",   info[i].pri_before);
		printf("%4d |",      info[i].pri_after);
		printf("%4d)",       info[i].exp_after);
		printf("\t\t(%5d |", info[i].indx_before);
		printf("%5d)\n",     info[i].indx_after);
	}
}	

static void
print_usage() {

	printf("\nUsage:\n");
	printf("[-e] [-p] [-v] [-d <seconds>][ -g <count> | -l <list of pids>]\n\n");
	printf("Exercise the MEMORYSTATUS_CMD_GRP_SET_PROPERTIES command.\n");
	printf("Operates on at most %d pids.\n", MAXTESTPIDS);
	printf("Pass in a list of pids or allow the test to generate the pids dynamically.\n\n");

	printf("\t -e		     : exercise error tests\n");
	printf("\t -p <priority>     : Override default priority band.\n");
	printf("\t -v                : extra verbosity\n");
	printf("\t -d <seconds>      : delay before and after idle move (default = 0)\n");
	printf("\t -g <count>        : dynamically generate <count> processes.\n");
	printf("\t -l <list of pids> : operate on the given list of pids\n\n");
	printf("\t default	     : generate %d pids, no delay, priority %d  eg: -g %d -p %d\n\n",
	    MAXTESTPIDS, g_new_priority, MAXTESTPIDS, g_new_priority);
}
