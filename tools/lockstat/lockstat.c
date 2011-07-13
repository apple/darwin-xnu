#include <mach/mach.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <mach/error.h>
#include <mach/mach_error.h>
#include <mach/mig_errors.h>
#include <mach/machine.h>
#include <mach/processor_info.h>
#include <assert.h>
#include <nlist.h>
#include <fcntl.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/host_info.h>

/*
 *	lockstat.c
 *
 *	Utility to display kernel lock contention statistics.
 *	Usage:
 *	lockstat [all, spin, mutex, rw, <lock group name>] {<repeat interval>} {abs}
 *
 *	Argument 1 specifies the type of lock to display contention statistics
 *	for; alternatively, a lock group (a logically grouped set of locks,
 *	which can encompass multiple types of locks) can be specified by name.
 *	When argument 1 is "all", statistics are displayed for all lock groups
 *	which have statistics enabled.
 *	Lock types include mutexes, reader-writer locks and spin locks.
 *	Note that support for gathering contention statistics may not be present
 *	for all types of locks on all platforms.
 *
 *	Argument 2 specifies a periodic interval. The program will display an
 *	updated list of statistics every <repeat interval> seconds. This
 *	argument is optional. The updates display the deltas from the previous
 *	set of statistics, unless "abs" is specified as argument 3.
 *
 *	Argument 3, if "abs", causes the periodically refreshed lock statistics
 *	to be displayed as absolute values rather than deltas from the previous
 *	display.
 *
 *	Types of statistics:
 *	Acquisitions: These can include both normal acquisitions, as well
 *	as acquisition attempts. These are listed in the first column.
 *	Examples include calls to lck_mtx_lock and lck_mtx_try_lock
 *	Misses: Incremented if  a lock acquisition attempt failed, due to
 *	contention.
 *	Waits (Meaningful only for lock types that can block): Incremented
 *	if a lock acquisition attempt proceeded to block.
 *
 *	Direct Waits (currently implemented only on i386/x86_64): For adaptive
 *	locks, such as mutexes, incremented if the owner of the mutex
 *	wasn't active on another processor at the time of the lock
 *	attempt. This indicates that no adaptive spin occurred.
 */

/*
 * HISTORY
 * 2005: Bernard Semeria
 *		Created.
 * 2006: Derek Kumar
 *		Display i386 specific stats, fix incremental display, add
 *		explanatory block comment.
 */
void usage(void);
void print_spin_hdr(void);
void print_spin(int requested, lockgroup_info_t *lockgroup);
void print_all_spin(lockgroup_info_t *lockgroup);
void print_mutex_hdr(void);
void print_mutex(int requested, lockgroup_info_t *lockgroup);
void print_all_mutex(lockgroup_info_t *lockgroup);
void print_rw_hdr(void);
void print_rw(int requested, lockgroup_info_t *lockgroup);
void print_all_rw(lockgroup_info_t *lockgroup);
void prime_lockgroup_deltas(void);
void get_lockgroup_deltas(void);

char *pgmname;
mach_port_t host_control;

lockgroup_info_t	*lockgroup_info, *lockgroup_start, *lockgroup_deltas;
unsigned int		count;

unsigned int		gDebug = 1;

int
main(int argc, char **argv)
{
	kern_return_t		kr;
	int 			arg2;
	unsigned int 		i;
	int 			found;

	setlinebuf(stdout);

	pgmname = argv[0];
	gDebug = (NULL != strstr(argv[0], "debug"));

	host_control = mach_host_self();  

	kr = host_lockgroup_info(host_control, &lockgroup_info, &count);

	if (kr != KERN_SUCCESS)
	{
		mach_error("host_statistics", kr);
		exit (EXIT_FAILURE);
	}
	if (gDebug) {
		printf("count = %d\n", count);
		for (i = 0; i < count; i++) {
			printf("%s\n",lockgroup_info[i].lockgroup_name);
		}
	}

	switch (argc) {
	case 2:
		if (strcmp(argv[1], "all") == 0) {
			print_spin_hdr();
			print_all_spin(lockgroup_info);
			print_mutex_hdr();
			print_all_mutex(lockgroup_info);
			print_rw_hdr();
			print_all_rw(lockgroup_info);
		}
		else if (strcmp(argv[1], "spin") == 0) {
			print_spin_hdr();
			print_all_spin(lockgroup_info);
		}
		else if (strcmp(argv[1], "mutex") == 0) {
			print_mutex_hdr();
			print_all_mutex(lockgroup_info);
		}
		else if (strcmp(argv[1], "rw") == 0) {
			print_rw_hdr();
			print_all_rw(lockgroup_info);
		}
		else {
			found = 0;
			for (i = 0;i < count;i++) {
				if (strcmp(argv[1], lockgroup_info[i].lockgroup_name) == 0) {
					found = 1;
					print_spin_hdr();
					print_spin(i, lockgroup_info);
					print_mutex_hdr();
					print_mutex(i, lockgroup_info);
					print_rw_hdr();
					print_rw(i, lockgroup_info);
					break;
				}
			}
			if (found == 0) 
			{ usage(); }
		}
		break;	
	case 3:
		if (sscanf(argv[2], "%d", &arg2) != 1) {
			usage();
		}
		if (arg2 < 0) {
			usage();
		}
		prime_lockgroup_deltas();
		if (strcmp(argv[1], "all") == 0) {

			while (1) {
				sleep(arg2);
				get_lockgroup_deltas();
				print_spin_hdr();
				print_all_spin(lockgroup_deltas);
				print_mutex_hdr();
				print_all_mutex(lockgroup_deltas);
				print_rw_hdr();
				print_all_rw(lockgroup_deltas);
			}
		}
		else if (strcmp(argv[1], "spin") == 0) {

			while (1) {
				sleep(arg2);
				get_lockgroup_deltas();
				print_spin_hdr();
				print_all_spin(lockgroup_deltas);
			}
		}
		else if (strcmp(argv[1], "mutex") == 0) {

			while (1) {
				sleep(arg2);
				get_lockgroup_deltas();
				print_mutex_hdr();
				print_all_mutex(lockgroup_deltas);
			}
		}
		else if (strcmp(argv[1], "rw") == 0) {

			while (1) {
				sleep(arg2);
				get_lockgroup_deltas();
				print_rw_hdr();
				print_all_rw(lockgroup_deltas);
			}
		}
		else {

			found = 0;
			for (i = 0;i < count;i++) {
				if (strcmp(argv[1], lockgroup_info[i].lockgroup_name) == 0) {
					found = 1;
					while (1) {
						sleep(arg2);
						get_lockgroup_deltas();
						print_spin_hdr();
						print_spin(i, lockgroup_deltas);
						print_mutex_hdr();
						print_mutex(i, lockgroup_deltas);
						print_rw_hdr();
						print_rw(i, lockgroup_deltas);
					}
				}
			}
			if (found == 0)
			{ usage(); }
		}
		break;
	case 4:
		if (strcmp(argv[3], "abs") != 0)
		{ usage(); }
		if (sscanf(argv[2], "%d", &arg2) != 1)
		{ usage(); }
		if (strcmp(argv[1], "all") == 0) {
			while (1)
			{
				print_spin_hdr();
				print_all_spin(lockgroup_info);
				print_mutex_hdr();
				print_all_mutex(lockgroup_info);
				print_rw_hdr();
				print_all_rw(lockgroup_info);
				sleep(arg2);
			}
		}
		else if (strcmp(argv[1], "spin") == 0) {
			while (1)
			{print_all_spin(lockgroup_info);
				sleep(arg2);
			}
		}
		else if (strcmp(argv[1], "mutex") == 0) {
			print_mutex_hdr();
			while (1)
			{print_all_mutex(lockgroup_info);
				sleep(arg2);
			}
		}
		else if (strcmp(argv[1], "rw") == 0) {
			print_rw_hdr();
			while (1)
			{print_all_rw(lockgroup_info);
				sleep(arg2);
			}
		}
		else {
			found = 0;
			for (i = 0;i < count;i++) {
				if (strcmp(argv[1], lockgroup_info[i].lockgroup_name) == 0) {
					found = 1;
					while (1)
					{
						print_spin_hdr();
						print_spin(i, lockgroup_info);
						print_mutex_hdr();
						print_mutex(i, lockgroup_info);
						print_rw_hdr();
						print_rw(i, lockgroup_info);
						sleep(arg2);
					}
				}
			}
			if (found == 0)
			{ usage(); }
		}
		break;
	default:
		usage();
		break;
	}	

	exit(0);
}
 
void 
usage()
{
	fprintf(stderr, "Usage: %s [all, spin, mutex, rw, <lock group name>] {<repeat interval>} {abs}\n", pgmname);
	exit(EXIT_FAILURE);
}

void
print_spin_hdr(void)
{
	printf("    Spinlock acquires           misses   Name\n");
}

void
print_spin(int requested, lockgroup_info_t *lockgroup)
{
	lockgroup_info_t	*curptr = &lockgroup[requested];

	if (curptr->lock_spin_cnt != 0 && curptr->lock_spin_util_cnt != 0) {
		printf("%16lld ", curptr->lock_spin_util_cnt);
		printf("%16lld   ", curptr->lock_spin_miss_cnt);
		printf("%-14s\n", curptr->lockgroup_name);
	}
}

void
print_all_spin(lockgroup_info_t *lockgroup)
{
	unsigned int		i;

	for (i = 0;i < count;i++)
		print_spin(i, lockgroup);
        printf("\n");
}

void
print_mutex_hdr(void)
{
#if defined(__i386__) || defined(__x86_64__)
	printf("Mutex lock attempts  Misses      Waits Direct Waits Name\n");
#else
        printf("     mutex locks           misses            waits   name\n");
#endif
}

void
print_mutex(int requested, lockgroup_info_t *lockgroup)
{
	lockgroup_info_t	*curptr = &lockgroup[requested];

	if (curptr->lock_mtx_cnt != 0 && curptr->lock_mtx_util_cnt != 0) {
		printf("%16lld ", curptr->lock_mtx_util_cnt);
#if defined(__i386__) || defined(__x86_64__)
		printf("%10lld %10lld %10lld   ", curptr->lock_mtx_miss_cnt,  curptr->lock_mtx_wait_cnt, curptr->lock_mtx_held_cnt);
#else
		printf("%16lld %16lld   ", curptr->lock_mtx_miss_cnt,  curptr->lock_mtx_wait_cnt);
#endif
		printf("%-14s\n", curptr->lockgroup_name);
	}
}

void
print_all_mutex(lockgroup_info_t *lockgroup)
{
	unsigned int		i;

	for (i = 0;i < count;i++)
		print_mutex(i, lockgroup);
        printf("\n");

}

void
print_rw_hdr(void)
{
	printf("        RW locks           Misses            Waits   Name\n");
}

void
print_rw(int requested, lockgroup_info_t *lockgroup)
{
	lockgroup_info_t	*curptr = &lockgroup[requested];

	if (curptr->lock_rw_cnt != 0 && curptr->lock_rw_util_cnt != 0) {
		printf("%16lld ", curptr->lock_rw_util_cnt);
		printf("%16lld %16lld   ", curptr->lock_rw_miss_cnt,  curptr->lock_rw_wait_cnt);
		printf("%-14s\n", curptr->lockgroup_name);
	}
}

void
print_all_rw(lockgroup_info_t *lockgroup)
{
	unsigned int		i;

	for (i = 0;i < count;i++)
		print_rw(i, lockgroup);
        printf("\n");

}

void
prime_lockgroup_deltas(void)
{
	lockgroup_start = calloc(count, sizeof(lockgroup_info_t));
	if (lockgroup_start == NULL) {
		fprintf(stderr, "Can't allocate memory for lockgroup info\n");
		exit (EXIT_FAILURE);
	}
	memcpy(lockgroup_start, lockgroup_info, count * sizeof(lockgroup_info_t));

	lockgroup_deltas = calloc(count,  sizeof(lockgroup_info_t));
	if (lockgroup_deltas == NULL) {
		fprintf(stderr, "Can't allocate memory for lockgroup info\n");
		exit (EXIT_FAILURE);
	}
}

void
get_lockgroup_deltas(void)
{
	kern_return_t 			kr;
	unsigned int			i;

	kr = host_lockgroup_info(host_control, &lockgroup_info, &count);

	if (kr != KERN_SUCCESS)
	{
		mach_error("host_statistics", kr);
		exit (EXIT_FAILURE);
	}

	memcpy(lockgroup_deltas, lockgroup_info, count * sizeof(lockgroup_info_t));
	for (i = 0; i < count; i++) {
		lockgroup_deltas[i].lock_spin_util_cnt =
		    lockgroup_info[i].lock_spin_util_cnt -
		    lockgroup_start[i].lock_spin_util_cnt;
		lockgroup_deltas[i].lock_spin_miss_cnt =
		    lockgroup_info[i].lock_spin_miss_cnt -
		    lockgroup_start[i].lock_spin_miss_cnt;
		lockgroup_deltas[i].lock_mtx_util_cnt =
		    lockgroup_info[i].lock_mtx_util_cnt -
		    lockgroup_start[i].lock_mtx_util_cnt;
		lockgroup_deltas[i].lock_mtx_miss_cnt =
		    lockgroup_info[i].lock_mtx_miss_cnt -
		    lockgroup_start[i].lock_mtx_miss_cnt;
		lockgroup_deltas[i].lock_mtx_wait_cnt =
		    lockgroup_info[i].lock_mtx_wait_cnt -
		    lockgroup_start[i].lock_mtx_wait_cnt;
		lockgroup_deltas[i].lock_mtx_held_cnt =
		    lockgroup_info[i].lock_mtx_held_cnt -
		    lockgroup_start[i].lock_mtx_held_cnt;
		lockgroup_deltas[i].lock_rw_util_cnt =
		    lockgroup_info[i].lock_rw_util_cnt -
		    lockgroup_start[i].lock_rw_util_cnt;
		lockgroup_deltas[i].lock_rw_miss_cnt =
		    lockgroup_info[i].lock_rw_miss_cnt -
		    lockgroup_start[i].lock_rw_miss_cnt;
		lockgroup_deltas[i].lock_rw_wait_cnt =
		    lockgroup_info[i].lock_rw_wait_cnt -
		    lockgroup_start[i].lock_rw_wait_cnt;
	}
	memcpy(lockgroup_start, lockgroup_info, count * sizeof(lockgroup_info_t));
}
