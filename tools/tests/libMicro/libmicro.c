/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the "License").  You may not use this file except
 * in compliance with the License.
 *
 * You can obtain a copy of the license at
 * src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing
 * permissions and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * HEADER in each file and include the License file at
 * usr/src/OPENSOLARIS.LICENSE.  If applicable,
 * add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your
 * own identifying information: Portions Copyright [yyyy]
 * [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * benchmarking routines
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <poll.h>
#include <pthread.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/resource.h>
#include <math.h>
#include <limits.h>

#ifdef	__sun
#include <sys/elf.h>
#endif

#include "libmicro.h"


#if defined(__APPLE__)
#include <mach/mach_time.h>

long long
gethrtime(void)
{
   long long        elapsed;
   static long long        start;
   static mach_timebase_info_data_t    sTimebaseInfo = { 0, 0 };

   // If this is the first time we've run, get the timebase.
   // We can use denom == 0 to indicate that sTimebaseInfo is
   // uninitialised because it makes no sense to have a zero
   // denominator in a fraction.

   if ( sTimebaseInfo.denom == 0 ) {
       (void) mach_timebase_info(&sTimebaseInfo);
		start = mach_absolute_time();
   }

   elapsed = mach_absolute_time() - start;

   // Convert to nanoseconds.
	// return (elapsed * (long long)sTimebaseInfo.numer)/(long long)sTimebaseInfo.denom;
	
	// Provided the final result is representable in 64 bits the following maneuver will
	// deliver that result without intermediate overflow.
	if (sTimebaseInfo.denom == sTimebaseInfo.numer)
		return elapsed;
	else if (sTimebaseInfo.denom == 1)
		return elapsed * (long long)sTimebaseInfo.numer;
	else {
       // Decompose elapsed = eta32 * 2^32 + eps32:
       long long eta32 = elapsed >> 32;
       long long eps32 = elapsed & 0x00000000ffffffffLL;

       long long numer = sTimebaseInfo.numer, denom = sTimebaseInfo.denom;

       // Form product of elapsed64 (decomposed) and numer:
       long long mu64 = numer * eta32;
       long long lambda64 = numer * eps32;

       // Divide the constituents by denom:
       long long q32 = mu64/denom;
       long long r32 = mu64 - (q32 * denom); // mu64 % denom

       return (q32 << 32) + ((r32 << 32) + lambda64)/denom;
	}
}

#endif

/*
 * user visible globals
 */

int				lm_argc = 0;
char **				lm_argv = NULL;

int				lm_opt1;
int				lm_optA;
int				lm_optB;
int				lm_optC = 100;
int				lm_optD;
int				lm_optE;
int				lm_optH;
int				lm_optI;
int				lm_optL = 0;
int				lm_optM = 0;
char				*lm_optN;
int				lm_optP;
int				lm_optS;
int				lm_optT;
int				lm_optW;

int				lm_def1 = 0;
int				lm_defB = 0; /* use lm_nsecs_per_op */
int				lm_defD = 10;
int				lm_defH = 0;
char				*lm_defN = NULL;
int				lm_defP = 1;

int				lm_defS = 0;
int				lm_defT = 1;

/*
 * default on fast platform, should be overridden by individual
 * benchmarks if significantly wrong in either direction.
 */

int				lm_nsecs_per_op = 5;

char				*lm_procpath;
char				lm_procname[STRSIZE];
char				lm_usage[STRSIZE];
char				lm_optstr[STRSIZE];
char				lm_header[STRSIZE];
size_t				lm_tsdsize = 0;


/*
 *  Globals we do not export to the user
 */

static barrier_t		*lm_barrier;
static pid_t			*pids = NULL;
static pthread_t		*tids = NULL;
static int			pindex = -1;
static void			*tsdseg = NULL;
static size_t			tsdsize = 0;

#ifdef USE_RDTSC
static long long		lm_hz = 0;
#endif


/*
 * Forward references
 */

static void 		worker_process();
static void 		usage();
static void 		print_stats(barrier_t *);
static void 		print_histo(barrier_t *);
static int 		remove_outliers(double *, int, stats_t *);
static long long	nsecs_overhead;
static long long	nsecs_resolution;
static long long	get_nsecs_overhead();
static int		crunch_stats(double *, int, stats_t *);
static void 		compute_stats(barrier_t *);
/*
 * main routine; renamed in this file to allow linking with other
 * files
 */

int
actual_main(int argc, char *argv[])
{
	int			i;
	int			opt;
	extern char		*optarg;
	char			*tmp;
	char			optstr[256];
	barrier_t		*b;
	long long		startnsecs = getnsecs();

#ifdef USE_RDTSC
	if (getenv("LIBMICRO_HZ") == NULL) {
		(void) printf("LIBMICRO_HZ needed but not set\n");
		exit(1);
	}
	lm_hz = strtoll(getenv("LIBMICRO_HZ"), NULL, 10);
#endif

	lm_argc = argc;
	lm_argv = argv;

	/* before we do anything */
	(void) benchmark_init();


	nsecs_overhead = get_nsecs_overhead();
	nsecs_resolution = get_nsecs_resolution();

	/*
	 * Set defaults
	 */

	lm_opt1	= lm_def1;
	lm_optB	= lm_defB;
	lm_optD	= lm_defD;
	lm_optH	= lm_defH;
	lm_optN	= lm_defN;
	lm_optP	= lm_defP;

	lm_optS	= lm_defS;
	lm_optT	= lm_defT;

	/*
	 * squirrel away the path to the current
	 * binary in a way that works on both
	 * Linux and Solaris
	 */

	if (*argv[0] == '/') {
		lm_procpath = strdup(argv[0]);
		*strrchr(lm_procpath, '/') = 0;
	} else {
		char path[1024];
		(void) getcwd(path, 1024);
		(void) strcat(path, "/");
		(void) strcat(path, argv[0]);
		*strrchr(path, '/') = 0;
		lm_procpath = strdup(path);
	}

	/*
	 * name of binary
	 */

	if ((tmp = strrchr(argv[0], '/')) == NULL)
		(void) strcpy(lm_procname, argv[0]);
	else
		(void) strcpy(lm_procname, tmp + 1);

	if (lm_optN == NULL) {
		lm_optN = lm_procname;
	}

	/*
	 * Parse command line arguments
	 */

	(void) sprintf(optstr, "1AB:C:D:EHI:LMN:P:RST:VW?%s", lm_optstr);
	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
		case '1':
			lm_opt1 = 1;
			break;
		case 'A':
			lm_optA = 1;
			break;
		case 'B':
			lm_optB = sizetoint(optarg);
			break;
		case 'C':
			lm_optC = sizetoint(optarg);
			break;
		case 'D':
			lm_optD = sizetoint(optarg);
			break;
		case 'E':
			lm_optE = 1;
			break;
		case 'H':
			lm_optH = 1;
			break;
		case 'I':
			lm_optI = sizetoint(optarg);
			break;
		case 'L':
			lm_optL = 1;
			break;
		case 'M':
			lm_optM = 1;
			break;
		case 'N':
			lm_optN = optarg;
			break;
		case 'P':
			lm_optP = sizetoint(optarg);
			break;
		case 'S':
			lm_optS = 1;
			break;
		case 'T':
			lm_optT = sizetoint(optarg);
			break;
		case 'V':
			(void) printf("%s\n", LIBMICRO_VERSION);
			exit(0);
			break;
		case 'W':
			lm_optW = 1;
			lm_optS = 1;
			break;
		case '?':
			usage();
			exit(0);
			break;
		default:
			if (benchmark_optswitch(opt, optarg) == -1) {
				usage();
				exit(0);
			}
		}
	}

	/* deal with implicit and overriding options */
	if (lm_opt1 && lm_optP > 1) {
		lm_optP = 1;
		(void) printf("warning: -1 overrides -P\n");
	}

	if (lm_optE) {
		(void) fprintf(stderr, "Running:%20s", lm_optN);
		(void) fflush(stderr);
	}

	if (lm_optB == 0) {
		/*
		 * neither benchmark or user has specified the number
		 * of cnts/sample, so use computed value
		 */
		if (lm_optI)
			lm_nsecs_per_op = lm_optI;
#define BLOCK_TOCK_DURATION 10000 /* number of raw timer "tocks" ideally comprising a block of work */
		lm_optB = nsecs_resolution * BLOCK_TOCK_DURATION / lm_nsecs_per_op;
		if (lm_optB == 0)
			lm_optB = 1;
	}

	/*
	 * now that the options are set
	 */

	if (benchmark_initrun() == -1) {
		exit(1);
	}

	/* allocate dynamic data */
	pids = (pid_t *)malloc(lm_optP * sizeof (pid_t));
	if (pids == NULL) {
		perror("malloc(pids)");
		exit(1);
	}
	tids = (pthread_t *)malloc(lm_optT * sizeof (pthread_t));
	if (tids == NULL) {
		perror("malloc(tids)");
		exit(1);
	}

	/* check that the case defines lm_tsdsize before proceeding */
	if (lm_tsdsize == (size_t)-1) {
		(void) fprintf(stderr, "error in benchmark_init: "
		    "lm_tsdsize not set\n");
		exit(1);
	}

	/* round up tsdsize to nearest 128 to eliminate false sharing */
	tsdsize = ((lm_tsdsize + 127) / 128) * 128;

	/* allocate sufficient TSD for each thread in each process */
	tsdseg = (void *)mmap(NULL, lm_optT * lm_optP * tsdsize + 8192,
	    PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0L);
	if (tsdseg == NULL) {
		perror("mmap(tsd)");
		exit(1);
	}

	/* initialise worker synchronisation */
	b = barrier_create(lm_optT * lm_optP, DATASIZE);
	if (b == NULL) {
		perror("barrier_create()");
		exit(1);
	}
	lm_barrier = b;
	b->ba_flag = 1;

	/* need this here so that parent and children can call exit() */
	(void) fflush(stdout);
	(void) fflush(stderr);

	/* when we started and when to stop */

	b->ba_starttime = getnsecs();
	b->ba_deadline = (long long) (b->ba_starttime + (lm_optD * 1000000LL));

	/* do the work */
	if (lm_opt1) {
		/* single process, non-fork mode */
		pindex = 0;
		worker_process();
	} else {
		/* create worker processes */
		for (i = 0; i < lm_optP; i++) {
			pids[i] = fork();

			switch (pids[i]) {
			case 0:
				pindex = i;
				worker_process();
				exit(0);
				break;
			case -1:
				perror("fork");
				exit(1);
				break;
			default:
				continue;
			}
		}

		/* wait for worker processes */
		for (i = 0; i < lm_optP; i++) {
			if (pids[i] > 0) {
				(void) waitpid(pids[i], NULL, 0);
			}
		}
	}

	b->ba_endtime = getnsecs();

	/* compute results */

	compute_stats(b);

	/* print arguments benchmark was invoked with ? */
	if (lm_optL) {
		int l;
		(void) printf("# %s ", argv[0]);
		for (l = 1; l < argc; l++) {
			(void) printf("%s ", argv[l]);
		}
		(void) printf("\n");
	}

	/* print result header (unless suppressed) */
	if (!lm_optH) {
		(void) printf("%12s %3s %3s %12s %12s %8s %8s %s\n",
		    "", "prc", "thr",
		    "usecs/call",
		    "samples", "errors", "cnt/samp", lm_header);
	}

	/* print result */

	(void) printf("%-12s %3d %3d %12.5f %12d %8lld %8d %s\n",
	    lm_optN, lm_optP, lm_optT,
	    (lm_optM?b->ba_corrected.st_mean:b->ba_corrected.st_median),
	    b->ba_batches, b->ba_errors, lm_optB,
	    benchmark_result());

	if (lm_optS) {
		print_stats(b);
	}

	/* just incase something goes awry */
	(void) fflush(stdout);
	(void) fflush(stderr);

	/* cleanup by stages */
	(void) benchmark_finirun();
	(void) barrier_destroy(b);
	(void) benchmark_fini();

	if (lm_optE) {
		(void) fprintf(stderr, " for %12.5f seconds\n",
		    (double)(getnsecs() - startnsecs) /
		    1.e9);
		(void) fflush(stderr);
	}
	return (0);
}

void *
worker_thread(void *arg)
{
	result_t		r;
	long long 		last_sleep = 0;
	long long		t;

	r.re_errors = benchmark_initworker(arg);

	while (lm_barrier->ba_flag) {
		r.re_count = 0;
		r.re_errors += benchmark_initbatch(arg);

		/* sync to clock */

		if (lm_optA && ((t = getnsecs()) - last_sleep) > 75000000LL) {
			(void) poll(0, 0, 10);
			last_sleep = t;
		}
		/* wait for it ... */
		(void) barrier_queue(lm_barrier, NULL);

		/* time the test */
		r.re_t0 = getnsecs();
		(void) benchmark(arg, &r);
		r.re_t1 = getnsecs();

		/* time to stop? */
		if (r.re_t1 > lm_barrier->ba_deadline &&
		    (!lm_optC || lm_optC < lm_barrier->ba_batches)) {
			lm_barrier->ba_flag = 0;
		}

		/* record results and sync */
		(void) barrier_queue(lm_barrier, &r);

		(void) benchmark_finibatch(arg);

		r.re_errors = 0;
	}

	(void) benchmark_finiworker(arg);

	return (0);
}

void
worker_process()
{
	int			i;
	void			*tsd;

	for (i = 1; i < lm_optT; i++) {
		tsd = gettsd(pindex, i);
		if (pthread_create(&tids[i], NULL, worker_thread, tsd) != 0) {
			perror("pthread_create");
			exit(1);
		}
	}

	tsd = gettsd(pindex, 0);
	(void) worker_thread(tsd);

	for (i = 1; i < lm_optT; i++) {
		(void) pthread_join(tids[i], NULL);
	}
}

void
usage()
{
	(void) printf(
	    "usage: %s\n"
	    "       [-1] (single process; overrides -P > 1)\n"
	    "       [-A] (align with clock)\n"
	    "       [-B batch-size (default %d)]\n"
	    "       [-C minimum number of samples (default 0)]\n"
	    "       [-D duration in msecs (default %ds)]\n"
	    "       [-E (echo name to stderr)]\n"
	    "       [-H] (suppress headers)\n"
	    "       [-I] nsecs per op (used to compute batch size)"
	    "       [-L] (print argument line)\n"
	    "       [-M] (reports mean rather than median)\n"
	    "       [-N test-name (default '%s')]\n"
	    "       [-P processes (default %d)]\n"
	    "       [-S] (print detailed stats)\n"
	    "       [-T threads (default %d)]\n"
	    "       [-V] (print the libMicro version and exit)\n"
	    "       [-W] (flag possible benchmark problems)\n"
	    "%s\n",
	    lm_procname,
	    lm_defB, lm_defD, lm_procname, lm_defP, lm_defT,
	    lm_usage);
}

void
print_warnings(barrier_t *b)
{
	int head = 0;
	int increase;

	if (b->ba_quant) {
		if (!head++) {
			(void) printf("#\n# WARNINGS\n");
		}
		increase = (int)(floor((nsecs_resolution * 100.0) /
		    ((double)lm_optB * b->ba_corrected.st_median * 1000.0)) +
		    1.0);
		(void) printf("#     Quantization error likely;"
		    "increase batch size (-B option) %dX to avoid.\n",
		    increase);
	}

	/*
	 * XXX should warn on median != mean by a lot
	 */

	if (b->ba_errors) {
		if (!head++) {
			(void) printf("#\n# WARNINGS\n");
		}
		(void) printf("#     Errors occured during benchmark.\n");
	}
}

void
print_stats(barrier_t *b)
{
	(void) printf("#\n");
	(void) printf("# STATISTICS         %12s          %12s\n",
	    "usecs/call (raw)",
	    "usecs/call (outliers removed)");

	if (b->ba_count == 0) {
		(void) printf("zero samples\n");
		return;
	}

	(void) printf("#                    min %12.5f            %12.5f\n",
	    b->ba_raw.st_min,
	    b->ba_corrected.st_min);

	(void) printf("#                    max %12.5f            %12.5f\n",
	    b->ba_raw.st_max,
	    b->ba_corrected.st_max);
	(void) printf("#                   mean %12.5f            %12.5f\n",
	    b->ba_raw.st_mean,
	    b->ba_corrected.st_mean);
	(void) printf("#                 median %12.5f            %12.5f\n",
	    b->ba_raw.st_median,
	    b->ba_corrected.st_median);
	(void) printf("#                 stddev %12.5f            %12.5f\n",
	    b->ba_raw.st_stddev,
	    b->ba_corrected.st_stddev);
	(void) printf("#         standard error %12.5f            %12.5f\n",
	    b->ba_raw.st_stderr,
	    b->ba_corrected.st_stderr);
	(void) printf("#   99%% confidence level %12.5f            %12.5f\n",
	    b->ba_raw.st_99confidence,
	    b->ba_corrected.st_99confidence);
	(void) printf("#                   skew %12.5f            %12.5f\n",
	    b->ba_raw.st_skew,
	    b->ba_corrected.st_skew);
	(void) printf("#               kurtosis %12.5f            %12.5f\n",
	    b->ba_raw.st_kurtosis,
	    b->ba_corrected.st_kurtosis);

	(void) printf("#       time correlation %12.5f            %12.5f\n",
	    b->ba_raw.st_timecorr,
	    b->ba_corrected.st_timecorr);
	(void) printf("#\n");

	(void) printf("#           elasped time %12.5f\n", (b->ba_endtime -
	    b->ba_starttime) / 1.0e9);
	(void) printf("#      number of samples %12d\n",   b->ba_batches);
	(void) printf("#     number of outliers %12d\n", b->ba_outliers);
	(void) printf("#      getnsecs overhead %12d\n", (int)nsecs_overhead);

	(void) printf("#\n");
	(void) printf("# DISTRIBUTION\n");

	print_histo(b);

	if (lm_optW) {
		print_warnings(b);
	}
}

void
update_stats(barrier_t *b, result_t *r)
{
	double			time;
	double			nsecs_per_call;

	if (b->ba_waiters == 0) {
		/* first thread only */
		b->ba_t0 = r->re_t0;
		b->ba_t1 = r->re_t1;
		b->ba_count0 = 0;
		b->ba_errors0 = 0;
	} else {
		/* all but first thread */
		if (r->re_t0 < b->ba_t0) {
			b->ba_t0 = r->re_t0;
		}
		if (r->re_t1 > b->ba_t1) {
			b->ba_t1 = r->re_t1;
		}
	}

	b->ba_count0  += r->re_count;
	b->ba_errors0 += r->re_errors;

	if (b->ba_waiters == b->ba_hwm - 1) {
		/* last thread only */


		time = (double)b->ba_t1 - (double)b->ba_t0 -
		    (double)nsecs_overhead;

		if (time < 100 * nsecs_resolution)
			b->ba_quant++;

		/*
		 * normalize by procs * threads if not -U
		 */

		nsecs_per_call = time / (double)b->ba_count0 *
		    (double)(lm_optT * lm_optP);

		b->ba_count  += b->ba_count0;
		b->ba_errors += b->ba_errors0;

		b->ba_data[b->ba_batches % b->ba_datasize] =
		    nsecs_per_call;

		b->ba_batches++;
	}
}

#ifdef USE_SEMOP
barrier_t *
barrier_create(int hwm, int datasize)
{
	struct sembuf		s[1];
	barrier_t		*b;

	/*LINTED*/
	b = (barrier_t *)mmap(NULL,
	    sizeof (barrier_t) + (datasize - 1) * sizeof (double),
	    PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANON, -1, 0L);
	if (b == (barrier_t *)MAP_FAILED) {
		return (NULL);
	}
	b->ba_datasize = datasize;

	b->ba_flag  = 0;
	b->ba_hwm   = hwm;
	b->ba_semid = semget(IPC_PRIVATE, 3, 0600);
	if (b->ba_semid == -1) {
		(void) munmap((void *)b, sizeof (barrier_t));
		return (NULL);
	}

	/* [hwm - 1, 0, 0] */
	s[0].sem_num = 0;
	s[0].sem_op  = hwm - 1;
	s[0].sem_flg = 0;
	if (semop(b->ba_semid, s, 1) == -1) {
		perror("semop(1)");
		(void) semctl(b->ba_semid, 0, IPC_RMID);
		(void) munmap((void *)b, sizeof (barrier_t));
		return (NULL);
	}

	b->ba_waiters = 0;
	b->ba_phase = 0;

	b->ba_count = 0;
	b->ba_errors = 0;

	return (b);
}

int
barrier_destroy(barrier_t *b)
{
	(void) semctl(b->ba_semid, 0, IPC_RMID);
	(void) munmap((void *)b, sizeof (barrier_t));

	return (0);
}

int
barrier_queue(barrier_t *b, result_t *r)
{
	struct sembuf		s[2];

	/*
	 * {s0(-(hwm-1))}
	 * if ! nowait {s1(-(hwm-1))}
	 *   (all other threads)
	 *   update shared stats
	 *   {s0(hwm-1), s1(1)}
	 *   {s0(1), s2(-1)}
	 * else
	 *   (last thread)
	 *   update shared stats
	 *   {s2(hwm-1)}
	 */

	s[0].sem_num = 0;
	s[0].sem_op  = -(b->ba_hwm - 1);
	s[0].sem_flg = 0;
	if (semop(b->ba_semid, s, 1) == -1) {
		perror("semop(2)");
		return (-1);
	}

	s[0].sem_num = 1;
	s[0].sem_op  = -(b->ba_hwm - 1);
	s[0].sem_flg = IPC_NOWAIT;
	if (semop(b->ba_semid, s, 1) == -1) {
		if (errno != EAGAIN) {
			perror("semop(3)");
			return (-1);
		}

		/* all but the last thread */

		if (r != NULL) {
			update_stats(b, r);
		}

		b->ba_waiters++;

		s[0].sem_num = 0;
		s[0].sem_op  = b->ba_hwm - 1;
		s[0].sem_flg = 0;
		s[1].sem_num = 1;
		s[1].sem_op  = 1;
		s[1].sem_flg = 0;
		if (semop(b->ba_semid, s, 2) == -1) {
			perror("semop(4)");
			return (-1);
		}

		s[0].sem_num = 0;
		s[0].sem_op  = 1;
		s[0].sem_flg = 0;
		s[1].sem_num = 2;
		s[1].sem_op  = -1;
		s[1].sem_flg = 0;
		if (semop(b->ba_semid, s, 2) == -1) {
			perror("semop(5)");
			return (-1);
		}

	} else {
		/* the last thread */

		if (r != NULL) {
			update_stats(b, r);
		}

		b->ba_waiters = 0;
		b->ba_phase++;

		s[0].sem_num = 2;
		s[0].sem_op  = b->ba_hwm - 1;
		s[0].sem_flg = 0;
		if (semop(b->ba_semid, s, 1) == -1) {
			perror("semop(6)");
			return (-1);
		}
	}

	return (0);
}

#else /* USE_SEMOP */

barrier_t *
barrier_create(int hwm, int datasize)
{
	pthread_mutexattr_t	attr;
	pthread_condattr_t	cattr;
	barrier_t		*b;

	/*LINTED*/
	b = (barrier_t *)mmap(NULL,
	    sizeof (barrier_t) + (datasize - 1) * sizeof (double),
	    PROT_READ | PROT_WRITE,
	    MAP_SHARED | MAP_ANON, -1, 0L);
	if (b == (barrier_t *)MAP_FAILED) {
		return (NULL);
	}
	b->ba_datasize = datasize;

	b->ba_hwm = hwm;
	b->ba_flag  = 0;

	(void) pthread_mutexattr_init(&attr);
	(void) pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);

	(void) pthread_condattr_init(&cattr);
	(void) pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);

	(void) pthread_mutex_init(&b->ba_lock, &attr);
	(void) pthread_cond_init(&b->ba_cv, &cattr);

	b->ba_waiters = 0;
	b->ba_phase = 0;

	b->ba_count = 0;
	b->ba_errors = 0;

	return (b);
}

int
barrier_destroy(barrier_t *b)
{
	(void) munmap((void *)b, sizeof (barrier_t));

	return (0);
}

int
barrier_queue(barrier_t *b, result_t *r)
{
	int			phase;

	(void) pthread_mutex_lock(&b->ba_lock);

	if (r != NULL) {
		update_stats(b, r);
	}

	phase = b->ba_phase;

	b->ba_waiters++;
	if (b->ba_hwm == b->ba_waiters) {
		b->ba_waiters = 0;
		b->ba_phase++;
		(void) pthread_cond_broadcast(&b->ba_cv);
	}

	while (b->ba_phase == phase) {
		(void) pthread_cond_wait(&b->ba_cv, &b->ba_lock);
	}

	(void) pthread_mutex_unlock(&b->ba_lock);
	return (0);
}
#endif /* USE_SEMOP */

int
gettindex()
{
	int			i;

	if (tids == NULL) {
		return (-1);
	}

	for (i = 1; i < lm_optT; i++) {
		if (pthread_self() == tids[i]) {
			return (i);
		}
	}

	return (0);
}

int
getpindex()
{
	return (pindex);
}

void *
gettsd(int p, int t)
{
	if ((p < 0) || (p >= lm_optP) || (t < 0) || (t >= lm_optT))
		return (NULL);

	return ((void *)((unsigned long)tsdseg +
	    (((p * lm_optT) + t) * tsdsize)));
}

#if defined(__APPLE__)
int
gettsdindex(void *arg){
        /*
         * gettindex() can race with pthread_create() filling in tids[].
         * This is an alternative approach to finding the calling thread's tsd in t
sdseg
         */
        return tsdsize ? ((unsigned long)arg - (unsigned long)tsdseg)/tsdsize : 0;
}
#endif /* __APPLE__ */

#ifdef USE_GETHRTIME
long long
getnsecs()
{
	return (gethrtime());
}

long long
getusecs()
{
	return (gethrtime() / 1000);
}

#elif USE_RDTSC /* USE_GETHRTIME */

__inline__ long long
rdtsc(void)
{
	unsigned long long x;
	__asm__ volatile(".byte 0x0f, 0x31" : "=A" (x));
	return (x);
}

long long
getusecs()
{
	return (rdtsc() * 1000000 / lm_hz);
}

long long
getnsecs()
{
	return (rdtsc() * 1000000000 / lm_hz);
}

#else /* USE_GETHRTIME */

long long
getusecs()
{
	struct timeval		tv;

	(void) gettimeofday(&tv, NULL);

	return ((long long)tv.tv_sec * 1000000LL + (long long) tv.tv_usec);
}

long long
getnsecs()
{
	struct timeval		tv;

	(void) gettimeofday(&tv, NULL);

	return ((long long)tv.tv_sec * 1000000000LL +
	    (long long) tv.tv_usec * 1000LL);
}

#endif /* USE_GETHRTIME */

int
setfdlimit(int limit)
{
	struct rlimit rlimit;

	if (getrlimit(RLIMIT_NOFILE, &rlimit) < 0) {
		perror("getrlimit");
		exit(1);
	}

	if (rlimit.rlim_cur > limit)
		return (0); /* no worries */

	rlimit.rlim_cur = limit;

	if (rlimit.rlim_max < limit)
		rlimit.rlim_max = limit;

	if (setrlimit(RLIMIT_NOFILE, &rlimit) < 0) {
		perror("setrlimit");
		exit(3);
	}

	return (0);
}


#define	KILOBYTE		1024
#define	MEGABYTE		(KILOBYTE * KILOBYTE)
#define	GIGABYTE		(KILOBYTE * MEGABYTE)

long long
sizetoll(const char *arg)
{
	int			len = strlen(arg);
	int			i;
	long long		mult = 1;

	if (len && isalpha(arg[len - 1])) {
		switch (arg[len - 1]) {

		case 'k':
		case 'K':
			mult = KILOBYTE;
			break;
		case 'm':
		case 'M':
			mult = MEGABYTE;
			break;
		case 'g':
		case 'G':
			mult = GIGABYTE;
			break;
		default:
			return (-1);
		}

		for (i = 0; i < len - 1; i++)
			if (!isdigit(arg[i]))
				return (-1);
	}

	return (mult * strtoll(arg, NULL, 10));
}

int
sizetoint(const char *arg)
{
	int			len = strlen(arg);
	int			i;
	long long		mult = 1;

	if (len && isalpha(arg[len - 1])) {
		switch (arg[len - 1]) {

		case 'k':
		case 'K':
			mult = KILOBYTE;
			break;
		case 'm':
		case 'M':
			mult = MEGABYTE;
			break;
		case 'g':
		case 'G':
			mult = GIGABYTE;
			break;
		default:
			return (-1);
		}

		for (i = 0; i < len - 1; i++)
			if (!isdigit(arg[i]))
				return (-1);
	}

	return (mult * atoi(arg));
}

static void
print_bar(long count, long total)
{
	int			i;

	(void) putchar_unlocked(count ? '*' : ' ');
	for (i = 1; i < (32 * count) / total; i++)
		(void) putchar_unlocked('*');
	for (; i < 32; i++)
		(void) putchar_unlocked(' ');
}

static int
doublecmp(const void *p1, const void *p2)
{
	double a = *((double *)p1);
	double b = *((double *)p2);

	if (a > b)
		return (1);
	if (a < b)
		return (-1);
	return (0);
}

static void
print_histo(barrier_t *b)
{
	int			n;
	int			i;
	int			j;
	int			last;
	long long		maxcount;
	double			sum;
	long long		min;
	long long		scale;
	double			x;
	long long		y;
	long long		count;
	int			i95;
	double			p95;
	double			r95;
	double			m95;
	histo_t			*histo;

	(void) printf("#	%12s %12s %32s %12s\n", "counts", "usecs/call",
	    "", "means");

	/* calculate how much data we've captured */
	n = b->ba_batches > b->ba_datasize ? b->ba_datasize : b->ba_batches;

	/* find the 95th percentile - index, value and range */
	qsort((void *)b->ba_data, n, sizeof (double), doublecmp);
	min = b->ba_data[0] + 0.000001;
	i95 = n * 95 / 100;
	p95 = b->ba_data[i95];
	r95 = p95 - min + 1;

	/* find a suitable min and scale */
	i = 0;
	x = r95 / (HISTOSIZE - 1);
	while (x >= 10.0) {
		x /= 10.0;
		i++;
	}
	y = x + 0.9999999999;
	while (i > 0) {
		y *= 10;
		i--;
	}
	min /= y;
	min *= y;
	scale = y * (HISTOSIZE - 1);
	if (scale < (HISTOSIZE - 1)) {
		scale = (HISTOSIZE - 1);
	}

	/* create and initialise the histogram */
	histo = malloc(HISTOSIZE * sizeof (histo_t));
	for (i = 0; i < HISTOSIZE; i++) {
		histo[i].sum = 0.0;
		histo[i].count = 0;
	}

	/* populate the histogram */
	last = 0;
	sum = 0.0;
	count = 0;
	for (i = 0; i < i95; i++) {
		j = (HISTOSIZE - 1) * (b->ba_data[i] - min) / scale;

		if (j >= HISTOSIZE) {
			(void) printf("panic!\n");
			j = HISTOSIZE - 1;
		}

		histo[j].sum += b->ba_data[i];
		histo[j].count++;

		sum += b->ba_data[i];
		count++;
	}
	m95 = sum / count;

	/* find the larges bucket */
	maxcount = 0;
	for (i = 0; i < HISTOSIZE; i++)
		if (histo[i].count > 0) {
			last = i;
			if (histo[i].count > maxcount)
				maxcount = histo[i].count;
		}

	/* print the buckets */
	for (i = 0; i <= last; i++) {
		(void) printf("#       %12lld %12.5f |", histo[i].count,
		    (min + scale * (double)i / (HISTOSIZE - 1)));

		print_bar(histo[i].count, maxcount);

		if (histo[i].count > 0)
			(void) printf("%12.5f\n",
			    histo[i].sum / histo[i].count);
		else
			(void) printf("%12s\n", "-");
	}

	/* find the mean of values beyond the 95th percentile */
	sum = 0.0;
	count = 0;
	for (i = i95; i < n; i++) {
		sum += b->ba_data[i];
		count++;
	}

	/* print the >95% bucket summary */
	(void) printf("#\n");
	(void) printf("#       %12lld %12s |", count, "> 95%");
	print_bar(count, maxcount);
	if (count > 0)
		(void) printf("%12.5f\n", sum / count);
	else
		(void) printf("%12s\n", "-");
	(void) printf("#\n");
	(void) printf("#       %12s %12.5f\n", "mean of 95%", m95);
	(void) printf("#       %12s %12.5f\n", "95th %ile", p95);

	/* quantify any buffer overflow */
	if (b->ba_batches > b->ba_datasize)
		(void) printf("#       %12s %12d\n", "data dropped",
		    b->ba_batches - b->ba_datasize);
}

static void
compute_stats(barrier_t *b)
{
	int i;

	if (b->ba_batches > b->ba_datasize)
		b->ba_batches = b->ba_datasize;

	/*
	 * convert to usecs/call
	 */

	for (i = 0; i < b->ba_batches; i++)
		b->ba_data[i] /= 1000.0;

	/*
	 * do raw stats
	 */

	(void) crunch_stats(b->ba_data, b->ba_batches, &b->ba_raw);

	/*
	 * recursively apply 3 sigma rule to remove outliers
	 */

	b->ba_corrected = b->ba_raw;
	b->ba_outliers = 0;

	if (b->ba_batches > 40) { /* remove outliers */
		int removed;

		do {
			removed = remove_outliers(b->ba_data, b->ba_batches,
			    &b->ba_corrected);
			b->ba_outliers += removed;
			b->ba_batches -= removed;
			(void) crunch_stats(b->ba_data, b->ba_batches,
			    &b->ba_corrected);
			} while (removed != 0 && b->ba_batches > 40);
	}

}

/*
 * routine to compute various statistics on array of doubles.
 */

static int
crunch_stats(double *data, int count, stats_t *stats)
{
	double a;
	double std;
	double diff;
	double sk;
	double ku;
	double mean;
	int i;
	int bytes;
	double *dupdata;

	/*
	 * first we need the mean
	 */

	mean = 0.0;

	for (i = 0; i < count; i++) {
		mean += data[i];
	}

	mean /= count;

	stats->st_mean = mean;

	/*
	 * malloc and sort so we can do median
	 */

	dupdata = malloc(bytes = sizeof (double) * count);
	(void) memcpy(dupdata, data, bytes);
	qsort((void *)dupdata, count, sizeof (double), doublecmp);
	stats->st_median   = dupdata[count/2];

	/*
	 * reuse dupdata to compute time correlation of data to
	 * detect interesting time-based trends
	 */

	for (i = 0; i < count; i++)
		dupdata[i] = (double)i;

	(void) fit_line(dupdata, data, count, &a, &stats->st_timecorr);
	free(dupdata);

	std = 0.0;
	sk  = 0.0;
	ku  = 0.0;

	stats->st_max = -1;
	stats->st_min = 1.0e99; /* hard to find portable values */

	for (i = 0; i < count; i++) {
		if (data[i] > stats->st_max)
			stats->st_max = data[i];
		if (data[i] < stats->st_min)
			stats->st_min = data[i];

		diff = data[i] - mean;
		std += diff * diff;
		sk  += diff * diff * diff;
		ku  += diff * diff * diff * diff;
	}

	stats->st_stddev   = std = sqrt(std/(double)(count - 1));
	stats->st_stderr   = std / sqrt(count);
	stats->st_99confidence = stats->st_stderr * 2.326;
	stats->st_skew	   = sk / (std * std * std) / (double)(count);
	stats->st_kurtosis = ku / (std * std * std * std) /
	    (double)(count) - 3;

	return (0);
}

/*
 * does a least squares fit to the set of points x, y and
 * fits a line y = a + bx.  Returns a, b
 */

int
fit_line(double *x, double *y, int count, double *a, double *b)
{
	double sumx, sumy, sumxy, sumx2;
	double denom;
	int i;

	sumx = sumy = sumxy = sumx2 = 0.0;

	for (i = 0; i < count; i++) {
		sumx	+= x[i];
		sumx2	+= x[i] * x[i];
		sumy	+= y[i];
		sumxy	+= x[i] * y[i];
	}

	denom = count * sumx2 - sumx * sumx;

	if (denom == 0.0)
		return (-1);

	*a = (sumy * sumx2 - sumx * sumxy) / denom;

	*b = (count * sumxy - sumx * sumy) / denom;

	return (0);
}

/*
 * empty function for measurement purposes
 */

int
nop()
{
	return (1);
}

#define	NSECITER 1000

static long long
get_nsecs_overhead()
{
	long long s;

	double data[NSECITER];
	stats_t stats;

	int i;
	int count;
	int outliers;

	(void) getnsecs(); /* warmup */
	(void) getnsecs(); /* warmup */
	(void) getnsecs(); /* warmup */

	i = 0;

	count = NSECITER;

	for (i = 0; i < count; i++) {
		s = getnsecs();
		data[i] = getnsecs() - s;
	}

	(void) crunch_stats(data, count, &stats);

	while ((outliers = remove_outliers(data, count, &stats)) != 0) {
		count -= outliers;
		(void) crunch_stats(data, count, &stats);
	}

	return ((long long)stats.st_mean);

}

long long
get_nsecs_resolution()
{
	long long y[1000];

	int i, j, nops, res;
	long long start, stop;

	/*
	 * first, figure out how many nops to use
	 * to get any delta between time measurements.
	 * use a minimum of one.
	 */

	/*
	 * warm cache
	 */

	stop = start = getnsecs();

	for (i = 1; i < 10000000; i++) {
		start = getnsecs();
		for (j = i; j; j--)
			;
		stop = getnsecs();
		if (stop > start)
			break;
	}

	nops = i;

	/*
	 * now collect data at linearly varying intervals
	 */

	for (i = 0; i < 1000; i++) {
		start = getnsecs();
		for (j = nops * i; j; j--)
			;
		stop = getnsecs();
		y[i] = stop - start;
	}

	/*
	 * find smallest positive difference between samples;
	 * this is the timer resolution
	 */

	res = 1<<30;

	for (i = 1; i < 1000; i++) {
		int diff = y[i] - y[i-1];

		if (diff > 0 && res > diff)
			res = diff;

	}

	return (res);
}

/*
 * remove any data points from the array more than 3 sigma out
 */

static int
remove_outliers(double *data, int count, stats_t *stats)
{
	double outmin = stats->st_mean - 3 * stats->st_stddev;
	double outmax = stats->st_mean + 3 * stats->st_stddev;

	int i, j, outliers;

	for (outliers = i = j = 0; i < count; i++)
		if (data[i] > outmax || data[i] < outmin)
			outliers++;
		else
			data[j++] = data[i];

	return (outliers);
}
