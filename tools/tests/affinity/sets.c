#include <AvailabilityMacros.h>
#ifdef AVAILABLE_MAC_OS_X_VERSION_10_5_AND_LATER
#include </System/Library/Frameworks/System.framework/PrivateHeaders/mach/thread_policy.h>
#endif
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_time.h>
#include <pthread.h>
#include <sys/queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

/*
 * Sets is a multithreaded test/benchmarking program to evaluate
 * affinity set placement in Leopard.
 *
 * The picture here, for each set, is:
 *  
 *       free                   work
 *    -> queue --> producer --> queue --> consumer --
 *   |                                               |
 *    -----------------------------------------------
 *
 *       <------ "stage" -----> <------ "stage" ----->

 * We spin off sets of production line threads (2 sets by default).
 * All threads of each line sets the same affinity tag (unless disabled).
 * By default there are 2 stage (worker) threads per production line.
 * A worker thread removes a buffer from an input queue, processses it and
 * queues it on an output queue.  By default the initial stage (producer)
 * writes every byte in a buffer and the other (consumer) stages read every
 * byte. By default the buffers are 1MB (256 pages) in size but this can be
 * overidden.  By default there are 2 buffers per set (again overridable).
 * Worker threads process (iterate over) 10000 buffers by default.
 *
 * With affinity enabled, each producer and consumer thread sets its affinity
 * to the set number, 1 .. N. So the threads of each set share an L2 cache.
 *
 * Buffer management uses pthread mutex/condition variables. A thread blocks
 * when no buffer is available on a queue and it is signaled when a buffer
 * is placed on an empty queue. Queues are tailq'a a la <sys/queue.h>.
 * The queue management is centralized in a single routine: what queues to
 * use as input and output and what function to call for processing is
 * data-driven.
 */
  
pthread_mutex_t funnel;
pthread_cond_t	barrier;

uint64_t	timer;
int		threads;
int		threads_ready = 0;

int		iterations = 10000;
boolean_t	affinity = FALSE;
boolean_t	halting = FALSE;
boolean_t	cache_config = FALSE;
int		verbosity = 1;

typedef struct work {
	TAILQ_ENTRY(work)	link;
	int			*data;
} work_t;

/*
 * A work queue, complete with pthread objects for its management
 */
typedef struct work_queue {
	pthread_mutex_t		mtx;
	pthread_cond_t		cnd;
	TAILQ_HEAD(, work)	queue;
	boolean_t		waiters;
} work_queue_t;

/* Worker functions take a integer array and size */
typedef void (worker_fn_t)(int *, int); 

/* This struct controls the function of a thread */
typedef struct {
	int			stagenum;
	char			*name;
	worker_fn_t		*fn;
	work_queue_t		*input;		
	work_queue_t		*output;		
	struct line_info	*set;
	pthread_t		thread;
	work_queue_t		bufq;
} stage_info_t;

/* This defines a thread set */
#define WORKERS_MAX 10
typedef struct line_info {
	int			setnum;
	int			*data;
	int			isize;
	stage_info_t		*stage[WORKERS_MAX];
} line_info_t;

#define DBG(x...) do {				\
	if (verbosity > 1) {			\
		pthread_mutex_lock(&funnel);	\
		printf(x);			\
		pthread_mutex_unlock(&funnel);	\
	}					\
} while (0)

#define mutter(x...) do {			\
	if (verbosity > 0) {			\
		printf(x);			\
	}					\
} while (0)

#define s_if_plural(x)	(((x) > 1) ? "s" : "")

static void
usage()
{
	fprintf(stderr,
#ifdef AVAILABLE_MAC_OS_X_VERSION_10_5_AND_LATER
		"usage: sets [-a]   Turn affinity on (off)\n"
		"            [-b B] Number of buffers per set/line (2)\n"
#else
		"usage: sets [-b B] Number of buffers per set/line (2)\n"
#endif
		"            [-c]   Configure for max cache performance\n"
		"            [-h]   Print this\n"
		"            [-i I] Number of items/buffers to process (1000)\n"
		"            [-s S] Number of stages per set/line (2)\n"
		"            [-t]   Halt for keyboard input to start\n"
		"            [-p P] Number of pages per buffer (256=1MB)]\n"
		"            [-w]   Consumer writes data\n"
		"            [-v V] Level of verbosity 0..2 (1)\n"
		"            [N]    Number of sets/lines (2)\n"
	);
	exit(1);
}

/* Trivial producer: write to each byte */
void
writer_fn(int *data, int isize)
{
	int 	i;

	for (i = 0; i < isize; i++) {
		data[i] = i;
	}
}

/* Trivial consumer: read each byte */
void
reader_fn(int *data, int isize)
{
	int 	i;
	int	datum;

	for (i = 0; i < isize; i++) {
		datum = data[i];
	}
}

/* Consumer reading and writing the buffer */
void
reader_writer_fn(int *data, int isize)
{
	int 	i;

	for (i = 0; i < isize; i++) {
		data[i] += 1;
	}
}

/*
 * This is the central function for every thread.
 * For each invocation, its role is ets by (a pointer to) a stage_info_t.
 */
void *
manager_fn(void *arg)
{
	stage_info_t			*sp = (stage_info_t *) arg;
	line_info_t			*lp = sp->set;
	kern_return_t			ret;
	long				iteration = 0;

	/*
	 * If we're using affinity sets (we are by default)
	 * set our tag to by our thread set number.
	 */
#ifdef AVAILABLE_MAC_OS_X_VERSION_10_5_AND_LATER
	thread_extended_policy_data_t	epolicy;
	thread_affinity_policy_data_t	policy;

	epolicy.timeshare = FALSE;
	ret = thread_policy_set(
			mach_thread_self(), THREAD_EXTENDED_POLICY,
			(thread_policy_t) &epolicy,
			THREAD_EXTENDED_POLICY_COUNT);
	if (ret != KERN_SUCCESS)
		printf("thread_policy_set(THREAD_EXTENDED_POLICY) returned %d\n", ret);
	
	if (affinity) {
		policy.affinity_tag = lp->setnum;
		ret = thread_policy_set(
				mach_thread_self(), THREAD_AFFINITY_POLICY,
				(thread_policy_t) &policy,
				THREAD_AFFINITY_POLICY_COUNT);
		if (ret != KERN_SUCCESS)
			printf("thread_policy_set(THREAD_AFFINITY_POLICY) returned %d\n", ret);
	}
#endif

	DBG("Starting %s set: %d stage: %d\n", sp->name, lp->setnum, sp->stagenum);

	/*
	 * Start barrier.
	 * The tets thread to get here releases everyone and starts the timer.
	 */
	pthread_mutex_lock(&funnel);
	threads_ready++;
	if (threads_ready == threads) {
		pthread_mutex_unlock(&funnel);
		if (halting) {
			printf("  all threads ready for process %d, "
				"hit any key to start", getpid());
			fflush(stdout);
			(void) getchar();
		}
		pthread_cond_broadcast(&barrier);
		timer = mach_absolute_time();
	} else {
		pthread_cond_wait(&barrier, &funnel);
		pthread_mutex_unlock(&funnel);
	}

	do {
		int		i;
		work_t		*workp;

		/*
		 * Get a buffer from the input queue.
		 * Block if none.
		 */
		pthread_mutex_lock(&sp->input->mtx);
		while (1) {
			workp = TAILQ_FIRST(&(sp->input->queue));
			if (workp != NULL)
				break;
			DBG("    %s[%d,%d] iteration %d waiting for buffer\n",
				sp->name, lp->setnum, sp->stagenum, iteration);
			sp->input->waiters = TRUE;
			pthread_cond_wait(&sp->input->cnd, &sp->input->mtx);
			sp->input->waiters = FALSE;
		}
		TAILQ_REMOVE(&(sp->input->queue), workp, link);
		pthread_mutex_unlock(&sp->input->mtx);

		DBG("  %s[%d,%d] iteration %d work %p data %p\n",
			sp->name, lp->setnum, sp->stagenum, iteration, workp, workp->data);

		/* Do our stuff with the buffer */
		(void) sp->fn(workp->data, lp->isize);

		/*
		 * Place the buffer on the input queue.
		 * Signal  waiters if required.
		 */
		pthread_mutex_lock(&sp->output->mtx);
		TAILQ_INSERT_TAIL(&(sp->output->queue), workp, link);
		if (sp->output->waiters) {
			DBG("    %s[%d,%d] iteration %d signaling work\n",
				sp->name, lp->setnum, sp->stagenum, iteration);
			pthread_cond_signal(&sp->output->cnd);
		}
		pthread_mutex_unlock(&sp->output->mtx);
	} while (++iteration < iterations);

	DBG("Ending %s[%d,%d]\n", sp->name, lp->setnum, sp->stagenum);

	return (void *) iteration;
}

#define	MAX_CACHE_DEPTH 10
static void
auto_config(int npages, int *nbufs, int *nsets)
{
	int	len;
	int	ncpu;
	int	llc;
	int64_t	cacheconfig[MAX_CACHE_DEPTH];
	int64_t	cachesize[MAX_CACHE_DEPTH];

	mutter("Autoconfiguring...\n");

	len = sizeof(cacheconfig);
	if (sysctlbyname("hw.cacheconfig",
			 &cacheconfig[0], &len, NULL, 0) != 0) {
		printf("Unable to get hw.cacheconfig, %d\n", errno);
		exit(1);
	}
	len = sizeof(cachesize);
	if (sysctlbyname("hw.cachesize",
			 &cachesize[0],  &len, NULL, 0) != 0) {
		printf("Unable to get hw.cachesize, %d\n", errno);
		exit(1);
	}

	/*
	 * Find LLC
	 */
	for (llc = MAX_CACHE_DEPTH - 1; llc > 0; llc--)
		if (cacheconfig[llc] != 0)
			break;

	/*
	 * Calculate number of buffers of size pages*4096 bytes
	 * fit into 90% of an L2 cache.
	 */
	*nbufs = cachesize[llc] * 9 / (npages * 4096 * 10);
	mutter("  L%d (LLC) cache %qd bytes: "
		"using %d buffers of size %d bytes\n",
		llc, cachesize[llc], *nbufs, (npages * 4096));

	/* 
	 * Calcalute how many sets:
	 */
	*nsets = cacheconfig[0]/cacheconfig[llc];
	mutter("  %qd cpus; %qd cpus per L%d cache: using %d sets\n",
		cacheconfig[0], cacheconfig[llc], llc, *nsets);
}

void (*producer_fnp)(int *data, int isize) = &writer_fn;
void (*consumer_fnp)(int *data, int isize) = &reader_fn;

int
main(int argc, char *argv[])
{
	int			i;
	int			j;
	int			pages = 256; /* 1MB */
	int			buffers = 2;
	int			sets = 2;
	int			stages = 2;
	int			*status;
	line_info_t		*line_info;
	line_info_t		*lp;
	stage_info_t		*stage_info;
	stage_info_t		*sp;
	kern_return_t		ret;
	int			c;

	/* Do switch parsing: */
	while ((c = getopt (argc, argv, "ab:chi:p:s:twv:")) != -1) {
		switch (c) {
		case 'a':
#ifdef AVAILABLE_MAC_OS_X_VERSION_10_5_AND_LATER
			affinity = !affinity;
			break;
#else
			usage();
#endif
		case 'b':
			buffers = atoi(optarg);
			break;
		case 'c':
			cache_config = TRUE;
			break;
		case 'i':
			iterations = atoi(optarg);
			break;
		case 'p':
			pages = atoi(optarg);
			break;
		case 's':
			stages = atoi(optarg);
			if (stages >= WORKERS_MAX)
				usage();
			break;
		case 't':
			halting = TRUE;
			break;
		case 'w':
			consumer_fnp = &reader_writer_fn;
			break;
		case 'v':
			verbosity = atoi(optarg);
			break;
		case '?':
		case 'h':
		default:
			usage();
		}
	}
	argc -= optind; argv += optind;
	if (argc > 0)
		sets = atoi(*argv);

	if (cache_config)
		auto_config(pages, &buffers, &sets);

	pthread_mutex_init(&funnel, NULL);
	pthread_cond_init(&barrier, NULL);

	/*
 	 * Fire up the worker threads.
	 */
	threads = sets * stages;
	mutter("Launching %d set%s of %d threads with %saffinity, "
			"consumer reads%s data\n",
		sets, s_if_plural(sets), stages, affinity? "": "no ",
		(consumer_fnp == &reader_writer_fn)? " and writes" : "");
	if (pages < 256)
		mutter("  %dkB bytes per buffer, ", pages * 4);
	else
		mutter("  %dMB bytes per buffer, ", pages / 256);
	mutter("%d buffer%s per set ",
		buffers, s_if_plural(buffers));
	if (buffers * pages < 256)
		mutter("(total %dkB)\n", buffers * pages * 4);
	else
		mutter("(total %dMB)\n", buffers * pages / 256);
	mutter("  processing %d buffer%s...\n",
		iterations, s_if_plural(iterations));
	line_info = (line_info_t *) malloc(sets * sizeof(line_info_t));
	stage_info = (stage_info_t *) malloc(sets * stages * sizeof(stage_info_t));
	for (i = 0; i < sets; i++) {
		work_t	*work_array;

		lp = &line_info[i];

		lp->setnum = i + 1;
		lp->isize = pages * 4096 / sizeof(int);
		lp->data = (int *) malloc(buffers * pages * 4096);

		/* Set up the queue for the workers of this thread set: */
		for (j = 0; j < stages; j++) {
			sp = &stage_info[(i*stages) + j];
			sp->stagenum = j;
			sp->set = lp;
			lp->stage[j] = sp;
			pthread_mutex_init(&sp->bufq.mtx, NULL);
			pthread_cond_init(&sp->bufq.cnd, NULL);
			TAILQ_INIT(&sp->bufq.queue);
			sp->bufq.waiters = FALSE;
		}

		/*
		 * Take a second pass through the stages
		 * to define what the workers are and to interconnect their input/outputs
		 */
		for (j = 0; j < stages; j++) {
			sp = lp->stage[j];
			if (j == 0) {
				sp->fn = producer_fnp;
				sp->name = "producer";
			} else {
				sp->fn = consumer_fnp;
				sp->name = "consumer";
			}
			sp->input = &lp->stage[j]->bufq;
			sp->output = &lp->stage[(j + 1) % stages]->bufq;
		}

		/* Set up the buffers on the first worker of the set. */
		work_array = (work_t *)  malloc(buffers * sizeof(work_t));
		for (j = 0; j < buffers; j++) {
			work_array[j].data = lp->data + (lp->isize * j);	
			TAILQ_INSERT_TAIL(&lp->stage[0]->bufq.queue, &work_array[j], link);
			DBG("  empty work item %p for set %d data %p\n",
				&work_array[j], i, work_array[j].data);
		}

		/* Create this set of threads */
		for (j = 0; j < stages; j++) {
			if (ret = pthread_create(&lp->stage[j]->thread, NULL,
					&manager_fn,
					(void *) lp->stage[j]))
			err(1, "pthread_create %d,%d", i, j);
		}
	}

	/*
	 * We sit back anf wait for the slave to finish.
	 */
	for (i = 0; i < sets; i++) {
		lp = &line_info[i];
		for (j = 0; j < stages; j++) {
			if(ret = pthread_join(lp->stage[j]->thread, (void **)&status))
			    err(1, "pthread_join %d,%d", i, j);
			DBG("Thread %d,%d status %d\n", i, j, status);
		}
	}

	/*
	 * See how long the work took.
	 */
	timer = mach_absolute_time() - timer;
	timer = timer / 1000000ULL;
	printf("%d.%03d seconds elapsed.\n",
		(int) (timer/1000ULL), (int) (timer % 1000ULL));

	return 0;
}
