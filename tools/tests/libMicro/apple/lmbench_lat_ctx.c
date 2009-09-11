/*
 * Copyright (c) 2006 Apple Inc.  All Rights Reserved.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */


/*
 *	Order of Execution
 *
 *	benchmark_init
 *
 *	benchmark_optswitch
 *
 *		benchmark_initrun
 *
 *			benchmark_initworker
 *				benchmark_initbatch
 *					benchmark
 *				benchmark_finibatch
 *				benchmark_initbatch
 *					benchmark
 *				benchmark_finibatch, etc.
 *			benchmark_finiworker
 *
 *		benchmark_result
 *
 *		benchmark_finirun
 *
 *	benchmark_fini
 */



#ifdef	__sun
#pragma ident	"@(#)trivial.c	1.0	08/17/06 Apple Inc."
#endif



#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <signal.h>
#include <strings.h>

#include <sys/sysctl.h>
#include "../libmicro.h"

#if 1
# define debug(fmt, args...)	(void) fprintf(stderr, fmt "\n" , ##args)
#else
# define debug(fmt, args...)
#endif


#define	MAXPROC	2048
#define	CHUNK	(4<<10)
#define	TRIPS	5
#ifndef	max
#define	max(a, b)	((a) > (b) ? (a) : (b))
#endif


/*
 *	Your state variables should live in the tsd_t struct below
 */
typedef struct {
	int	process_size;
	double	overhead;
	int	procs;
	pid_t*	pids;
	int	**p;
	void*	data;
} tsd_t;

static int 	opts = 1;

void	doit(int rd, int wr, int process_size);
int		create_pipes(int **p, int procs);
int		create_daemons(int **p, pid_t *pids, int procs, int process_size);
void	initialize_overhead(void* tsd);
void	cleanup_overhead(void* tsd);
void	benchmark_overhead(void* tsd);
void	initialize(void* tsd);
void	cleanup(void* tsd);
long	bread(void* buf, long nbytes);


#pragma mark *** lmbench routines

/*
 * lmbench routines, etc. brought over for this benchmark
 */
 
void
morefds(void)
{
#ifdef  RLIMIT_NOFILE
        struct  rlimit r;

        getrlimit(RLIMIT_NOFILE, &r);
        r.rlim_cur = r.rlim_max;
        setrlimit(RLIMIT_NOFILE, &r);
#endif
}

void
doit(int rd, int wr, int process_size)
{
	int	msg;
	void*	data = NULL;

	if (process_size) {
		data = malloc(process_size);
		if (data) bzero(data, process_size);
	}
	for ( ;; ) {
		if (read(rd, &msg, sizeof(msg)) != sizeof(msg)) {
			debug("read/write on pipe"); 
			break;
		}
		bread(data, process_size);
		if (write(wr, &msg, sizeof(msg)) != sizeof(msg)) {
			debug("read/write on pipe");
			break;
		}
	}
	exit(0);
}

/*
 * Return the number of processors in this host
 */
int
sched_ncpus()
{
#ifdef MP_NPROCS
	/* SGI IRIX interface */
	return sysmp(MP_NPROCS);
#elif defined(HAVE_MPCTL)
	/* HP-UX interface */
	return mpctl(MPC_GETNUMSPUS_SYS, 0, 0);
#elif defined(_SC_NPROCESSORS_ONLN)
	/* AIX, Solaris, and Linux interface */
	return sysconf(_SC_NPROCESSORS_ONLN);
#elif __APPLE__
	char *name="hw.activecpu";
	int cpus, retval;	
	size_t len = 4;
	retval=sysctlbyname(name, &cpus, &len, NULL, 0);
	/* Check retval here */	
	debug("cpus = %d retval = %d", cpus, retval);
	return cpus;
#endif
	return 1;
}

/*
 * Use to get sequentially created processes "far" away from
 * each other in an SMP.
 *
 * XXX: probably doesn't work for NCPUS not a power of two.
 */
int
reverse_bits(int cpu)
{
	int	i;
	int	nbits;
	int	max = sched_ncpus() - 1;
	int	cpu_reverse = 0;

	for (i = max>>1, nbits = 1; i > 0; i >>= 1, nbits++)
	  ;
	/* now reverse the bits */
	for (i = 0; i < nbits; i++) {
		if (cpu & (1<<i))
			cpu_reverse |= (1<<(nbits-i-1));
	}
	return cpu_reverse;
}


/*
 * The interface used by benchmp.
 *
 * childno is the "logical" child id number.  
 *	In range [0, ..., parallel-1].
 * benchproc is the "logical" id within the benchmark process.  The
 *	benchmp-created process is logical ID zero, child processes
 *	created by the benchmark range from [1, ..., nbenchprocs].
 * nbenchprocs is the number of child processes that each benchmark
 * 	process will create.  Most benchmarks will leave this zero,
 *	but some such as the pipe() benchmarks will not.
 */
int
handle_scheduler(int childno, int benchproc, int nbenchprocs)
{
	int	cpu = 0;
	char*	sched = getenv("LMBENCH_SCHED");
	
	if (!sched || strcasecmp(sched, "DEFAULT") == 0) {
		/* do nothing.  Allow scheduler to control placement */
		return 0;
	} else if (strcasecmp(sched, "SINGLE") == 0) {
		/* assign all processes to CPU 0 */
		cpu = 0;
	} else if (strcasecmp(sched, "BALANCED") == 0) {
		/* assign each benchmark process to its own processor,
		 * but child processes will share the CPU with the
		 * parent.
		 */
		cpu = childno;
	} else if (strcasecmp(sched, "BALANCED_SPREAD") == 0) {
		/* 
		 * assign each benchmark process to its own processor, 
		 * logically as far away from neighboring IDs as 
		 * possible.  This can help identify bus contention
		 * issues in SMPs with hierarchical busses or NUMA
		 * memory.
		 */
		cpu = reverse_bits(childno);
	} else if (strcasecmp(sched, "UNIQUE") == 0) {
		/*
		 * assign each benchmark process and each child process
		 * to its own processor.
		 */
		cpu = childno * (nbenchprocs + 1) + benchproc;
	} else if (strcasecmp(sched, "UNIQUE_SPREAD") == 0) {
		/* 
		 * assign each benchmark process and each child process
		 * to its own processor, logically as far away from 
		 * neighboring IDs as possible.  This can help identify 
		 * bus contention issues in SMPs with hierarchical busses
		 * or NUMA memory.
		 */
		cpu = reverse_bits(childno * (nbenchprocs + 1) + benchproc);
	} 
#if 0 // BLOB
	  else if (strncasecmp(sched, "CUSTOM ", strlen("CUSTOM ")) == 0) {
		cpu = custom(sched + strlen("CUSTOM"), childno);
	} else if (strncasecmp(sched, "CUSTOM_UNIQUE ", strlen("CUSTOM_UNIQUE ")) == 0) {
		cpu = custom(sched + strlen("CUSTOM_UNIQUE"), 
			     childno * (nbenchprocs + 1) + benchproc);
	} 
#endif // BLOB
		else {
		/* default action: do nothing */
		return 0;
	}
	debug("cpu = %d, sched_ncpus() = %d", cpu, sched_ncpus());
	return 0;
//	return sched_pin(cpu % sched_ncpus());
}

int
create_daemons(int **p, pid_t *pids, int procs, int process_size)
{
	int	i, j;
	int	msg;

	/*
	 * Use the pipes as a ring, and fork off a bunch of processes
	 * to pass the byte through their part of the ring.
	 *
	 * Do the sum in each process and get that time before moving on.
	 */
	handle_scheduler(getpid(), 0, procs-1);
     	for (i = 1; i < procs; ++i) {
		switch (pids[i] = fork()) {
		    case -1:	/* could not fork, out of processes? */
			return i;

		    case 0:	/* child */
			handle_scheduler(getpid(), i, procs-1);
			for (j = 0; j < procs; ++j) {
				if (j != i - 1) close(p[j][0]);
				if (j != i) close(p[j][1]);
			}
			doit(p[i-1][0], p[i][1], process_size);
			/* NOTREACHED */

		    default:	/* parent */
			;
	    	}
	}

	/*
	 * Go once around the loop to make sure that everyone is ready and
	 * to get the token in the pipeline.
	 */
	if (write(p[0][1], &msg, sizeof(msg)) != sizeof(msg) ||
	    read(p[procs-1][0], &msg, sizeof(msg)) != sizeof(msg)) {
		debug("write/read/write on pipe"); 
		exit(1);
	}
	return procs;
}

int
create_pipes(int **p, int procs)
{
	int	i;
	/*
	 * Get a bunch of pipes.
	 */
	morefds();
     	for (i = 0; i < procs; ++i) {
		if (pipe(p[i]) == -1) {
			return i;
		}
	}
	return procs;
}

void
initialize_overhead(void* cookie)
{
    int i;
    int procs;
    int* p;
    tsd_t	*pState = (tsd_t *)cookie;

    pState->pids = NULL;
    pState->p = (int**)malloc(pState->procs * (sizeof(int*) + 2 * sizeof(int)));
    p = (int*)&pState->p[pState->procs];
    for (i = 0; i < pState->procs; ++i) {
        pState->p[i] = p;
        p += 2;
    }

    pState->data = (pState->process_size > 0) ? malloc(pState->process_size) : NULL;
    if (pState->data)
        bzero(pState->data, pState->process_size);

    procs = create_pipes(pState->p, pState->procs);
    if (procs < pState->procs) {
    	debug("procs < pState->procs");
        cleanup_overhead(cookie);
        exit(1);
    }
}

void
cleanup_overhead(void* tsd)
{
	int 	i;
	tsd_t	*ts = (tsd_t *)tsd;

     	for (i = 0; i < ts->procs; ++i) {
		close(ts->p[i][0]);
		close(ts->p[i][1]);
	}

	free(ts->p);
	if (ts->data) free(ts->data);
}

void
cleanup(void* cookie)
{
    int 	i;
    tsd_t	*pState = (tsd_t *)cookie;


    /*
     * Close the pipes and kill the children.
     */
    cleanup_overhead(cookie);
        for (i = 1; pState->pids && i < pState->procs; ++i) {
        if (pState->pids[i] > 0) {
            kill(pState->pids[i], SIGKILL);
            waitpid(pState->pids[i], NULL, 0);
        }
    }
    if (pState->pids)
        free(pState->pids);
    pState->pids = NULL;
}

void
benchmark_overhead(void* tsd)
{
	tsd_t	*ts = (tsd_t *)tsd;
	int	i = 0;
	int	msg = 1;

	for (i = 0; i < lm_optB; i++) {
		if (write(ts->p[i][1], &msg, sizeof(msg)) != sizeof(msg)) {
			debug("read/write on pipe");
			exit(1);				
		}
		if (read(ts->p[i][0], &msg, sizeof(msg)) != sizeof(msg)) {
			debug("read/write on pipe");
			exit(1);
		}
		if (++i == ts->procs) {
			i = 0;
		}
		bread(ts->data, ts->process_size);
	}
}

/* analogous to bzero, bcopy, etc., except that it just reads
 * data into the processor
 */
long
bread(void* buf, long nbytes)
{
	long sum = 0;
	register long *p, *next;
	register char *end;

	p = (long*)buf;
	end = (char*)buf + nbytes;
	for (next = p + 128; (void*)next <= (void*)end; p = next, next += 128) {
		sum +=
			p[0]+p[1]+p[2]+p[3]+p[4]+p[5]+p[6]+p[7]+
			p[8]+p[9]+p[10]+p[11]+p[12]+p[13]+p[14]+
			p[15]+p[16]+p[17]+p[18]+p[19]+p[20]+p[21]+
			p[22]+p[23]+p[24]+p[25]+p[26]+p[27]+p[28]+
			p[29]+p[30]+p[31]+p[32]+p[33]+p[34]+p[35]+
			p[36]+p[37]+p[38]+p[39]+p[40]+p[41]+p[42]+
			p[43]+p[44]+p[45]+p[46]+p[47]+p[48]+p[49]+
			p[50]+p[51]+p[52]+p[53]+p[54]+p[55]+p[56]+
			p[57]+p[58]+p[59]+p[60]+p[61]+p[62]+p[63]+
			p[64]+p[65]+p[66]+p[67]+p[68]+p[69]+p[70]+
			p[71]+p[72]+p[73]+p[74]+p[75]+p[76]+p[77]+
			p[78]+p[79]+p[80]+p[81]+p[82]+p[83]+p[84]+
			p[85]+p[86]+p[87]+p[88]+p[89]+p[90]+p[91]+
			p[92]+p[93]+p[94]+p[95]+p[96]+p[97]+p[98]+
			p[99]+p[100]+p[101]+p[102]+p[103]+p[104]+
			p[105]+p[106]+p[107]+p[108]+p[109]+p[110]+
			p[111]+p[112]+p[113]+p[114]+p[115]+p[116]+
			p[117]+p[118]+p[119]+p[120]+p[121]+p[122]+
			p[123]+p[124]+p[125]+p[126]+p[127];
	}
	for (next = p + 16; (void*)next <= (void*)end; p = next, next += 16) {
		sum +=
			p[0]+p[1]+p[2]+p[3]+p[4]+p[5]+p[6]+p[7]+
			p[8]+p[9]+p[10]+p[11]+p[12]+p[13]+p[14]+
			p[15];
	}
	for (next = p + 1; (void*)next <= (void*)end; p = next, next++) {
		sum += *p;
	}
	return sum;
}

#pragma mark *** darbench routines


/*ARGSUSED*/
int
benchmark_initbatch(void *tsd)
{
	/*
	 * initialize your state variables here second
	 */
	tsd_t			*ts = (tsd_t *)tsd;
	int procs;

	initialize_overhead(tsd);

	ts->pids = (pid_t*)malloc(ts->procs * sizeof(pid_t));
	if (ts->pids == NULL)
		exit(1);
	bzero((void*)ts->pids, ts->procs * sizeof(pid_t));
	procs = create_daemons(ts->p, ts->pids, 
			       ts->procs, ts->process_size);
	if (procs < ts->procs) {
		cleanup(tsd);
		exit(1);
	}
	return (0);
}

int
benchmark_finirun()
{
	return (0);
}

int
benchmark_init()
{
	/* 
	 *	the lm_optstr must be defined here or no options for you
	 *
	 * 	...and the framework will throw an error
	 *
	 */
	(void) sprintf(lm_optstr, "s:");
	/*
	 *	working hypothesis:
	 *	
	 * 	tsd_t is the struct that we can pass around our
	 *	state info in
	 *
	 *	lm_tsdsize will allocate the space we need for this
	 *	structure throughout the rest of the framework
	 */
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_usage,
		"		[-s kbytes]\n"
		"		processes [processes ...]\n");

	return (0);
}

int
benchmark_fini()
{
	return (0);
}

int
benchmark_finibatch(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int i;
	
	/*
	 * Close the pipes and kill the children.
	 */
	cleanup_overhead(tsd);
     	for (i = 1; ts->pids && i < ts->procs; ++i) {
		if (ts->pids[i] > 0) {
			kill(ts->pids[i], SIGKILL);
			waitpid(ts->pids[i], NULL, 0);
		}
	}
	if (ts->pids)
		free(ts->pids);
	ts->pids = NULL;
	return (0);
}

char *
benchmark_result()
{
	static char		result = '\0';
	return (&result);
}

int
benchmark_finiworker(void *tsd)
{
	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	
	switch (opt) {
	case 's':
		opts = sizetoint(optarg);
		break;
	default:
		return (-1);
	}
	return (0);
}

int
benchmark_initworker(void *tsd)
{
	tsd_t		*ts = (tsd_t *)tsd;
	
	ts->process_size = opts;
	 
	return (0);
}

int
benchmark_initrun()
{
	return (0);
}

int
benchmark(void *tsd, result_t *res)
{
	/* 
	 *	initialize your state variables here last
	 * 
	 * 	and realize that you are paying for your initialization here
	 *	and it is really a bad idea
	 */
	tsd_t		*ts = (tsd_t *)tsd;
	int			i;
	int			msg=1;
	
	for (i = 0; i < lm_optB; i++) {
		if (write(ts->p[0][1], &msg, sizeof(msg)) !=
		    sizeof(msg)) {
			debug("read/write on pipe");
			exit(1);
		}
		if (read(ts->p[ts->procs-1][0], &msg, sizeof(msg)) != sizeof(msg)) {
			debug("read/write on pipe");
			exit(1);
		}
		bread(ts->data, ts->process_size);
	}
	res->re_count = i;

	return (0);
}
