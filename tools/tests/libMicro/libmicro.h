/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef LIBMICRO_H
#define	LIBMICRO_H

#include <pthread.h>

#define	LIBMICRO_VERSION	"0.4.0"

#define	STRSIZE			1024

typedef struct {
	long long		re_count;
	long long		re_errors;
	long long		re_t0;
	long long		re_t1;
} result_t;

typedef struct {
	double			sum;
	long long		count;
} histo_t;

#define	HISTOSIZE		32
#define	DATASIZE		100000

/*
 * stats we compute on data sets
 */

typedef struct stats {
	double	st_min;
	double	st_max;
	double	st_mean;
	double	st_median;
	double	st_stddev;
	double	st_stderr;
	double	st_99confidence;
	double	st_skew;
	double	st_kurtosis;
	double	st_timecorr;	/* correlation with respect to time */
} stats_t;

/*
 * Barrier stuff
 */

typedef struct {
	int			ba_hwm;		/* barrier setpoint	*/
	int			ba_flag;	/* benchmark while true	*/
	long long		ba_deadline;	/* when to stop		*/
	int			ba_phase;	/* number of time used	*/
	int 			ba_waiters;	/* how many are waiting	*/

#ifdef USE_SEMOP
	int			ba_semid;
#else
	pthread_mutex_t		ba_lock;
	pthread_cond_t		ba_cv;
#endif

	long long		ba_count;	/* how many ops		 */
	long long		ba_errors;	/* how many errors	 */

	int			ba_quant;	/* how many quant errors */
	int			ba_batches;	/* how many samples	 */

	double			ba_starttime;	/* test time start */
	double			ba_endtime;	/* test time end */

#ifdef NEVER
	double			ba_tmin;	/* min time taken */
	double			ba_tmax;	/* max time taken */
	double			ba_ctmax;	/* max after outliers */
	double			ba_mean;	/* average value */
	double			ba_median;	/* median value */
	double			ba_rawmedian;	/* raw median value */
	double			ba_stddev;	/* standard deviation */
	double			ba_stderr;	/* standard error */
	double			ba_skew; 	/* skew */
	double			ba_kurtosis;	/* kurtosis */
#endif
	stats_t			ba_raw;		/* raw stats */
	stats_t			ba_corrected;	/* corrected stats */

	int			ba_outliers;	/* outlier count */

	long long		ba_t0;		/* first thread/proc */
	long long		ba_t1;		/* time of last thread */
	long long		ba_count0;
	long long		ba_errors0;

	int			ba_datasize;	/* possible #items data	*/
	double			ba_data[1];	/* start of data ararry	*/
} barrier_t;


/*
 * Barrier interfaces
 */

barrier_t *barrier_create(int hwm, int datasize);
int barrier_destroy(barrier_t *bar);
int barrier_queue(barrier_t *bar, result_t *res);


/*
 * Functions that can be provided by the user
 */

int	benchmark(void *tsd, result_t *res);
int	benchmark_init();
int	benchmark_fini();
int	benchmark_initrun();
int	benchmark_finirun();
int	benchmark_initworker();
int	benchmark_finiworker();
int	benchmark_initbatch(void *tsd);
int	benchmark_finibatch(void *tsd);
int	benchmark_optswitch(int opt, char *optarg);
char	*benchmark_result();


/*
 * Globals exported to the user
 */

extern int			lm_argc;
extern char			**lm_argv;

extern int			lm_optB;
extern int			lm_optD;
extern int			lm_optH;
extern char			*lm_optN;
extern int			lm_optP;
extern int			lm_optS;
extern int			lm_optT;

extern int			lm_defB;
extern int			lm_defD;
extern int			lm_defH;
extern char			*lm_defN;
extern int			lm_defP;
extern int			lm_defS;
extern int			lm_defT;
extern int			lm_nsecs_per_op;

extern char			*lm_procpath;
extern char			lm_procname[STRSIZE];
extern char 			lm_usage[STRSIZE];
extern char 			lm_optstr[STRSIZE];
extern char 			lm_header[STRSIZE];
extern size_t			lm_tsdsize;


/*
 * Utility functions
 */

int 		getpindex();
int 		gettindex();
void 		*gettsd(int p, int t);
#if defined(__APPLE__)
int gettsdindex(void *arg);
#endif /* __APPLE__ */
long long 	getusecs();
long long 	getnsecs();
int 		setfdlimit(int limit);
long long 	sizetoll();
int 		sizetoint();
int		fit_line(double *, double *, int, double *, double *);
long long	get_nsecs_resolution();


/* Apple Mods Here */



#ifdef  NO_PORTMAPPER
#define TCP_SELECT      -31233
#define TCP_XACT        -31234
#define TCP_CONTROL     -31235
#define TCP_DATA        -31236
#define TCP_CONNECT     -31237
#define UDP_XACT        -31238
#define UDP_DATA        -31239
#else
#define TCP_SELECT      (u_long)404038  /* XXX - unregistered */
#define TCP_XACT        (u_long)404039  /* XXX - unregistered */
#define TCP_CONTROL     (u_long)404040  /* XXX - unregistered */
#define TCP_DATA        (u_long)404041  /* XXX - unregistered */
#define TCP_CONNECT     (u_long)404042  /* XXX - unregistered */
#define UDP_XACT        (u_long)404032  /* XXX - unregistered */
#define UDP_DATA        (u_long)404033  /* XXX - unregistered */
#define VERS            (u_long)1
#endif
 
/*
* socket send/recv buffer optimizations
*/
#define SOCKOPT_READ    0x0001
#define SOCKOPT_WRITE   0x0002
#define SOCKOPT_RDWR    0x0003
#define SOCKOPT_PID     0x0004
#define SOCKOPT_REUSE   0x0008
#define SOCKOPT_NONE    0

#ifndef SOCKBUF
#define SOCKBUF         (1024*1024)
#endif

#ifndef XFERSIZE
#define XFERSIZE        (64*1024)       /* all bandwidth I/O should use this */
#endif

typedef unsigned long iter_t;

int     tcp_server(int prog, int rdwr);
int     tcp_done(int prog);
int     tcp_accept(int sock, int rdwr);
int     tcp_connect(char *host, int prog, int rdwr);
void    sock_optimize(int sock, int rdwr);
int     sockport(int s);

/* end Apple Mods */
	

#endif /* LIBMICRO_H */
