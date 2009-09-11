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
#pragma ident	"@(#)socket.c	1.3	05/08/04 Apple Inc."
#endif



#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <netdb.h>
#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>

#include "../libmicro.h"

/*
 * lmbench routines, etc. brought over for this benchmark
 */
int  	open_file(void* tsd);
void 	server(void* tsd);
int		tcp_accept(int sock, int rdwr);
void	sock_optimize(int sock, int flags);
int		sockport(int s);
int		tcp_server(int prog, int rdwr);
int		tcp_connect(char *host, int prog, int rdwr);
int		open_socket(void *tsd);


typedef int (*open_f)(void* tsd);
/*
 * end of lmbench support routines
 */

/*
 *	Your state variables should live in the tsd_t struct below
 */
typedef struct {
	char	fname[L_tmpnam];
	open_f	fid_f;
	pid_t	pid;
	int	sock;
	int	fid;
	int	num;
	int	max;
	fd_set  set;
} tsd_t;

static int 	optt = 1;
static int 	optn = -1;
static int 	optp = 1;
static int	optw = 0;

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

int
open_file(void* tsd)
{
	tsd_t* ts = (tsd_t*)tsd;
		return (int) open(ts->fname, O_RDONLY);
}

int
open_socket(void* tsd)
{
	return tcp_connect("localhost", TCP_SELECT, SOCKOPT_NONE);
}

void
server(void* tsd)
{
	int pid;
	tsd_t		*ts = (tsd_t *)tsd;

	pid = getpid();
	ts->pid = 0;

	if (ts->fid_f == open_file) {
		/* Create a temporary file for clients to open */
		sprintf(ts->fname, "lat_selectXXXXXX");
		ts->fid = mkstemp(ts->fname);
		if (ts->fid <= 0) {
			char buf[L_tmpnam+128];
			sprintf(buf, "lat_select: Could not create temp file %s", ts->fname);
			perror(buf);
			exit(1);
		}
		close(ts->fid);
		return;
	}

	/* Create a socket for clients to connect to */
	ts->sock = tcp_server(TCP_SELECT, SOCKOPT_REUSE);
	if (ts->sock <= 0) {
		perror("lat_select: Could not open tcp server socket");
		exit(1);
	}

	/* Start a server process to accept client connections */
	switch(ts->pid = fork()) {
	case 0:
		/* child server process */
		while (pid == getppid()) {
			int newsock = tcp_accept(ts->sock, SOCKOPT_NONE);
			read(newsock, &ts->fid, 1);
			close(newsock);
		}
		exit(0);
	case -1:
		/* error */
		perror("lat_select::server(): fork() failed");
		exit(1);
	default:
		break;
	}
}


/*
 * Accept a connection and return it
 */
int
tcp_accept(int sock, int rdwr)
{
    struct sockaddr_in 	s;
    int 				newsock;
    socklen_t			namelen;

    namelen = sizeof(s);
    bzero((void*)&s, namelen);

retry:
    if ((newsock = accept(sock, (struct sockaddr*)&s, &namelen)) < 0) {
        if (errno == EINTR)
            goto retry;
        perror("accept");
        exit(6);
    }
#ifdef  LIBTCP_VERBOSE
    fprintf(stderr, "Server newsock port %d\n", sockport(newsock));
#endif
    sock_optimize(newsock, rdwr);
    return (newsock);
}

void
sock_optimize(int sock, int flags)
{
    if (flags & SOCKOPT_READ) {
        int sockbuf = SOCKBUF;

        while (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &sockbuf,
            sizeof(int))) {
            sockbuf >>= 1;
        }
#ifdef  LIBTCP_VERBOSE
        fprintf(stderr, "sockopt %d: RCV: %dK\n", sock, sockbuf>>10);
#endif
    }
    if (flags & SOCKOPT_WRITE) {
        int sockbuf = SOCKBUF;

        while (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sockbuf,
            sizeof(int))) {
            sockbuf >>= 1;
        }
#ifdef  LIBTCP_VERBOSE
        fprintf(stderr, "sockopt %d: SND: %dK\n", sock, sockbuf>>10);
#endif
    }
    if (flags & SOCKOPT_REUSE) {
        int val = 1;
        if (setsockopt(sock, SOL_SOCKET,
            SO_REUSEADDR, &val, sizeof(val)) == -1) {
            perror("SO_REUSEADDR");
        }
    }
}

int
sockport(int s)
{
	socklen_t	namelen;
	struct sockaddr_in sin;

	namelen = sizeof(sin);
	if (getsockname(s, (struct sockaddr *)&sin, &namelen) < 0) {
		perror("getsockname");
		return(-1);
	}
	return ((int)ntohs(sin.sin_port));
}

/*
 * Get a TCP socket, bind it, figure out the port,
 * and advertise the port as program "prog".
 *
 * XXX - it would be nice if you could advertise ascii strings.
 */
int
tcp_server(int prog, int rdwr)
{
	int	sock;
	struct	sockaddr_in s;

#ifdef	LIBTCP_VERBOSE
	fprintf(stderr, "tcp_server(%u, %u)\n", prog, rdwr);
#endif
	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		exit(1);
	}
	sock_optimize(sock, rdwr);
	bzero((void*)&s, sizeof(s));
	s.sin_family = AF_INET;
	if (prog < 0) {
		s.sin_port = htons(-prog);
	}
	if (bind(sock, (struct sockaddr*)&s, sizeof(s)) < 0) {
		perror("bind");
		exit(2);
	}
	if (listen(sock, 100) < 0) {
		perror("listen");
		exit(4);
	}
	if (prog > 0) {
#ifdef	LIBTCP_VERBOSE
		fprintf(stderr, "Server port %d\n", sockport(sock));
#endif
		(void)pmap_unset((u_long)prog, (u_long)1);
		if (!pmap_set((u_long)prog, (u_long)1, (u_long)IPPROTO_TCP,
		    (unsigned short)sockport(sock))) {
			perror("pmap_set");
			exit(5);
		}
	}
	return (sock);
}


/*
 * Connect to the TCP socket advertised as "prog" on "host" and
 * return the connected socket.
 *
 * Hacked Thu Oct 27 1994 to cache pmap_getport calls.  This saves
 * about 4000 usecs in loopback lat_connect calls.  I suppose we
 * should time gethostbyname() & pmap_getprot(), huh?
 */
int
tcp_connect(char *host, int prog, int rdwr)
{
	static	struct hostent *h;
	static	struct sockaddr_in s;
	static	u_short	save_port;
	static	u_long save_prog;
	static	char *save_host;
	int	sock;
	static	int tries = 0;

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		exit(1);
	}
	if (rdwr & SOCKOPT_PID) {
		static	unsigned short port;
		struct sockaddr_in sin;

		if (!port) {
			port = (unsigned short)(getpid() << 4);
			if (port < 1024) {
				port += 1024;
			}
		}
		do {
			port++;
			bzero((void*)&sin, sizeof(sin));
			sin.sin_family = AF_INET;
			sin.sin_port = htons(port);
		} while (bind(sock, (struct sockaddr*)&sin, sizeof(sin)) == -1);
	}
#ifdef	LIBTCP_VERBOSE
	else {
		struct sockaddr_in sin;

		bzero((void*)&sin, sizeof(sin));
		sin.sin_family = AF_INET;
		if (bind(sock, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
			perror("bind");
			exit(2);
		}
	}
	fprintf(stderr, "Client port %d\n", sockport(sock));
#endif
	sock_optimize(sock, rdwr);
	if (!h || host != save_host || prog != save_prog) {
		save_host = host;	/* XXX - counting on them not
					 * changing it - benchmark only.
					 */
		save_prog = prog;
		if (!(h = gethostbyname(host))) {
			perror(host);
			exit(2);
		}
		bzero((void *) &s, sizeof(s));
		s.sin_family = AF_INET;
		bcopy((void*)h->h_addr, (void *)&s.sin_addr, h->h_length);
		if (prog > 0) {
			save_port = pmap_getport(&s, prog,
			    (u_long)1, IPPROTO_TCP);
			if (!save_port) {
				perror("lib TCP: No port found");
				exit(3);
			}
#ifdef	LIBTCP_VERBOSE
			fprintf(stderr, "Server port %d\n", save_port);
#endif
			s.sin_port = htons(save_port);
		} else {
			s.sin_port = htons(-prog);
		}
	}
	if (connect(sock, (struct sockaddr*)&s, sizeof(s)) < 0) {
		if (errno == ECONNRESET 
		    || errno == ECONNREFUSED
		    || errno == EAGAIN) {
			close(sock);
			if (++tries > 10) return(-1);
			return (tcp_connect(host, prog, rdwr));
		}
		perror("connect");
		exit(4);
	}
	tries = 0;
	return (sock);
}


/*
 * end of lmbench support routines
 */

/*ARGSUSED*/
int
benchmark_initbatch(void *tsd)
{
	/*
	 * initialize your state variables here second
	 */
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
	(void) sprintf(lm_optstr, "p:w:n:t:");
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
		"       [-p parallelism (default 1)]\n"			
		"       [-w warmup (default 0)]\n"
		"       [-n number of descriptors (default 1)]\n"
	    "       [-t int (default 1)]\n"
	    "notes: measures lmbench_select_file\n");
	lm_defB = 1;
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
	tsd_t			*ts = (tsd_t *)tsd;
	int i;
	// pulls in the lmbench cleanup code
		for (i = 0; i <= ts->max; ++i) {
		if (FD_ISSET(i, &(ts->set)))
			close(i);
	}
	FD_ZERO(&(ts->set));
	unlink(ts->fname);
	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
		
	switch (opt) {
	case 't':
		optt = sizetoint(optarg);
		break;
	case 'n':
		optn = sizetoint(optarg);
		break;
	case 'p':
		optp = sizetoint(optarg);
		break;
	case 'w':
		optw = sizetoint(optarg);
		break;
	default:
		return (-1);
	}
	return (0);
}

int
benchmark_initworker(void *tsd)
{	
	// pulls in code from lmbench main and initialize
	int		n = 0;
	/*
	 *	initialize your state variables here first
	 */
	tsd_t			*ts = (tsd_t *)tsd;
	int	N, fid, fd;
	
	/*
	 * default number of file descriptors
	 */
		ts->num = 200;
	if (optn > 0) {
		ts->num = optn;
	}
	N = ts->num;
		
	/*
	 *	grab more file descriptors
	 */
	 
	morefds();
	
	ts->fid_f = open_socket;
	server(ts);
		/* 
	 * Initialize function from lmbench
	 * for this test
	 */
	fid = (*ts->fid_f)(ts);
		if (fid <= 0) {
		perror("Could not open device");
		exit(1);
	}
	ts->max = 0;
	FD_ZERO(&(ts->set));
			for (n = 0; n < N; n++) {
				fd = dup(fid);
				//(void) fprintf(stderr, "benchmark_initworker: errno result is %d - \"%s\"\n",errno, strerror(errno));

		if (fd == -1) break;
		if (fd > ts->max)
			ts->max = fd;
		FD_SET(fd, &(ts->set));
		//(void) fprintf(stderr, "initworker FD_SET: ts->set result is %i\n",ts->set);

	}
	//(void) fprintf(stderr, "benchmark_initworker: after second macro/loop\n");

	ts->max++;
	close(fid);
		if (n != N)
		exit(1);
	/* end of initialize function */
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
	tsd_t			*ts = (tsd_t *)tsd;
	fd_set		nosave;
	static struct timeval tv;

	//(void) fprintf(stderr, "benchmark\n");

	int			i;
	//int 		sel_res;
	tv.tv_sec = 0;
	tv.tv_usec = 0;

	
	for (i = 0; i < lm_optB; i++) {
		 nosave = ts->set;
		 //(void) fprintf(stderr, "benchmark: nosave is %i\n", nosave);

		 select(ts->num, 0, &nosave, 0, &tv);
		 
	}
	res->re_count = i;
	return (0);
}

