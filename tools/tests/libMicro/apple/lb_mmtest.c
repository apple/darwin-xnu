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
#pragma ident	"@(#)lb_mmtest.c	1.0	08/21/06 Apple Inc."
#endif



#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <mach/boolean.h>
#include <mach/mach_error.h>
#include <mach/mach.h>
#include <mach/notify.h>
#include <servers/bootstrap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <sys/types.h>

#include "../libmicro.h"

/*
 *	Your state variables should live in the tsd_t struct below
 */
typedef struct {
    int server_mode;
    boolean_t verbose;
    boolean_t oneway;
    int overwrite;
    int msg_type;
    int num_ints;
    int num_msgs;
    const char *server_port_name;
    mach_port_t server_port;
    mach_port_t reply_port;
    int request_msg_size;
    void *request_msg;
    int reply_msg_size;
    void *reply_msg;
    void *ints;
    long pid;
} tsd_t;

static boolean_t 	opt_verbose;
static boolean_t 	opt_oneway;
static int 			opt_num_msgs;
static int	 		opt_msg_type;
static int 			opt_num_ints;
static char *		opt_server_port_name;

#pragma mark *** definitions from MMTest.c
/*
 *	These variables were taken from MMtest.c
 */
typedef struct {
    mach_msg_header_t	header;
    mach_msg_trailer_t	trailer;		// subtract this when sending
} ipc_trivial_message;

typedef struct {
    mach_msg_header_t	header;
    u_int32_t		numbers[0];
    mach_msg_trailer_t	trailer;		// subtract this when sending
} ipc_inline_message;

typedef struct {
    mach_msg_header_t		header;
    mach_msg_body_t		body;
    mach_msg_ool_descriptor_t	descriptor;
    mach_msg_trailer_t		trailer;	// subtract this when sending
} ipc_complex_message;

void signal_handler(int sig) {
}

enum {
    msg_type_trivial = 0,
    msg_type_inline = 1,
    msg_type_complex = 2
};

void server(void *tsd);
void client(void *tsd);

#pragma mark *** routines from MMTest.c
/*
 *	These routines were taken from MMtest.c
 */
 
void server(void *tsd) {
    mach_msg_header_t *request;
    mach_msg_header_t *reply;
    mach_msg_option_t option;
    kern_return_t ret;

	tsd_t			*ts = (tsd_t *)tsd;

    request = (mach_msg_header_t *)ts->request_msg;

    reply = (mach_msg_header_t *)ts->reply_msg;

#ifndef OPTIMIZED_SERVER
    for (;;) {
#endif /* !OPTIMIZED_SERVER */

    	if (ts->verbose) printf("Awaiting message\n");
	option = MACH_RCV_MSG|MACH_RCV_INTERRUPT|MACH_RCV_LARGE;
	ret = mach_msg(request,  
		       option,
		       0,
		       ts->request_msg_size,  
		       ts->server_port,
		       MACH_MSG_TIMEOUT_NONE,
		       MACH_PORT_NULL);

#ifdef OPTIMIZED_SERVER
    for (;;) {
    	mach_msg_header_t *tmp;
#endif /* OPTIMIZED_SERVER */

	if (MACH_MSG_SUCCESS != ret)
		break;
	if (ts->verbose) printf("Received message\n");
	if (request->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		ipc_complex_message *complex_request;

		complex_request = (ipc_complex_message *)ts->request_msg;
		ret = vm_deallocate(mach_task_self(),  
				    (vm_address_t)complex_request->descriptor.address,  
				    complex_request->descriptor.size);
	}
	if (1 == request->msgh_id) {
	    	if (ts->verbose) printf("Sending reply\n");
	    	reply->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
		reply->msgh_size = ts->reply_msg_size;
	    	reply->msgh_remote_port = request->msgh_remote_port;
		reply->msgh_local_port = MACH_PORT_NULL;
	    	reply->msgh_id = 2;

#ifdef OPTIMIZED_SERVER
		option = MACH_SEND_MSG|MACH_RCV_MSG|MACH_RCV_INTERRUPT|MACH_RCV_LARGE;
	} else {
		option = MACH_RCV_MSG|MACH_RCV_INTERRUPT|MACH_RCV_LARGE;
	}

	ret = mach_msg(	reply,
			option,
			ts->reply_msg_size,
			ts->request_msg_size,
			ts->server_port,
			MACH_MSG_TIMEOUT_NONE,  
			MACH_PORT_NULL);
	tmp = reply;
	reply = request;
	request = tmp;
#else /* !OPTIMIZED_SERVER */
		ret = mach_msg(reply,
			       MACH_SEND_MSG,
			       ts->reply_msg_size,
			       0,
			       MACH_PORT_NULL,
			       MACH_MSG_TIMEOUT_NONE,
			       MACH_PORT_NULL);
		if (ret != MACH_MSG_SUCCESS)
			break;
        }
#endif /* !OPTIMIZED_SERVER */
    }

    if (MACH_RCV_INTERRUPTED != ret) {
    	mach_error("mach_msg: ", ret);
		exit(1);
    }
}

void client(void *tsd) {
	mach_msg_header_t *request;
	mach_msg_header_t *reply;
	mach_msg_option_t option;
	kern_return_t ret;
	int idx;

	tsd_t			*ts = (tsd_t *)tsd;

#ifdef SWAP_BUFFERS
	mach_msg_header_t *tmp;
#endif

	request = (mach_msg_header_t *)ts->request_msg;
	reply = (mach_msg_header_t *)ts->reply_msg;
	
    for (idx = 0; idx < ts->num_msgs; idx++) {
	request->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 
					    MACH_MSG_TYPE_MAKE_SEND_ONCE);
	request->msgh_size = ts->request_msg_size;
	request->msgh_remote_port = ts->server_port;
	request->msgh_local_port = ts->reply_port;

	if (ts->msg_type == msg_type_complex) {
	    ipc_complex_message *complexmsg = (ipc_complex_message *)request;

	    request->msgh_bits |=  MACH_MSGH_BITS_COMPLEX;
	    complexmsg->body.msgh_descriptor_count = 1;
	    complexmsg->descriptor.address =  ts->ints;
	    complexmsg->descriptor.size = ts->num_ints * sizeof(u_int32_t);
	    complexmsg->descriptor.deallocate = FALSE;
	    complexmsg->descriptor.copy = MACH_MSG_VIRTUAL_COPY;
	    complexmsg->descriptor.type =  MACH_MSG_OOL_DESCRIPTOR;
	}

	if (ts->oneway) {
	    request->msgh_id = 0;
	    option = MACH_SEND_MSG;
	} else {
	    request->msgh_id = 1;
	    option = MACH_SEND_MSG|MACH_RCV_MSG;
	}

	if (ts->verbose) printf("Sending request\n");
#ifdef SWAP_BUFFERS
	ret = mach_msg(	request,
			option,
			ts->request_msg_size,
			ts->reply_msg_size,
			ts->reply_port,
			MACH_MSG_TIMEOUT_NONE,
			MACH_PORT_NULL);
	if (MACH_MSG_SUCCESS != ret) {
	    mach_error("client: mach_msg: ", ret);
	    fprintf(stderr, "bailing after %u iterations\n", idx);
	    exit(1);
	}
	tmp = request;
	request = reply;
	reply = tmp;
#else
	ret = mach_msg_overwrite(request,
				 option,
				 ts->request_msg_size,
				 ts->reply_msg_size,
				 ts->reply_port,
				 MACH_MSG_TIMEOUT_NONE,
				 MACH_PORT_NULL,
				 reply,
				 0);
	if (MACH_MSG_SUCCESS != ret) {
	    mach_error("client: mach_msg_overwrite: ", ret);
	    fprintf(stderr, "bailing after %u iterations\n", idx);
	    exit(1);
	}
#endif
	if (ts->verbose && !ts->oneway) printf("Received reply\n");
    }
}


#pragma mark *** Darbench routines

/*
 *	These routines are required by darbench
 */
 
/*ARGSUSED*/
int
benchmark_initbatch(void *tsd)
{
	/*
	 * initialize your state variables here second
	 */
	long	pid;
	tsd_t	*ts = (tsd_t *)tsd;
	
    ts->server_mode = -1;
    ts->verbose = opt_verbose;
    ts->oneway = opt_oneway;
    ts->overwrite = 0;
    ts->msg_type = opt_msg_type;
    ts->num_ints = opt_num_ints;
    ts->num_msgs = opt_num_msgs;
    ts->server_port_name = opt_server_port_name;
    ts->server_port = MACH_PORT_NULL;
    ts->reply_port = MACH_PORT_NULL;
    ts->request_msg = NULL;
    ts->request_msg_size = 0;
    ts->reply_msg = NULL;
    ts->reply_msg_size = 0;

	switch (ts->msg_type) {
	case msg_type_trivial:
	  ts->request_msg_size = sizeof(ipc_trivial_message);
		break;

	case msg_type_inline:
	  ts->request_msg_size = sizeof(ipc_inline_message) +  
		sizeof(u_int32_t) * ts->num_ints;
		break;

	case msg_type_complex:
	  ts->request_msg_size = sizeof(ipc_complex_message);
	  ts->ints = malloc(sizeof(u_int32_t) * ts->num_ints);
	  break;
	}

    ts->request_msg = malloc(ts->request_msg_size);
    ts->reply_msg = malloc(ts->reply_msg_size);

    if (ts->server_mode) {
		kern_return_t ret = 0;
		mach_port_t bsport;

		ts->reply_msg_size -= sizeof(mach_msg_trailer_t);
		ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,  
					 &(ts->server_port));
		if (KERN_SUCCESS != ret) {
			mach_error("mach_port_allocate(): ", ret);
			exit(1);
		}
		ret = mach_port_insert_right(mach_task_self(), ts->server_port,  
                ts->server_port, MACH_MSG_TYPE_MAKE_SEND);
		if (KERN_SUCCESS != ret) {
			mach_error("mach_port_insert_right(): ", ret);
			exit(1);
		}
		ret = task_get_bootstrap_port(mach_task_self(), &bsport);
		if (KERN_SUCCESS != ret) {
			mach_error("task_get_bootstrap_port(): ", ret);
			exit(1);
		}
		ret = bootstrap_check_in(bsport, (char *)ts->server_port_name,  
                	&ts->server_port);
		if (KERN_SUCCESS != ret) {
			mach_error("bootstrap_register(): ", ret);
			exit(1);
		}
    } else {   /* client mode */
		kern_return_t ret = 0;
		mach_port_t bsport;

		ts->request_msg_size -= sizeof(mach_msg_trailer_t);

		ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,  
					 &(ts->reply_port));
		if (KERN_SUCCESS != ret) {
			mach_error("mach_port_allocate(): ", ret);
			exit(1);
		}

		ret = task_get_bootstrap_port(mach_task_self(), &bsport);
		if (KERN_SUCCESS != ret) {
			mach_error("task_get_bootstrap_port(): ", ret);
			exit(1);
		}
		ret = bootstrap_look_up(bsport, (char *)ts->server_port_name,  
			&(ts->server_port));
		if (KERN_SUCCESS != ret) {
	   		mach_error("bootstrap_look_up(): ", ret);
			exit(1);
		}
    }
    
    if (ts->verbose) {
		if (ts->server_mode) {
			printf("Server waiting for IPC messages from client on port  '%s'.\n",
			       ts->server_port_name);
		} else {
			printf("Client sending %d %s IPC messages to port '%s' in %s  mode.\n",
			       ts->num_msgs, (ts->msg_type == msg_type_inline) ? "inline" :  
			       ((ts->msg_type == msg_type_complex) ? "complex" : "trivial"),  
			       ts->server_port_name, (ts->oneway ? "oneway" : "rpc"));
		}
    }

	pid = fork();
	switch (pid) {
		case 0:
			server(tsd);
			exit(0);
			break;
		case -1:
			return (-1);
		default:
			ts->pid = pid;
			break;
		}
	return (0);
}

int
benchmark_finirun()
{
	(void) fprintf(stderr, "benchmark_finirun\n");
	return (0);
}

int
benchmark_init()
{
	/* 
	 *	the lm_optstr must be defined here or no options for you
	 * 	...and the framework will throw an error
	 *	lm_optstr has two kinds of arguments, boolean (single
	 *	lower case character) and with an argument (single lower
	 *	case character plus a :, indicating the next option is
	 *	the argument)
	 *
	 */
	(void) sprintf(lm_optstr, "voc:t:n:p:");
	/*
	 * 	tsd_t is the struct that we can pass around our
	 *	state info in
	 *
	 *	lm_tsdsize will allocate the space we need for this
	 *	structure throughout the rest of the framework
	 */
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_usage,
	"    -v\t\tbe verbose\n"
	"    -o\t\tdo not request return reply (client)\n"
	"    -c num\t\tnumber of messages to send (client)\n"
	"    -t trivial|inline|complex\ttype of messages to  send (client)\n"
	"    -n num\tnumber of 32-bit ints to send in  messages\n"
	"\t\t\t(client's value must be <= the server's)\n"
	"    -p portname\tname of port on which to communicate\n"
	"\t\t\t(client and server must use the same value)\n");

	opt_verbose = FALSE;
	opt_oneway = FALSE;
	opt_num_msgs = 10000;
	opt_msg_type = msg_type_trivial;
	opt_num_ints = 64;
	opt_server_port_name = malloc(32);
	strcpy(opt_server_port_name, "TEST");

	return (0);
}

int
benchmark_fini()
{
	free(opt_server_port_name);
	return (0);
}

int
benchmark_finibatch(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	kill(ts->pid, SIGKILL);
	return (0);
}

char *
benchmark_result()
{
	static char		result = '\0';
	(void) fprintf(stderr, "benchmark_result\n");
	return (&result);
}

int
benchmark_finiworker(void *tsd)
{
//	tsd_t			*ts = (tsd_t *)tsd;
	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	(void) fprintf(stderr, "benchmark_optswitch\n");
	
	switch (opt) {
	case 'v':
		opt_verbose = TRUE;
		break;
	case 'o':
		opt_oneway = TRUE;
		break;
	case 'c':
		opt_num_msgs = sizetoint(optarg);
		break;
	case 't':
		if ( 0 == strcmp("trivial", optarg) )
			opt_msg_type = msg_type_trivial;
		else if ( 0 == strcmp("inline", optarg) )
			opt_msg_type = msg_type_inline;
		else if ( 0 == strcmp("complex", optarg) )
			opt_msg_type = msg_type_complex;
		else {
			(void) fprintf(stderr, "incorrect argument for message type %s\n", optarg);
			return (-1);
		}
		break;
	case 'n':
		opt_num_ints = sizetoint(optarg);
		break;
	case 'p':
		strncpy(opt_server_port_name, optarg, 32);
		break;
	default:
		return (-1);
	}
	return (0);
}

int
benchmark_initworker(void *tsd)
{
	/*
	 *	initialize your state variables here first
	 */
//	tsd_t			*ts = (tsd_t *)tsd;
	return (0);
}

int
benchmark_initrun()
{
	(void) fprintf(stderr, "benchmark_initrun\n");
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
//	tsd_t			*ts = (tsd_t *)tsd;
	int			i;
	
	for (i = 0; i < lm_optB; i++) {
		client(tsd);
	}

	return (0);
}
