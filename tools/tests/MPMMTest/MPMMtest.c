#include <AvailabilityMacros.h>
#ifdef AVAILABLE_MAC_OS_X_VERSION_10_5_AND_LATER
#include </System/Library/Frameworks/System.framework/PrivateHeaders/mach/thread_policy.h>
#endif

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <unistd.h>

#include <pthread.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/notify.h>
#include <servers/bootstrap.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/signal.h>

#define MAX(A, B) ((A) < (B) ? (B) : (A))


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
	mach_msg_body_t			body;
	mach_msg_ool_descriptor_t	descriptor;
	mach_msg_trailer_t		trailer;	// subtract this when sending
} ipc_complex_message;

enum {
	msg_type_trivial = 0,
	msg_type_inline = 1,
	msg_type_complex = 2
};

struct port_args {
	int server_num;
	int req_size;
	mach_msg_header_t *req_msg;
	int reply_size;
	mach_msg_header_t *reply_msg;
	mach_port_t port;
	mach_port_t set;
};

typedef union {
	pid_t		pid;
	pthread_t	tid;
} thread_id_t;

/* Global options */
static boolean_t	verbose = FALSE;
static boolean_t	affinity = FALSE;
static boolean_t	timeshare = FALSE;
static boolean_t	threaded = FALSE;
static boolean_t	oneway = FALSE;
static boolean_t	useset = FALSE;
int			msg_type;
int			num_ints;
int			num_msgs;
int			num_clients;
int			num_servers;
int			client_delay;
int			client_spin;
int			client_pages;
int			portcount = 1;
char			**server_port_name;

void signal_handler(int sig) {
}

void usage(const char *progname) {
	fprintf(stderr, "usage: %s [options]\n", progname);
	fprintf(stderr, "where options are:\n");
	fprintf(stderr, "    -affinity\t\tthreads use affinity\n");
	fprintf(stderr, "    -timeshare\t\tthreads use timeshare\n");
	fprintf(stderr, "    -threaded\t\tuse (p)threads\n");
	fprintf(stderr, "    -verbose\t\tbe verbose\n");
	fprintf(stderr, "    -oneway\t\tdo not request return reply\n");
	fprintf(stderr, "    -count num\t\tnumber of messages to send\n");
	fprintf(stderr, "    -type trivial|inline|complex\ttype of messages to send\n");
	fprintf(stderr, "    -numints num\tnumber of 32-bit ints to send in messages\n");
	fprintf(stderr, "    -servers num\tnumber of servers threads to run\n");
	fprintf(stderr, "    -clients num\tnumber of clients per server\n");
	fprintf(stderr, "    -delay num\t\tmicroseconds to sleep clients between messages\n");
	fprintf(stderr, "    -work num\t\tmicroseconds of client work\n");
	fprintf(stderr, "    -pages num\t\tpages of memory touched by client work\n");
	fprintf(stderr, "    -set num\t\tuse a portset stuffed with num ports in server\n");
	fprintf(stderr, "default values are:\n");
	fprintf(stderr, "    . no affinity\n");
	fprintf(stderr, "    . not timeshare\n");
	fprintf(stderr, "    . not verbose\n");
	fprintf(stderr, "    . not oneway\n");
	fprintf(stderr, "    . client sends 100000 messages\n");
	fprintf(stderr, "    . inline message type\n");
	fprintf(stderr, "    . 64 32-bit integers in inline/complex messages\n");
	fprintf(stderr, "    . (num_available_processors+1)%%2 servers\n");
	fprintf(stderr, "    . 4 clients per server\n");
	fprintf(stderr, "    . no delay\n");
	exit(1);
}

void parse_args(int argc, char *argv[]) {
	host_basic_info_data_t		info;
	mach_msg_type_number_t		count;
	kern_return_t			result;

	/* Initialize defaults */
	msg_type = msg_type_trivial;
	num_ints = 64;
	num_msgs = 100000;
	client_delay = 0;
	num_clients = 4;

	count = HOST_BASIC_INFO_COUNT;
	result = host_info(mach_host_self(), HOST_BASIC_INFO, 
			(host_info_t)&info, &count);
	if (result == KERN_SUCCESS && info.avail_cpus > 1)
		num_servers = info.avail_cpus / 2;
	else
		num_servers = 1;

	const char *progname = argv[0];
	argc--; argv++;
	while (0 < argc) {
		if (0 == strcmp("-verbose", argv[0])) {
			verbose = TRUE;
			argc--; argv++;
		} else if (0 == strcmp("-affinity", argv[0])) {
			affinity = TRUE;
			argc--; argv++;
		} else if (0 == strcmp("-timeshare", argv[0])) {
			timeshare = TRUE;
			argc--; argv++;
		} else if (0 == strcmp("-threaded", argv[0])) {
			threaded = TRUE;
			argc--; argv++;
		} else if (0 == strcmp("-oneway", argv[0])) {
			oneway = TRUE;
			argc--; argv++;
		} else if (0 == strcmp("-type", argv[0])) {
			if (argc < 2) 
				usage(progname);
			if (0 == strcmp("trivial", argv[1])) {
				msg_type = msg_type_trivial;
			} else if (0 == strcmp("inline", argv[1])) {
				msg_type = msg_type_inline;
			} else if (0 == strcmp("complex", argv[1])) {
				msg_type = msg_type_complex;
			} else 
				usage(progname);
			argc -= 2; argv += 2;
		} else if (0 == strcmp("-numints", argv[0])) {
			if (argc < 2) 
				usage(progname);
			num_ints = strtoul(argv[1], NULL, 0);
			argc -= 2; argv += 2;
		} else if (0 == strcmp("-count", argv[0])) {
			if (argc < 2) 
				usage(progname);
			num_msgs = strtoul(argv[1], NULL, 0);
			argc -= 2; argv += 2;
		}  else if (0 == strcmp("-clients", argv[0])) {
			if (argc < 2) 
				usage(progname);
			num_clients = strtoul(argv[1], NULL, 0);
			argc -= 2; argv += 2;
		}  else if (0 == strcmp("-servers", argv[0])) {
			if (argc < 2) 
				usage(progname);
			num_servers = strtoul(argv[1], NULL, 0);
			argc -= 2; argv += 2;
		} else if (0 == strcmp("-delay", argv[0])) {
			if (argc < 2) 
				usage(progname);
			client_delay = strtoul(argv[1], NULL, 0);
			argc -= 2; argv += 2;
		} else if (0 == strcmp("-spin", argv[0])) {
			if (argc < 2) 
				usage(progname);
			client_spin = strtoul(argv[1], NULL, 0);
			argc -= 2; argv += 2;
		} else if (0 == strcmp("-pages", argv[0])) {
			if (argc < 2) 
				usage(progname);
			client_pages = strtoul(argv[1], NULL, 0);
			argc -= 2; argv += 2;
		} else if (0 == strcmp("-set", argv[0])) {
			if (argc < 2) 
				usage(progname);
			portcount = strtoul(argv[1], NULL, 0);
			useset = TRUE;
			argc -= 2; argv += 2;
			argc--; argv++;
		} else 
			usage(progname);
	}
}

void setup_server_ports(struct port_args *ports)
{
	kern_return_t ret = 0;
	mach_port_t bsport;
	mach_port_t port;
	int i;

	ports->req_size = MAX(sizeof(ipc_inline_message) +  
			sizeof(u_int32_t) * num_ints, 
			sizeof(ipc_complex_message));
	ports->reply_size = sizeof(ipc_trivial_message) - 
		sizeof(mach_msg_trailer_t);
	ports->req_msg = malloc(ports->req_size);
	ports->reply_msg = malloc(ports->reply_size);

	if (useset) {
		ret = mach_port_allocate(mach_task_self(), 
					 MACH_PORT_RIGHT_PORT_SET,  
					 &(ports->set));
		if (KERN_SUCCESS != ret) {
			mach_error("mach_port_allocate(SET): ", ret);
			exit(1);
		}
	}

	/* stuff the portset with ports */
	for (i=0; i < portcount; i++) {
		ret = mach_port_allocate(mach_task_self(), 
					 MACH_PORT_RIGHT_RECEIVE,  
					 &port);
		if (KERN_SUCCESS != ret) {
			mach_error("mach_port_allocate(PORT): ", ret);
			exit(1);
		}

		if (useset) {
			ret = mach_port_move_member(mach_task_self(), 
						    port, 
						    ports->set);
			if (KERN_SUCCESS != ret) {
				mach_error("mach_port_move_member(): ", ret);
				exit(1);
			}
		}
	}

	/* use the last one as the real port */
	ports->port = port;

	ret = mach_port_insert_right(mach_task_self(), 
			ports->port, 
			ports->port, 
			MACH_MSG_TYPE_MAKE_SEND);
	if (KERN_SUCCESS != ret) {
		mach_error("mach_port_insert_right(): ", ret);
		exit(1);
	}

	ret = task_get_bootstrap_port(mach_task_self(), &bsport);
	if (KERN_SUCCESS != ret) {
		mach_error("task_get_bootstrap_port(): ", ret);
		exit(1);
	}

	if (verbose) {
		printf("server waiting for IPC messages from client on port '%s'.\n",
			server_port_name[ports->server_num]);
	}
	ret = bootstrap_register(bsport,
				 server_port_name[ports->server_num],
				 ports->port);
	if (KERN_SUCCESS != ret) {
		mach_error("bootstrap_register(): ", ret);
		exit(1);
	}
}

void setup_client_ports(struct port_args *ports)
{
	kern_return_t ret = 0;
	switch(msg_type) {
		case msg_type_trivial:
			ports->req_size = sizeof(ipc_trivial_message);
			break;
		case msg_type_inline:
			ports->req_size = sizeof(ipc_inline_message) +  
				sizeof(u_int32_t) * num_ints;
			break;
		case msg_type_complex:
			ports->req_size = sizeof(ipc_complex_message);
			break;
	}
	ports->req_size -= sizeof(mach_msg_trailer_t);
	ports->reply_size = sizeof(ipc_trivial_message);
	ports->req_msg = malloc(ports->req_size);
	ports->reply_msg = malloc(ports->reply_size);

	ret = mach_port_allocate(mach_task_self(), 
			MACH_PORT_RIGHT_RECEIVE,  
			&(ports->port));
	if (KERN_SUCCESS != ret) {
		mach_error("mach_port_allocate(): ", ret);
		exit(1);
	}
	if (verbose) {
		printf("Client sending %d %s IPC messages to port '%s' in %s mode.\n",
				num_msgs, (msg_type == msg_type_inline) ? 
				"inline" :  ((msg_type == msg_type_complex) ? 
					"complex" : "trivial"),  
				server_port_name[ports->server_num],
				(oneway ? "oneway" : "rpc"));
	}

}


static void
thread_setup(int tag) {
#ifdef AVAILABLE_MAC_OS_X_VERSION_10_5_AND_LATER
	kern_return_t			ret;
        thread_extended_policy_data_t   epolicy;
        thread_affinity_policy_data_t   policy;

	if (!timeshare) {
		epolicy.timeshare = FALSE;
		ret = thread_policy_set(
				mach_thread_self(), THREAD_EXTENDED_POLICY,
				(thread_policy_t) &epolicy,
				THREAD_EXTENDED_POLICY_COUNT);
		if (ret != KERN_SUCCESS)
			printf("thread_policy_set(THREAD_EXTENDED_POLICY) returned %d\n", ret);
	}

        if (affinity) {
                policy.affinity_tag = tag;
                ret = thread_policy_set(
                                mach_thread_self(), THREAD_AFFINITY_POLICY,
                                (thread_policy_t) &policy,
                                THREAD_AFFINITY_POLICY_COUNT);
                if (ret != KERN_SUCCESS)
                        printf("thread_policy_set(THREAD_AFFINITY_POLICY) returned %d\n", ret);
        }
#endif
}

void *
server(void *serverarg) 
{
	struct port_args args;
	int idx;
	kern_return_t ret;
	int totalmsg = num_msgs * num_clients;
	mach_port_t recv_port;

	args.server_num = (int) (long) serverarg;
	setup_server_ports(&args);

	thread_setup(args.server_num + 1);

	recv_port = (useset) ? args.set : args.port;

	for (idx = 0; idx < totalmsg; idx++) {
		if (verbose) 
			printf("server awaiting message %d\n", idx);
		ret = mach_msg(args.req_msg,  
				MACH_RCV_MSG|MACH_RCV_INTERRUPT|MACH_RCV_LARGE, 
				0, 
				args.req_size,  
				recv_port, 
				MACH_MSG_TIMEOUT_NONE, 
				MACH_PORT_NULL);
		if (MACH_RCV_INTERRUPTED == ret)
			break;
		if (MACH_MSG_SUCCESS != ret) {
			if (verbose)
				printf("mach_msg() ret=%d", ret);
			mach_error("mach_msg (receive): ", ret);
			exit(1);
		}
		if (verbose)
			printf("server received message %d\n", idx);
		if (args.req_msg->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
			ret = vm_deallocate(mach_task_self(),  
					(vm_address_t)((ipc_complex_message *)args.req_msg)->descriptor.address,  
					((ipc_complex_message *)args.req_msg)->descriptor.size);
		}

		if (1 == args.req_msg->msgh_id) {
			if (verbose) 
				printf("server sending reply %d\n", idx);
			args.reply_msg->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
			args.reply_msg->msgh_size = args.reply_size;
			args.reply_msg->msgh_remote_port = args.req_msg->msgh_remote_port;
			args.reply_msg->msgh_local_port = MACH_PORT_NULL;
			args.reply_msg->msgh_id = 2;
			ret = mach_msg(args.reply_msg, 
					MACH_SEND_MSG, 
					args.reply_size, 
					0, 
					MACH_PORT_NULL, 
					MACH_MSG_TIMEOUT_NONE,  
					MACH_PORT_NULL);
			if (MACH_MSG_SUCCESS != ret) {
				mach_error("mach_msg (send): ", ret);
				exit(1);
			}
		}
	}
	return NULL;
}

static inline void
client_spin_loop(unsigned count, void (fn)(void))
{
	while (count--)
		fn();
}

static long	dummy_memory;
static long	*client_memory = &dummy_memory;
static void
client_work_atom(void)
{
	static int	i;

	if (++i > client_pages * PAGE_SIZE / sizeof(long))
		i = 0;
	client_memory[i] = 0;
}

static	int	calibration_count = 10000;
static	int	calibration_usec;
static void *
calibrate_client_work(void)
{
	long		dummy;
	struct timeval	nowtv;
	struct timeval	warmuptv = { 0, 100 * 1000 }; /* 100ms */
	struct timeval	starttv;
	struct timeval	endtv;

	if (client_spin) {
		/* Warm-up the stepper first... */
		gettimeofday(&nowtv, NULL);
		timeradd(&nowtv, &warmuptv, &endtv);
		do {
			client_spin_loop(calibration_count, client_work_atom);
			gettimeofday(&nowtv, NULL);
		} while (timercmp(&nowtv, &endtv, < ));	
	
		/* Now do the calibration */
		while (TRUE) {
			gettimeofday(&starttv, NULL);
			client_spin_loop(calibration_count, client_work_atom);
			gettimeofday(&endtv, NULL);
			if (endtv.tv_sec - starttv.tv_sec > 1) {
				calibration_count /= 10;
				continue;
			}
			calibration_usec = endtv.tv_usec - starttv.tv_usec;
			if (endtv.tv_usec < starttv.tv_usec) {
				calibration_usec += 1000000;
			}
			if (calibration_usec < 1000) {
				calibration_count *= 10;
				continue;
			}
			calibration_count /= calibration_usec;
			break;
		}
		if (verbose)
			printf("calibration_count=%d calibration_usec=%d\n",
				calibration_count, calibration_usec);
	}
	return NULL;
}

static void *
client_work(void)
{

	if (client_spin) {
		client_spin_loop(calibration_count*client_spin,
				 client_work_atom);
	}
	
	if (client_delay) {
		usleep(client_delay);
	}
	return NULL;
}

void *client(void *threadarg) 
{
	struct port_args args;
	int idx;
	mach_msg_header_t *req, *reply; 
	mach_port_t bsport, servport;
	kern_return_t ret;
	int server_num = (int) threadarg;
	void *ints = malloc(sizeof(u_int32_t) * num_ints);

	if (verbose) 
		printf("client(%d) started, server port name %s\n",
			server_num, server_port_name[server_num]);

	args.server_num = server_num;
	thread_setup(server_num + 1);

	/* find server port */
	ret = task_get_bootstrap_port(mach_task_self(), &bsport);
	if (KERN_SUCCESS != ret) {
		mach_error("task_get_bootstrap_port(): ", ret);
		exit(1);
	}
	ret = bootstrap_look_up(bsport,
				server_port_name[server_num],
				&servport); 
	if (KERN_SUCCESS != ret) {
		mach_error("bootstrap_look_up(): ", ret);
		exit(1);
	}

	setup_client_ports(&args);

	/* Allocate and touch memory */
	if (client_pages) {
		unsigned	i;
		client_memory = (long *) malloc(client_pages * PAGE_SIZE);
		for (i = 0; i < client_pages; i++)
			client_memory[i * PAGE_SIZE / sizeof(long)] = 0;
	}
	
	/* start message loop */
	for (idx = 0; idx < num_msgs; idx++) {
		req = args.req_msg;
		reply = args.reply_msg;

		req->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 
				MACH_MSG_TYPE_MAKE_SEND_ONCE);
		req->msgh_size = args.req_size;
		req->msgh_remote_port = servport;
		req->msgh_local_port = args.port;
		req->msgh_id = oneway ? 0 : 1;
		if (msg_type == msg_type_complex) {
			(req)->msgh_bits |=  MACH_MSGH_BITS_COMPLEX;
			((ipc_complex_message *)req)->body.msgh_descriptor_count = 1;
			((ipc_complex_message *)req)->descriptor.address = ints;
			((ipc_complex_message *)req)->descriptor.size = 
				num_ints * sizeof(u_int32_t);
			((ipc_complex_message *)req)->descriptor.deallocate = FALSE;
			((ipc_complex_message *)req)->descriptor.copy = MACH_MSG_VIRTUAL_COPY;
			((ipc_complex_message *)req)->descriptor.type = MACH_MSG_OOL_DESCRIPTOR;
		}
		if (verbose) 
			printf("client sending message %d\n", idx);
		ret = mach_msg(req,  
				MACH_SEND_MSG, 
				args.req_size, 
				0, 
				MACH_PORT_NULL,  
				MACH_MSG_TIMEOUT_NONE, 
				MACH_PORT_NULL);
		if (MACH_MSG_SUCCESS != ret) {
			mach_error("mach_msg (send): ", ret);
			fprintf(stderr, "bailing after %u iterations\n", idx);
			exit(1);
			break;
		}
		if (!oneway) {
			if (verbose) 
				printf("client awaiting reply %d\n", idx);
			reply->msgh_bits = 0;
			reply->msgh_size = args.reply_size;
			reply->msgh_local_port = args.port;
			ret = mach_msg(args.reply_msg,  
					MACH_RCV_MSG|MACH_RCV_INTERRUPT, 
					0, 
					args.reply_size, 
					args.port,  
					MACH_MSG_TIMEOUT_NONE, 
					MACH_PORT_NULL);
			if (MACH_MSG_SUCCESS != ret) {
				mach_error("mach_msg (receive): ", ret);
				fprintf(stderr, "bailing after %u iterations\n",
						idx);
				exit(1);
			}
			if (verbose) 
				printf("client received reply %d\n", idx);
		}

		client_work();
	}

	free(ints);
	return NULL;
}

static void
thread_spawn(thread_id_t *thread, void *(fn)(void *), void *arg) {
	if (threaded) {
		kern_return_t	ret;
		ret = pthread_create(
				&thread->tid,
				NULL,
				fn,
				arg);
		if (ret != 0)
			err(1, "pthread_create()");
		if (verbose)
			printf("created pthread %p\n", thread->tid);
	} else {
		thread->pid = fork();
		if (thread->pid == 0) {
			if (verbose)
				printf("calling %p(%p)\n", fn, arg);
			fn(arg);
			exit(0);
		}
		if (verbose)
			printf("forked pid %d\n", thread->pid);
	}
}

static void
thread_join(thread_id_t *thread) {
	if (threaded) {
		kern_return_t	ret;
		if (verbose)
			printf("joining thread %p\n", thread->tid);
		ret = pthread_join(thread->tid, NULL);
		if (ret != KERN_SUCCESS)
			err(1, "pthread_join(%p)", thread->tid);
	} else {
		int	stat;
		if (verbose)
			printf("waiting for pid %d\n", thread->pid);
		waitpid(thread->pid, &stat, 0);
	}
}

static void
wait_for_servers(void)
{
	int		i;
	int		retry_count = 10;
	mach_port_t	bsport, servport;
	kern_return_t	ret;

	/* find server port */
	ret = task_get_bootstrap_port(mach_task_self(), &bsport);
	if (KERN_SUCCESS != ret) {
		mach_error("task_get_bootstrap_port(): ", ret);
		exit(1);
	}

	while (retry_count-- > 0) {
		for (i = 0; i < num_servers; i++) {
			ret = bootstrap_look_up(bsport,
					server_port_name[i],
					&servport); 
			if (ret != KERN_SUCCESS) {
				break;
			}
		}
		if (ret == KERN_SUCCESS)
			return;
		usleep(100 * 1000);	/* 100ms */
	}
	fprintf(stderr, "Server(s) failed to register\n");
	exit(1);
}

int main(int argc, char *argv[]) 
{
	int		i;
	int		j;
	thread_id_t	*client_id;
	thread_id_t	*server_id;

	signal(SIGINT, signal_handler);
	parse_args(argc, argv);

	calibrate_client_work();

	/*
	 * If we're using affinity create an empty namespace now
	 * so this is shared by all our offspring.
	 */
	if (affinity)
		thread_setup(0);

	server_id = (thread_id_t *) malloc(num_servers * sizeof(thread_id_t));
	server_port_name = (char **) malloc(num_servers * sizeof(char *));
	if (verbose)
		printf("creating %d servers\n", num_servers);
	for (i = 0; i < num_servers; i++) {
		server_port_name[i] = (char *) malloc(sizeof("PORT.pppppp.xx"));
		/* PORT names include pid of main process for disambiguation */
		sprintf(server_port_name[i], "PORT.%06d.%02d", getpid(), i);
		thread_spawn(&server_id[i], server, (void *) (long) i);
	}

	int totalclients = num_servers * num_clients;
	int totalmsg = num_msgs * totalclients;
	struct timeval starttv, endtv, deltatv;

	/*
	 * Wait for all servers to have registered all ports before starting
	 * the clients and the clock.
	 */
	wait_for_servers();
	
	printf("%d server%s, %d client%s per server (%d total) %u messages...", 
			num_servers, (num_servers > 1)? "s" : "",
			num_clients, (num_clients > 1)? "s" : "",
			totalclients,
			totalmsg);
	fflush(stdout);

	/* Call gettimeofday() once and throw away result; some implementations
	 * (like Mach's) cache some time zone info on first call.
	 */
	gettimeofday(&starttv, NULL);
	gettimeofday(&starttv, NULL);

	client_id = (thread_id_t *) malloc(totalclients * sizeof(thread_id_t));
	if (verbose)
		printf("creating %d clients\n", totalclients);
	for (i = 0; i < num_servers; i++) {
		for (j = 0; j < num_clients; j++) {
			thread_spawn(
				&client_id[(i*num_clients) + j],
				client,
				(void *) (long) i);
		}
	}

	/* Wait for servers to complete */
	for (i = 0; i < num_servers; i++) {
		thread_join(&server_id[i]);
	}

	gettimeofday(&endtv, NULL);

	for (i = 0; i < totalclients; i++) {
		thread_join(&client_id[i]);
	}

	/* report results */
	deltatv.tv_sec = endtv.tv_sec - starttv.tv_sec;
	deltatv.tv_usec = endtv.tv_usec - starttv.tv_usec;
	if (endtv.tv_usec < starttv.tv_usec) {
		deltatv.tv_sec--;
		deltatv.tv_usec += 1000000;
	}

	double dsecs = (double) deltatv.tv_sec + 
		1.0E-6 * (double) deltatv.tv_usec;

	printf(" in %u.%03u seconds\n",  
			deltatv.tv_sec, deltatv.tv_usec/1000);
	printf("  throughput in messages/sec:     %g\n",
			(double)totalmsg / dsecs);
	printf("  average message latency (usec): %2.3g\n", 
			dsecs * 1.0E6 / (double) totalmsg);

	return (0);

}
