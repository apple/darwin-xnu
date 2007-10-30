#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/notify.h>
#include <servers/bootstrap.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/signal.h>

#define MAX(A, B) ((A) < (B) ? (B) : (A))

static __inline__ unsigned long long ReadTSR() {
	union {
		unsigned long long time64;
		unsigned long word[2];
	} now;
#if defined(__i386__)
	/* Read from Pentium and Pentium Pro 64-bit timestamp counter.
	 * The counter is set to 0 at processor reset and increments on
	 * every clock cycle. */
	__asm__ volatile("rdtsc" : : : "eax", "edx");
	__asm__ volatile("movl %%eax,%0" : "=m" (now.word[0]) : : "eax");
	__asm__ volatile("movl %%edx,%0" : "=m" (now.word[1]) : : "edx");
#elif defined(__ppc__)
	/* Read from PowerPC 64-bit time base register. The increment
	 * rate of the time base is implementation-dependent, but is
	 * 1/4th the bus clock cycle on 603/604 processors. */
	unsigned long t3;
	do {
		__asm__ volatile("mftbu %0" : "=r" (now.word[0]));
		__asm__ volatile("mftb %0" : "=r" (now.word[1]));
		__asm__ volatile("mftbu %0" : "=r" (t3));
	} while (now.word[0] != t3);
#else
#warning Do not know how to read a time stamp register on this architecture
	now.time64 = 0ULL;
#endif
	return now.time64;
}

typedef struct  {
	unsigned int        msgt_name : 8,
			    msgt_size : 8,
			    msgt_number : 12,
			    msgt_inline : 1,
			    msgt_longform : 1,
			    msgt_deallocate : 1,
			    msgt_unused : 1;
} mach_msg_type_t;

typedef struct  {
	mach_msg_type_t     msgtl_header;
	unsigned short      msgtl_name;
	unsigned short      msgtl_size;
	natural_t           msgtl_number;
} mach_msg_type_long_t;
#define MACH_MSG_TYPE_INTEGER_32 0


typedef struct {
	mach_msg_header_t	header;
	mach_msg_trailer_t	trailer;		// subtract this when sending
} ipc_trivial_message;

typedef struct {
	mach_msg_header_t	header;
	mach_msg_type_t		type;
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
	int req_size;
	mach_msg_header_t *req_msg;
	int reply_size;
	mach_msg_header_t *reply_msg;
	mach_port_t port;
};

/* Global options */
static int verbose;
int oneway;
int msg_type;
int num_ints;
int num_msgs;
int num_clients;
int client_delay;
char *server_port_name;

void signal_handler(int sig) {
}

void usage(const char *progname) {
	fprintf(stderr, "usage: %s [options]\n", progname);
	fprintf(stderr, "where options are:\n");
	fprintf(stderr, "    -verbose\t\tbe verbose\n");
	fprintf(stderr, "    -oneway\t\tdo not request return reply\n");
	fprintf(stderr, "    -count num\t\tnumber of messages to send\n");
	fprintf(stderr, "    -type trivial|inline|complex\ttype of messages to send\n");
	fprintf(stderr, "    -numints num\tnumber of 32-bit ints to send in messages\n");
	fprintf(stderr, "    -clients num\tnumber of client threads to run\n");
	fprintf(stderr, "    -delay num\t\tmicroseconds to sleep clients between messages\n");
	fprintf(stderr, "    -name portname\tname of port on which to communicate\n");
	fprintf(stderr, "default values are:\n");
	fprintf(stderr, "    . not verbose\n");
	fprintf(stderr, "    . not oneway\n");
	fprintf(stderr, "    . client sends 10000 messages\n");
	fprintf(stderr, "    . inline message type\n");
	fprintf(stderr, "    . 64 32-bit integers in inline/complex messages\n");
	fprintf(stderr, "    . avail_cpus - 1 clients\n");
	fprintf(stderr, "    . no delay\n");
	fprintf(stderr, "    . port name 'TEST'\n");
	exit(1);
}

void parse_args(int argc, char *argv[]) {
	host_basic_info_data_t		info;
	mach_msg_type_number_t		count;
	kern_return_t			result;

	/* Initialize defaults */
	verbose = 0;
	oneway = 0;
	msg_type = msg_type_trivial;
	num_ints = 64;
	num_msgs = 10000;
	client_delay = 0;
	server_port_name = "TEST";

	count = HOST_BASIC_INFO_COUNT;
	result = host_info(mach_host_self(), HOST_BASIC_INFO, 
			(host_info_t)&info, &count);
	if (result == KERN_SUCCESS)
		num_clients = MAX(1, info.avail_cpus - 1);
	else
		num_clients = 1;

	const char *progname = argv[0];
	argc--; argv++;
	while (0 < argc) {
		if (0 == strcmp("-verbose", argv[0])) {
			verbose = 1;
			argc--; argv++;
		} else if (0 == strcmp("-oneway", argv[0])) {
			oneway = 1;
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
		} else if (0 == strcmp("-name", argv[0])) {
			if (argc < 2) 
				usage(progname);
			server_port_name = argv[1];
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
		} else if (0 == strcmp("-delay", argv[0])) {
			if (argc < 2) 
				usage(progname);
			client_delay = strtoul(argv[1], NULL, 0);
			argc -= 2; argv += 2;
		} else 
			usage(progname);
	}
}

void setup_server_ports(struct port_args *ports)
{
	kern_return_t ret = 0;
	mach_port_t bsport;

	ports->req_size = MAX(sizeof(ipc_inline_message) +  
			sizeof(u_int32_t) * num_ints, 
			sizeof(ipc_complex_message));
	ports->reply_size = sizeof(ipc_trivial_message) - 
		sizeof(mach_msg_trailer_t);
	ports->req_msg = malloc(ports->req_size);
	ports->reply_msg = malloc(ports->reply_size);

	ret = mach_port_allocate(mach_task_self(), 
			MACH_PORT_RIGHT_RECEIVE,  
			&(ports->port));
	if (KERN_SUCCESS != ret) {
		mach_error("mach_port_allocate(): ", ret);
		exit(1);
	}

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

	ret = bootstrap_register(bsport, server_port_name, ports->port);
	if (KERN_SUCCESS != ret) {
		mach_error("bootstrap_register(): ", ret);
		exit(1);
	}
	if (verbose) {
		printf("server waiting for IPC messages from client on port '%s'.\n",
				server_port_name);
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
				server_port_name, (oneway ? "oneway" : "rpc"));
	}

}

void server(struct port_args *args) 
{
	int idx;
	kern_return_t ret;
	int totalmsg = num_msgs * num_clients;

	unsigned long long starttsc, endtsc, deltatsc;
	struct timeval starttv, endtv, deltatv;

	/* Call gettimeofday() once and throw away result; some implementations
	 * (like Mach's) cache some time zone info on first call.  Then, call
	 * ReadTSR in case that helps warm things up, again discarding the 
	 * results.
	 */
	gettimeofday(&starttv, NULL);
	ReadTSR();

	gettimeofday(&starttv, NULL);
	starttsc = ReadTSR();

	for (idx = 0; idx < totalmsg; idx++) {
		if (verbose) 
			printf("server awaiting message %d\n", idx);
		args->req_msg->msgh_bits = 0;
		args->req_msg->msgh_size = args->req_size;
		args->req_msg->msgh_local_port = args->port;
		ret = mach_msg(args->req_msg,  
				MACH_RCV_MSG|MACH_RCV_INTERRUPT|MACH_RCV_LARGE, 
				0, 
				args->req_size,  
				args->port, 
				MACH_MSG_TIMEOUT_NONE, 
				MACH_PORT_NULL);
		if (MACH_MSG_SUCCESS != ret) {
			mach_error("mach_msg (receive): ", ret);
			exit(1);
		}
		if (verbose)
			printf("server received message %d\n", idx);
		if (args->req_msg->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
			ret = vm_deallocate(mach_task_self(),  
					(vm_address_t)((ipc_complex_message *)args->req_msg)->descriptor.address,  
					((ipc_complex_message *)args->req_msg)->descriptor.size);
		}

		if (1 == args->req_msg->msgh_id) {
			if (verbose) 
				printf("server sending reply %d\n", idx);
			args->reply_msg->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,  
					MACH_MSG_TYPE_MAKE_SEND);
			args->reply_msg->msgh_size = args->reply_size;
			args->reply_msg->msgh_remote_port = args->req_msg->msgh_remote_port;
			args->reply_msg->msgh_local_port = args->req_msg->msgh_local_port;
			args->reply_msg->msgh_id = 2;
			ret = mach_msg(args->reply_msg, 
					MACH_SEND_MSG, 
					args->reply_size, 
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

	endtsc = ReadTSR();
	gettimeofday(&endtv, NULL);

	/* report results */
	deltatsc = endtsc - starttsc;
	deltatv.tv_sec = endtv.tv_sec - starttv.tv_sec;
	deltatv.tv_usec = endtv.tv_usec - starttv.tv_usec;
	if (endtv.tv_usec < starttv.tv_usec) {
		deltatv.tv_sec--;
		deltatv.tv_usec += 1000000;
	}

	double dsecs = (double) deltatv.tv_sec + 
		1.0E-6 * (double) deltatv.tv_usec;

	printf("\n%u messages during %qd time stamp ticks\n", 
			totalmsg, deltatsc);
	printf("%g time stamp ticks per message\n", 
			(double) deltatsc / (double) totalmsg);
	printf("\n%u messages during %u.%06u seconds\n",  
			totalmsg, deltatv.tv_sec, deltatv.tv_usec);
	printf("%g messages per second\n", (double)totalmsg /  dsecs);
	printf("%g microseconds per message\n\n", 
			dsecs * 1.0E6 / (double) totalmsg); 
}

void *client(void *threadarg) 
{
	struct port_args args;
	int idx;
	mach_msg_header_t *req, *reply; 
	mach_port_t bsport, servport;
	kern_return_t ret;
	void *ints = malloc(sizeof(u_int32_t) * num_ints);

	/* find server port */
	ret = task_get_bootstrap_port(mach_task_self(), &bsport);
	if (KERN_SUCCESS != ret) {
		mach_error("task_get_bootstrap_port(): ", ret);
		exit(1);
	}
	ret = bootstrap_look_up(bsport, server_port_name, &servport); 
	if (KERN_SUCCESS != ret) {
		mach_error("bootstrap_look_up(): ", ret);
		exit(1);
	}

	setup_client_ports(&args);
	
	/* start message loop */
	for (idx = 0; idx < num_msgs; idx++) {
		req = args.req_msg;
		reply = args.reply_msg;

		req->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 
				MACH_MSG_TYPE_MAKE_SEND);
		req->msgh_size = args.req_size;
		req->msgh_remote_port = servport;
		req->msgh_local_port = args.port;
		req->msgh_id = oneway ? 0 : 1;
		switch (msg_type) {
			case msg_type_trivial:
				break;
			case msg_type_inline:
				((ipc_inline_message *)req)->type.msgt_name = MACH_MSG_TYPE_INTEGER_32;
				((ipc_inline_message *)req)->type.msgt_size = 32;
				((ipc_inline_message *)req)->type.msgt_number = num_ints;
				((ipc_inline_message *)req)->type.msgt_inline = TRUE;
				((ipc_inline_message *)req)->type.msgt_longform = FALSE;
				((ipc_inline_message *)req)->type.msgt_deallocate = FALSE;
				((ipc_inline_message *)req)->type.msgt_unused = 0;
				break;
			case msg_type_complex:
				(req)->msgh_bits |=  MACH_MSGH_BITS_COMPLEX;
				((ipc_complex_message *)req)->body.msgh_descriptor_count = 1;
				((ipc_complex_message *)req)->descriptor.address = ints;
				((ipc_complex_message *)req)->descriptor.size = 
					num_ints * sizeof(u_int32_t);
				((ipc_complex_message *)req)->descriptor.deallocate = FALSE;
				((ipc_complex_message *)req)->descriptor.copy = MACH_MSG_VIRTUAL_COPY;
				((ipc_complex_message *)req)->descriptor.type = MACH_MSG_OOL_DESCRIPTOR;
				break;
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

		if (client_delay) {
			usleep(client_delay);
		}
	}

	free(ints);
	return;
}


int main(int argc, char *argv[]) 
{
	struct port_args portargs;
	int i;

	signal(SIGINT, signal_handler);
	parse_args(argc, argv);

	setup_server_ports(&portargs);

	if (fork() != 0) {
		server(&portargs);
		exit(0);
	}

	if (num_clients > 1) {
		for (i = 1; i < num_clients; i++) {
			if (fork() == 0) {
				client(NULL);
				exit(0);
			}
		}
	}

	client(NULL);

	return (0);
}
