#define T_NAMESPACE "xnu.ipc"
#include <darwintest.h>

#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include <pthread/qos_private.h>
#include <voucher/ipc_pthread_priority_types.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

#define MSG      1024
#define PG_ALLOC 4096

typedef enum {
	ReplyWithNoError,
	ReplyWithReplyPort,
	ReplyWithReplyPortMove,
	ReplyWithReplyPortCplxBit,
	ReplyWithReplyPortMoveCplxBit,
	ReplyWithPortDesc,
	ReplyWithOOLDesc,
	ReplyWithVoucher,
	ReplyWithVoucherGarbage
} ReplyType;

struct exc_thread_arg {
	ReplyType    rt;
	mach_port_t  port;
};

static const char *
reply_type_str(ReplyType rt)
{
	switch (rt) {
	case ReplyWithNoError:
		return "ReplyWithNoError";
	case ReplyWithReplyPort:
		return "ReplyWithReplyPort";
	case ReplyWithReplyPortMove:
		return "ReplyWithReplyPortMove";
	case ReplyWithReplyPortCplxBit:
		return "ReplyWithReplyPortCplxBit";
	case ReplyWithReplyPortMoveCplxBit:
		return "ReplyWithReplyPortMoveCplxBit";
	case ReplyWithPortDesc:
		return "ReplyWithPortDesc";
	case ReplyWithOOLDesc:
		return "ReplyWithOOLDesc";
	case ReplyWithVoucher:
		return "ReplyWithVoucher";
	case ReplyWithVoucherGarbage:
		return "ReplyWithVoucherGarbage";
	}
}

static mach_voucher_t
create_pthpriority_voucher(void)
{
	char voucher_buf[sizeof(mach_voucher_attr_recipe_data_t) + sizeof(ipc_pthread_priority_value_t)];

	mach_voucher_t voucher = MACH_PORT_NULL;
	kern_return_t kr;
	ipc_pthread_priority_value_t ipc_pthread_priority_value =
	    (ipc_pthread_priority_value_t)_pthread_qos_class_encode(QOS_CLASS_USER_INTERACTIVE, 0, 0);

	mach_voucher_attr_raw_recipe_size_t recipe_size = 0;
	mach_voucher_attr_recipe_t recipe =
	    (mach_voucher_attr_recipe_t)&voucher_buf[0];

	recipe->key = MACH_VOUCHER_ATTR_KEY_PTHPRIORITY;
	recipe->command = MACH_VOUCHER_ATTR_PTHPRIORITY_CREATE;
	recipe->previous_voucher = MACH_VOUCHER_NULL;

	memcpy((char *)&recipe->content[0], &ipc_pthread_priority_value, sizeof(ipc_pthread_priority_value));
	recipe->content_size = sizeof(ipc_pthread_priority_value_t);
	recipe_size += sizeof(mach_voucher_attr_recipe_data_t) + recipe->content_size;

	kr = host_create_mach_voucher(mach_host_self(),
	    (mach_voucher_attr_raw_recipe_array_t)&voucher_buf[0],
	    recipe_size,
	    &voucher);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "host_create_mach_voucher");
	return voucher;
}

static void *
handle_exceptions(void *arg)
{
	struct exc_thread_arg *ta = (struct exc_thread_arg *)arg;
	mach_port_t ePort = ta->port;
	ReplyType reply_type = ta->rt;

	char msg_store[MSG + MAX_TRAILER_SIZE];
	char reply_store[MSG];
	mach_msg_header_t *msg = (mach_msg_header_t *)msg_store;
	vm_address_t page;
	kern_return_t kr;

	kr = vm_allocate(mach_task_self(), &page, PG_ALLOC, VM_FLAGS_ANYWHERE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ool page allocation of %d bytes", PG_ALLOC);

	mach_voucher_t voucher = create_pthpriority_voucher();

	while (1) {
		bzero(msg, sizeof(msg_store));

		msg->msgh_local_port = ePort;
		msg->msgh_size = MSG;
		kr = mach_msg_receive(msg);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "exception msg recv");

		bzero(reply_store, sizeof(reply_store));

		switch (reply_type) {
		case ReplyWithNoError: {
#pragma pack(4)
			typedef struct {
				mach_msg_header_t hdr;
				NDR_record_t ndr;
				kern_return_t kr;
			} reply_fmt_t;
#pragma pack()
			reply_fmt_t *reply = (reply_fmt_t *)reply_store;

			reply->hdr.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0, 0, 0);
			reply->hdr.msgh_remote_port = msg->msgh_remote_port;
			reply->hdr.msgh_local_port = MACH_PORT_NULL;
			reply->hdr.msgh_size = sizeof(*reply);
			reply->hdr.msgh_id = msg->msgh_id + 100;
			break;
		}

		case ReplyWithReplyPort: {
#pragma pack(4)
			typedef struct {
				mach_msg_header_t hdr;
				NDR_record_t ndr;
				kern_return_t kr;
			} reply_fmt_t;
#pragma pack()
			reply_fmt_t *reply = (reply_fmt_t *)reply_store;

			reply->hdr.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MOVE_SEND_ONCE, MACH_MSG_TYPE_COPY_SEND, 0, 0);
			reply->hdr.msgh_remote_port = msg->msgh_remote_port;
			reply->hdr.msgh_local_port = ePort; /* Bogus */
			reply->hdr.msgh_size = sizeof(*reply);
			reply->hdr.msgh_id = msg->msgh_id + 100;
			break;
		}

		case ReplyWithReplyPortMove: {
#pragma pack(4)
			typedef struct {
				mach_msg_header_t hdr;
				NDR_record_t ndr;
				kern_return_t kr;
			} reply_fmt_t;
#pragma pack()
			reply_fmt_t *reply = (reply_fmt_t *)reply_store;

			reply->hdr.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MOVE_SEND_ONCE, MACH_MSG_TYPE_MOVE_SEND, 0, 0);
			reply->hdr.msgh_remote_port = msg->msgh_remote_port;
			reply->hdr.msgh_local_port = ePort; /* Bogus */
			reply->hdr.msgh_size = sizeof(*reply);
			reply->hdr.msgh_id = msg->msgh_id + 100;
			break;
		}

		case ReplyWithReplyPortCplxBit: {
#pragma pack(4)
			typedef struct {
				mach_msg_header_t hdr;
				mach_msg_body_t body;
			} reply_fmt_t;
#pragma pack()
			reply_fmt_t *reply = (reply_fmt_t *)reply_store;

			reply->hdr.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MOVE_SEND_ONCE, MACH_MSG_TYPE_COPY_SEND, 0, MACH_MSGH_BITS_COMPLEX);
			reply->hdr.msgh_remote_port = msg->msgh_remote_port;
			reply->hdr.msgh_local_port = ePort; /* Bogus */
			reply->hdr.msgh_size = sizeof(*reply);
			reply->hdr.msgh_id = msg->msgh_id + 100;
			reply->body.msgh_descriptor_count = 0;
			break;
		}

		case ReplyWithReplyPortMoveCplxBit: {
#pragma pack(4)
			typedef struct {
				mach_msg_header_t hdr;
				mach_msg_body_t body;
			} reply_fmt_t;
#pragma pack()
			reply_fmt_t *reply = (reply_fmt_t *)reply_store;

			reply->hdr.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MOVE_SEND_ONCE, MACH_MSG_TYPE_MOVE_SEND, 0, MACH_MSGH_BITS_COMPLEX);
			reply->hdr.msgh_remote_port = msg->msgh_remote_port;
			reply->hdr.msgh_local_port = ePort; /* Bogus */
			reply->hdr.msgh_size = sizeof(*reply);
			reply->hdr.msgh_id = msg->msgh_id + 100;
			reply->body.msgh_descriptor_count = 0;
			break;
		}

		case ReplyWithPortDesc: {
#pragma pack(4)
			typedef struct {
				mach_msg_header_t hdr;
				mach_msg_body_t body;
				mach_msg_port_descriptor_t port;
			} reply_fmt_t;
#pragma pack()
			reply_fmt_t *reply = (reply_fmt_t *)reply_store;

			reply->hdr.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0, 0, MACH_MSGH_BITS_COMPLEX);
			reply->hdr.msgh_remote_port = msg->msgh_remote_port;
			reply->hdr.msgh_local_port = MACH_PORT_NULL;
			reply->hdr.msgh_size = sizeof(*reply);
			reply->hdr.msgh_id = msg->msgh_id + 100;
			reply->body.msgh_descriptor_count = 1;
			reply->port.type = MACH_MSG_PORT_DESCRIPTOR;
			reply->port.name = ePort;
			reply->port.disposition = MACH_MSG_TYPE_COPY_SEND;
			break;
		}

		case ReplyWithOOLDesc: {
#pragma pack(4)
			typedef struct {
				mach_msg_header_t hdr;
				mach_msg_body_t body;
				mach_msg_ool_descriptor_t ool;
			} reply_fmt_t;
#pragma pack()
			reply_fmt_t *reply = (reply_fmt_t *)reply_store;

			reply->hdr.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0, 0, MACH_MSGH_BITS_COMPLEX);
			reply->hdr.msgh_remote_port = msg->msgh_remote_port;
			reply->hdr.msgh_local_port = MACH_PORT_NULL;
			reply->hdr.msgh_size = sizeof(*reply);
			reply->hdr.msgh_id = msg->msgh_id + 100;
			reply->body.msgh_descriptor_count = 1;
			reply->ool.type = MACH_MSG_OOL_DESCRIPTOR;
			reply->ool.address = (void *)page;
			reply->ool.size = PG_ALLOC;
			reply->ool.deallocate = 0;
			reply->ool.copy = MACH_MSG_VIRTUAL_COPY;
			break;
		}

		case ReplyWithVoucher: {
#pragma pack(4)
			typedef struct {
				mach_msg_header_t hdr;
				NDR_record_t ndr;
				kern_return_t kr;
			} reply_fmt_t;
#pragma pack()
			reply_fmt_t *reply = (reply_fmt_t *)reply_store;

			reply->hdr.msgh_remote_port = msg->msgh_remote_port;
			reply->hdr.msgh_local_port = MACH_PORT_NULL;
			reply->hdr.msgh_size = sizeof(*reply);
			reply->hdr.msgh_id = msg->msgh_id + 100;
			reply->kr = KERN_SUCCESS;

			/* try to send a voucher */
			reply->hdr.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MOVE_SEND_ONCE,
			    0,
			    MACH_MSG_TYPE_MOVE_SEND,
			    0);
			reply->hdr.msgh_voucher_port = voucher;
			voucher = MACH_VOUCHER_NULL;
			break;
		}

		case ReplyWithVoucherGarbage: {
#pragma pack(4)
			typedef struct {
				mach_msg_header_t hdr;
				NDR_record_t ndr;
				kern_return_t kr;
			} reply_fmt_t;
#pragma pack()
			reply_fmt_t *reply = (reply_fmt_t *)reply_store;

			reply->hdr.msgh_remote_port = msg->msgh_remote_port;
			reply->hdr.msgh_local_port = MACH_PORT_NULL;
			reply->hdr.msgh_size = sizeof(*reply);
			reply->hdr.msgh_id = msg->msgh_id + 100;
			reply->kr = KERN_SUCCESS;

			/* don't claim to send a voucher */
			reply->hdr.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MOVE_SEND_ONCE,
			    0, 0, 0);
			/* but put some bits in the field */
			reply->hdr.msgh_voucher_port = (mach_voucher_t)0xdead;
			break;
		}

		default:
			T_ASSERT_FAIL("Invalid ReplyType: %d", reply_type);
			T_END;
		}

		if (voucher) {
			kr = mach_port_mod_refs(mach_task_self(), voucher,
			    MACH_PORT_RIGHT_SEND, -1);
			T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "destroy voucher");
		}

		T_LOG("sending exception reply of type (%s)", reply_type_str(reply_type));
		kr = mach_msg_send((mach_msg_header_t *)reply_store);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "exception reply msg send");

		T_PASS("Successfully delivered exception reply message of type %s", reply_type_str(reply_type));
		T_END;
		return NULL;
	}
}

static sigjmp_buf jb;
static int *bad_pointer = NULL;
static int s_sigmask = 0;

static void
signal_handler(int sig, siginfo_t *sip __unused, void *ucontext __unused)
{
	if (sigmask(sig) & s_sigmask) { /* TODO: check that the fault was generated by us */
		siglongjmp(jb, sig);
	} else {
		siglongjmp(jb, -sig);
	}
}

static int
handle_signals(void)
{
	int mask = 0;

	struct sigaction sa = {
		.sa_sigaction = signal_handler,
		.sa_flags = SA_SIGINFO
	};
	sigfillset(&sa.sa_mask);

	T_QUIET; T_ASSERT_POSIX_ZERO(sigaction(SIGTRAP, &sa, NULL), NULL);
	mask |= sigmask(SIGTRAP);

	T_QUIET; T_ASSERT_POSIX_ZERO(sigaction(SIGSEGV, &sa, NULL), NULL);
	mask |= sigmask(SIGSEGV);

	T_QUIET; T_ASSERT_POSIX_ZERO(sigaction(SIGILL, &sa, NULL), NULL);
	mask |= sigmask(SIGILL);

	return mask;
}

static void
test_exc_reply_type(ReplyType reply_type)
{
	kern_return_t kr;
	task_t me = mach_task_self();
	thread_t self = mach_thread_self();
	pthread_t handler_thread;
	pthread_attr_t  attr;
	mach_port_t ePort;

	s_sigmask = handle_signals();
	T_LOG("task self = 0x%x, thread self = 0x%x\n", me, self);

	kr = mach_port_allocate(me, MACH_PORT_RIGHT_RECEIVE, &ePort);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "allocate receive right");

	kr = mach_port_insert_right(me, ePort, ePort, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "insert right into port=[%d]", ePort);

	kr = thread_set_exception_ports(self, EXC_MASK_ALL, ePort, EXCEPTION_DEFAULT, THREAD_STATE_NONE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "set exception ports on self=[%d], handler=[%d]", self, ePort);

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	struct exc_thread_arg *ta = (struct exc_thread_arg *)malloc(sizeof(*ta));
	T_QUIET; T_ASSERT_NOTNULL(ta, "exception handler thread args allocation");
	ta->port = ePort;
	ta->rt = reply_type;

	T_QUIET; T_ASSERT_POSIX_SUCCESS(pthread_create(&handler_thread, &attr, handle_exceptions, (void *)ta),
	    "pthread creation");

	pthread_attr_destroy(&attr);

	/* cause exception! */
	int x = sigsetjmp(jb, 0); //s_sigmask);
	if (x == 0) {
		*bad_pointer = 0;
	} else if (x < 0) {
		T_FAIL("Unexpected state on return-from-exception");
		T_END;
	} else {
		T_PASS("Successfully recovered from exception");
		T_END;
	}
	T_FAIL("Unexpected end of test!");
	T_END;
}

T_DECL(mach_exc_ReplyNoError, "exception server reply with no error",
    T_META_CHECK_LEAKS(false), T_META_IGNORECRASHES(".*mach_exception_reply.*"))
{
	test_exc_reply_type(ReplyWithNoError);
}
T_DECL(mach_exc_ReplyWithReplyPort, "exception server reply with reply port",
    T_META_CHECK_LEAKS(false), T_META_IGNORECRASHES(".*mach_exception_reply.*"))
{
	test_exc_reply_type(ReplyWithReplyPort);
}
T_DECL(mach_exc_ReplyWithReplyPortMove, "exception server reply with reply port as MOVE_SEND",
    T_META_CHECK_LEAKS(false), T_META_IGNORECRASHES(".*mach_exception_reply.*"))
{
	test_exc_reply_type(ReplyWithReplyPortMove);
}
T_DECL(mach_exc_ReplyWithReplyPortCplxBit, "exception server reply with reply port and complex bit set",
    T_META_CHECK_LEAKS(false), T_META_IGNORECRASHES(".*mach_exception_reply.*"))
{
	test_exc_reply_type(ReplyWithReplyPortCplxBit);
}
T_DECL(mach_exc_ReplyWithReplyPortMoveCplxBit, "exception server reply with reply port as MOVE_SEND and complex bit set",
    T_META_CHECK_LEAKS(false), T_META_IGNORECRASHES(".*mach_exception_reply.*"))
{
	test_exc_reply_type(ReplyWithReplyPortMoveCplxBit);
}
T_DECL(mach_exc_ReplyWithOOLPort, "exception server reply with OOL port descriptor",
    T_META_CHECK_LEAKS(false), T_META_IGNORECRASHES(".*mach_exception_reply.*"))
{
	test_exc_reply_type(ReplyWithPortDesc);
}
T_DECL(mach_exc_ReplyWithOOLDesc, "exception server reply with OOL memory descriptor",
    T_META_CHECK_LEAKS(false), T_META_IGNORECRASHES(".*mach_exception_reply.*"))
{
	test_exc_reply_type(ReplyWithOOLDesc);
}
T_DECL(mach_exc_ReplyWithVoucher, "exception server reply with a voucher",
    T_META_CHECK_LEAKS(false), T_META_IGNORECRASHES(".*mach_exception_reply.*"))
{
	test_exc_reply_type(ReplyWithVoucher);
}
T_DECL(mach_exc_ReplyWithVoucherGarbage, "exception server reply with bits in msgh_voucher_port",
    T_META_CHECK_LEAKS(false), T_META_IGNORECRASHES(".*mach_exception_reply.*"))
{
	test_exc_reply_type(ReplyWithVoucherGarbage);
}
