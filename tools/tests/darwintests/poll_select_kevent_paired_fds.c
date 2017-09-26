#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif

#include <darwintest.h>
#include <mach/mach.h>
#include <darwintest_multiprocess.h>

#include <assert.h>
#include <dispatch/dispatch.h>
#include <dispatch/private.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <pthread/workqueue_private.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <unistd.h>
#include <util.h>
#include <System/sys/event.h> /* kevent_qos */

T_GLOBAL_META(
		T_META_NAMESPACE("xnu.kevent"),
		T_META_CHECK_LEAKS(false),
		T_META_LTEPHASE(LTE_POSTINIT));

/*
 * Test to validate that monitoring a PTY device, FIFO, pipe, or socket pair in
 * a dispatch source, kqueue, poll, or select delivers read events within and
 * between processes as expected.
 *
 * This test catches issues with watching special devices in kqueue(),
 * which has tricky special cases for character devices like PTYs.
 *
 * It also exercises the path to wake up a dispatch worker thread from the
 * special device kqueue event, which is also a special case in kqueue().
 *
 * See rdar://problem/26240299&26220074&26226862&28625427 for examples and
 * history.
 */

#define EXPECTED_STRING    "abcdefghijklmnopqrstuvwxyz. ABCDEFGHIJKLMNOPQRSTUVWXYZ. 1234567890"
#define EXPECTED_LEN       strlen(EXPECTED_STRING)

#define READ_SETUP_TIMEOUT_SECS       2
#define WRITE_TIMEOUT_SECS            4
#define READ_TIMEOUT_SECS             4
#define INCREMENTAL_WRITE_SLEEP_USECS 50

static mach_timespec_t READ_SETUP_timeout = {.tv_sec = READ_SETUP_TIMEOUT_SECS, .tv_nsec = 0};
static mach_timespec_t READ_timeout = {.tv_sec = READ_TIMEOUT_SECS, .tv_nsec = 0};
static mach_timespec_t WRITE_timeout = {.tv_sec = WRITE_TIMEOUT_SECS, .tv_nsec = 0};

enum fd_pair {
	PTY_PAIR,
	FIFO_PAIR,
	PIPE_PAIR,
	SOCKET_PAIR
};

enum write_mode {
	FULL_WRITE,
	INCREMENTAL_WRITE,
	KEVENT_INCREMENTAL_WRITE,
	KEVENT64_INCREMENTAL_WRITE,
	KEVENT_QOS_INCREMENTAL_WRITE,
	WORKQ_INCREMENTAL_WRITE,
	DISPATCH_INCREMENTAL_WRITE
};

enum read_mode {
	POLL_READ,
	SELECT_READ,
	KEVENT_READ,
	KEVENT64_READ,
	KEVENT_QOS_READ,
	WORKQ_READ,
	DISPATCH_READ
};

union mode {
	enum read_mode rd;
	enum write_mode wr;
};

static struct {
	enum fd_pair fd_pair;
	enum write_mode wr_mode;
	int wr_fd;
	enum read_mode rd_mode;
	int rd_fd;

	enum writer_kind {
		THREAD_WRITER, /* sem */
		PROCESS_WRITER /* fd */
	} wr_kind;
	union {
		semaphore_t sem;
		struct {
			int in_fd;
			int out_fd;
		};
	} wr_wait;
	semaphore_t wr_finished;
	semaphore_t rd_finished;
} shared;

static bool handle_reading(enum fd_pair fd_pair, int fd);
static bool handle_writing(enum fd_pair fd_pair, int fd);
static void drive_kq(bool reading, union mode mode, enum fd_pair fd_pair,
		int fd);

#pragma mark writing

static void
wake_writer(void)
{
	T_LOG("waking writer");

	switch (shared.wr_kind) {
	case THREAD_WRITER:
		T_LOG("signal shared.wr_wait.sem");
		semaphore_signal(shared.wr_wait.sem);
		break;
	case PROCESS_WRITER: {
		char tmp = 'a';
		close(shared.wr_wait.out_fd);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(write(
				shared.wr_wait.in_fd, &tmp, 1), NULL);
		break;
	}
	}
}

static void
writer_wait(void)
{
	switch (shared.wr_kind) {
	case THREAD_WRITER:
		T_LOG("wait shared.wr_wait.sem");
		kern_return_t kret = semaphore_timedwait(shared.wr_wait.sem, READ_SETUP_timeout);

		if (kret == KERN_OPERATION_TIMED_OUT) {
			T_ASSERT_FAIL("THREAD_WRITER semaphore timedout after %d seconds", READ_SETUP_timeout.tv_sec);
		}
		T_QUIET;
		T_ASSERT_MACH_SUCCESS(kret, "semaphore_timedwait shared.wr_wait.sem");
		break;

	case PROCESS_WRITER: {
		char tmp;
		close(shared.wr_wait.in_fd);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(read(
				shared.wr_wait.out_fd, &tmp, 1), NULL);
		break;
	}
	}

	T_LOG("writer woken up, starting to write");
}

static bool
handle_writing(enum fd_pair __unused fd_pair, int fd)
{
	static unsigned int cur_char = 0;
	T_QUIET; T_ASSERT_POSIX_SUCCESS(write(fd,
			&(EXPECTED_STRING[cur_char]), 1), NULL);
	cur_char++;

	return (cur_char < EXPECTED_LEN);
}

#define EXPECTED_QOS QOS_CLASS_USER_INITIATED

static void
reenable_workq(int fd, int16_t filt)
{
	struct kevent_qos_s events[] = {{
		.ident = (uint64_t)fd,
		.filter = filt,
		.flags = EV_ENABLE | EV_UDATA_SPECIFIC | EV_DISPATCH,
		.qos = (int32_t)_pthread_qos_class_encode(EXPECTED_QOS,
				0, 0),
		.fflags = NOTE_LOWAT,
		.data = 1
	}};

	int kev = kevent_qos(-1, events, 1, events, 1, NULL, NULL,
			KEVENT_FLAG_WORKQ | KEVENT_FLAG_ERROR_EVENTS);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(kev, "reenable workq in kevent_qos");
}

static void
workqueue_write_fn(void ** __unused buf, int * __unused count)
{
	// T_MAYFAIL;
	// T_QUIET; T_ASSERT_EFFECTIVE_QOS_EQ(EXPECTED_QOS,
			// "writer thread should be woken up at correct QoS");
	if (!handle_writing(shared.fd_pair, shared.wr_fd)) {
		/* finished handling the fd, tear down the source */
		T_LOG("signal shared.wr_finished");
		semaphore_signal(shared.wr_finished);
		return;
	}

	reenable_workq(shared.wr_fd, EVFILT_WRITE);
}

static void
workqueue_fn(pthread_priority_t __unused priority)
{
	T_ASSERT_FAIL("workqueue function callback was called");
}

static void
drive_kq(bool reading, union mode mode, enum fd_pair fd_pair, int fd)
{
	struct timespec timeout = { .tv_sec = READ_TIMEOUT_SECS };
	int kev = -1;

	struct kevent events;
	EV_SET(&events, fd, reading ? EVFILT_READ : EVFILT_WRITE, EV_ADD,
			NOTE_LOWAT, 1, NULL);
	struct kevent64_s events64;
	EV_SET64(&events64, fd, reading ? EVFILT_READ : EVFILT_WRITE, EV_ADD,
			NOTE_LOWAT, 1, 0, 0, 0);
	struct kevent_qos_s events_qos[] = {{
		.ident = (uint64_t)fd,
		.filter = reading ? EVFILT_READ : EVFILT_WRITE,
		.flags = EV_ADD,
		.fflags = NOTE_LOWAT,
		.data = 1
	}, {
		.ident = 0,
		.filter = EVFILT_TIMER,
		.flags = EV_ADD,
		.fflags = NOTE_SECONDS,
		.data = READ_TIMEOUT_SECS
	}};

	/* determine which variant of kevent to use */
	enum read_mode which_kevent;
	if (reading) {
		which_kevent = mode.rd;
	} else {
		if (mode.wr == KEVENT_INCREMENTAL_WRITE) {
			which_kevent = KEVENT_READ;
		} else if (mode.wr == KEVENT64_INCREMENTAL_WRITE) {
			which_kevent = KEVENT64_READ;
		} else if (mode.wr == KEVENT_QOS_INCREMENTAL_WRITE) {
			which_kevent = KEVENT_QOS_READ;
		} else {
			T_ASSERT_FAIL("unexpected mode: %d", mode.wr);
			__builtin_unreachable();
		}
	}

	int kq_fd = kqueue();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(kq_fd, "kqueue");

	switch (which_kevent) {
	case KEVENT_READ:
		kev = kevent(kq_fd, &events, 1, NULL, 0, NULL);
		break;
	case KEVENT64_READ:
		kev = kevent64(kq_fd, &events64, 1, NULL, 0, 0, NULL);
		break;
	case KEVENT_QOS_READ:
		kev = kevent_qos(kq_fd, events_qos, 2, NULL, 0, NULL, NULL, 0);
		break;
	case POLL_READ: /* FALLTHROUGH */
	case SELECT_READ: /* FALLTHROUGH */
	case DISPATCH_READ: /* FALLTHROUGH */
	case WORKQ_READ: /* FALLTHROUGH */
	default:
		T_ASSERT_FAIL("unexpected mode: %d", reading ? mode.rd : mode.wr);
		break;
	}

	if (reading) {
		wake_writer();
	} else {
		writer_wait();
	}

	for (;;) {
		switch (which_kevent) {
		case KEVENT_READ:
			kev = kevent(kq_fd, NULL, 0, &events, 1, &timeout);
			break;
		case KEVENT64_READ:
			kev = kevent64(kq_fd, NULL, 0, &events64, 1, 0, &timeout);
			break;
		case KEVENT_QOS_READ:
			kev = kevent_qos(kq_fd, NULL, 0, events_qos, 2, NULL, NULL, 0);

			/* check for a timeout */
			for (int i = 0; i < kev; i++) {
				if (events_qos[i].filter == EVFILT_TIMER) {
					kev = 0;
				}
			}
			break;
		case POLL_READ: /* FALLTHROUGH */
		case SELECT_READ: /* FALLTHROUGH */
		case DISPATCH_READ: /* FALLTHROUGH */
		case WORKQ_READ: /* FALLTHROUGH */
		default:
			T_ASSERT_FAIL("unexpected mode: %d", reading ? mode.rd : mode.wr);
			break;
		}

		if (kev == -1 && errno == EINTR) {
			T_LOG("kevent was interrupted");
			continue;
		}
		T_QUIET; T_ASSERT_POSIX_SUCCESS(kev, "kevent");
		T_QUIET; T_ASSERT_NE(kev, 0, "kevent timed out");

		if (reading) {
			if (!handle_reading(fd_pair, fd)) {
				break;
			}
		} else {
			if (!handle_writing(fd_pair, fd)) {
				break;
			}
		}
	}

	close(kq_fd);
}

static void *
write_to_fd(void * __unused ctx)
{
	ssize_t bytes_wr = 0;

	writer_wait();

	switch (shared.wr_mode) {
	case FULL_WRITE:
		do {
			if (bytes_wr == -1) {
				T_LOG("write from child was interrupted");
			}
			bytes_wr = write(shared.wr_fd, EXPECTED_STRING,
					EXPECTED_LEN);
		} while (bytes_wr == -1 && errno == EINTR);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(bytes_wr, "write");
		T_QUIET; T_ASSERT_EQ(bytes_wr, (ssize_t)EXPECTED_LEN,
				"wrote enough bytes");
		break;

	case INCREMENTAL_WRITE:
		for (unsigned int i = 0; i < EXPECTED_LEN ; i++) {
			T_QUIET;
			T_ASSERT_POSIX_SUCCESS(write(shared.wr_fd,
					&(EXPECTED_STRING[i]), 1), NULL);
			usleep(INCREMENTAL_WRITE_SLEEP_USECS);
		}
		break;

	case KEVENT_INCREMENTAL_WRITE: /* FALLTHROUGH */
	case KEVENT64_INCREMENTAL_WRITE: /* FALLTHROUGH */
	case KEVENT_QOS_INCREMENTAL_WRITE: {
		union mode mode = { .wr = shared.wr_mode };
		drive_kq(false, mode, shared.fd_pair, shared.wr_fd);
		break;
	}

	case WORKQ_INCREMENTAL_WRITE: {
		// prohibit ourselves from going multi-threaded see:rdar://33296008
		_dispatch_prohibit_transition_to_multithreaded(true);
		int changes = 1;

		T_ASSERT_MACH_SUCCESS(semaphore_create(mach_task_self(), &shared.wr_finished, SYNC_POLICY_FIFO, 0),
		                      "semaphore_create shared.wr_finished");

		T_QUIET;
		T_ASSERT_NE_UINT(shared.wr_finished, (unsigned)MACH_PORT_NULL, "wr_finished semaphore_create");

		T_QUIET;
		T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_kevent(workqueue_fn, workqueue_write_fn, 0, 0), NULL);

		struct kevent_qos_s events[] = {{
			.ident = (uint64_t)shared.wr_fd,
			.filter = EVFILT_WRITE,
			.flags = EV_ADD | EV_UDATA_SPECIFIC | EV_DISPATCH | EV_VANISHED,
			.fflags = NOTE_LOWAT,
			.data = 1,
			.qos = (int32_t)_pthread_qos_class_encode(EXPECTED_QOS,
					0, 0)
		}};

		for (;;) {
			int kev = kevent_qos(-1, changes == 0 ? NULL : events, changes,
					events, 1, NULL, NULL,
					KEVENT_FLAG_WORKQ | KEVENT_FLAG_ERROR_EVENTS);
			if (kev == -1 && errno == EINTR) {
				changes = 0;
				T_LOG("kevent_qos was interrupted");
				continue;
			}

			T_QUIET; T_ASSERT_POSIX_SUCCESS(kev, "kevent_qos");
			break;
		}
		break;
	}

	case DISPATCH_INCREMENTAL_WRITE: {
		dispatch_source_t write_src;

		T_ASSERT_MACH_SUCCESS(semaphore_create(mach_task_self(), &shared.wr_finished, SYNC_POLICY_FIFO, 0),
		                      "semaphore_create shared.wr_finished");

		T_QUIET;
		T_ASSERT_NE_UINT(shared.wr_finished, (unsigned)MACH_PORT_NULL, "semaphore_create");

		write_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE,
				(uintptr_t)shared.wr_fd, 0, NULL);
		T_QUIET; T_ASSERT_NOTNULL(write_src,
				"dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE ...)");

		dispatch_block_t handler = dispatch_block_create_with_qos_class(
				DISPATCH_BLOCK_ENFORCE_QOS_CLASS, EXPECTED_QOS, 0, ^{
			// T_MAYFAIL;
			// T_QUIET; T_ASSERT_EFFECTIVE_QOS_EQ(EXPECTED_QOS,
					// "write handler block should run at correct QoS");
			if (!handle_writing(shared.fd_pair, shared.wr_fd)) {
				/* finished handling the fd, tear down the source */
				dispatch_source_cancel(write_src);
				dispatch_release(write_src);
				T_LOG("signal shared.wr_finished");
				semaphore_signal(shared.wr_finished);
			}
		});

		dispatch_source_set_event_handler(write_src, handler);
		dispatch_activate(write_src);

		break;
	}

	default:
		T_ASSERT_FAIL("unrecognized write mode: %d", shared.wr_mode);
		break;
	}

	if (shared.wr_finished) {
		T_LOG("wait shared.wr_finished");
		kern_return_t kret = semaphore_timedwait(shared.wr_finished, WRITE_timeout);
		if (kret == KERN_OPERATION_TIMED_OUT) {
			T_ASSERT_FAIL("write side semaphore timedout after %d seconds", WRITE_timeout.tv_sec);
		}
		T_QUIET;
		T_ASSERT_MACH_SUCCESS(kret, "semaphore_timedwait shared.wr_finished");
		semaphore_destroy(mach_task_self(), shared.wr_finished);
	}

	T_LOG("writer finished, closing fd");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(close(shared.wr_fd), NULL);
	return NULL;
}

#pragma mark reading

#define BUF_LEN 1024
static char final_string[BUF_LEN];
static size_t final_length;

/*
 * Read from the master PTY descriptor.
 *
 * Returns false if EOF is encountered, and true otherwise.
 */
static bool
handle_reading(enum fd_pair fd_pair, int fd)
{
	char read_buf[BUF_LEN] = { 0 };
	ssize_t bytes_rd = 0;

	do {
		if (bytes_rd == -1) {
			T_LOG("read was interrupted, retrying");
		}
		bytes_rd = read(fd, read_buf, sizeof(read_buf) - 1);
	} while (bytes_rd == -1 && errno == EINTR);

	// T_LOG("read %zd bytes: '%s'", bytes_rd, read_buf);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(bytes_rd, "reading from file");
	T_QUIET; T_ASSERT_LE(bytes_rd, (ssize_t)EXPECTED_LEN,
			"read too much from file");

	if (bytes_rd == 0) {
		T_LOG("read EOF from file");
		return false;
	}

	read_buf[bytes_rd] = '\0';
	strlcpy(&(final_string[final_length]), read_buf,
			sizeof(final_string) - final_length);
	final_length += (size_t)bytes_rd;

	T_QUIET; T_ASSERT_LE(final_length, EXPECTED_LEN,
			"should not read more from file than what can be sent");

	/* FIFOs don't (and TTYs may not) send EOF when the write side closes */
	if (final_length == strlen(EXPECTED_STRING) &&
			(fd_pair == FIFO_PAIR || fd_pair == PTY_PAIR))
	{
		T_LOG("read all expected bytes from %s",
				fd_pair == FIFO_PAIR ? "FIFO" : "PTY");
		return false;
	}
	return true;
}

static void
workqueue_read_fn(void ** __unused buf, int * __unused count)
{
	// T_MAYFAIL;
	// T_QUIET; T_ASSERT_EFFECTIVE_QOS_EQ(EXPECTED_QOS,
			// "reader thread should be requested at correct QoS");
	if (!handle_reading(shared.fd_pair, shared.rd_fd)) {
		T_LOG("signal shared.rd_finished");
		semaphore_signal(shared.rd_finished);
	}

	reenable_workq(shared.rd_fd, EVFILT_READ);
}

static void
read_from_fd(int fd, enum fd_pair fd_pair, enum read_mode mode)
{
	int fd_flags;

	T_LOG("reader setting up");

	bzero(final_string, sizeof(final_string));

	fd_flags = fcntl(fd, F_GETFL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd_flags, "fcntl(F_GETFL)");

	if (!(fd_flags & O_NONBLOCK)) {
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(fcntl(fd, F_SETFL,
			fd_flags | O_NONBLOCK), NULL);
	}

	switch (mode) {
	case POLL_READ: {
		struct pollfd fds[] = { { .fd = fd, .events = POLLIN } };
		wake_writer();

		for (;;) {
			fds[0].revents = 0;
			int pol = poll(fds, 1, READ_TIMEOUT_SECS * 1000);
			T_QUIET; T_ASSERT_POSIX_SUCCESS(pol, "poll");
			T_QUIET; T_ASSERT_NE(pol, 0,
					"poll should not time out after %d seconds, read %zd out "
					"of %zu bytes",
					READ_TIMEOUT_SECS, final_length, strlen(EXPECTED_STRING));
			T_QUIET; T_ASSERT_FALSE(fds[0].revents & POLLERR,
					"should not see an error on the device");
			T_QUIET; T_ASSERT_FALSE(fds[0].revents & POLLNVAL,
					"should not set up an invalid poll");

			if (!handle_reading(fd_pair, fd)) {
				break;
			}
		}
		break;
	}

	case SELECT_READ:
		wake_writer();

		for (;;) {
			struct timeval tv = { .tv_sec = READ_TIMEOUT_SECS };

			fd_set read_fd;
			FD_ZERO(&read_fd);
			FD_SET(fd, &read_fd);
			fd_set err_fd;
			FD_ZERO(&err_fd);
			FD_SET(fd, &err_fd);

			int sel = select(fd + 1, &read_fd, NULL, NULL/*&err_fd*/, &tv);
			if (sel == -1 && errno == EINTR) {
				T_LOG("select interrupted");
				continue;
			}
			(void)fd_pair;

			T_QUIET; T_ASSERT_POSIX_SUCCESS(sel, "select");

			T_QUIET; T_ASSERT_NE(sel, 0,
				"select waited for %d seconds and timed out",
				READ_TIMEOUT_SECS);

			if (fd_pair == PTY_PAIR) {
				/*
				 * XXX sometimes a PTY doesn't send EOF when the writer closes
				 */
				T_MAYFAIL;
			}
			/* didn't fail or time out, therefore data is ready */
			T_QUIET; T_ASSERT_NE(FD_ISSET(fd, &read_fd), 0,
					"select should show reading fd as readable");

			if (!handle_reading(fd_pair, fd)) {
				break;
			}
		}
		break;

	case KEVENT_READ: /* FALLTHROUGH */
	case KEVENT64_READ: /* FALLTHROUGH */
	case KEVENT_QOS_READ: {
		union mode rd_mode = { .rd = shared.rd_mode };
		drive_kq(true, rd_mode, fd_pair, shared.rd_fd);
		break;
	}

	case WORKQ_READ: {
		// prohibit ourselves from going multi-threaded see:rdar://33296008
		_dispatch_prohibit_transition_to_multithreaded(true);
		T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_kevent(
				workqueue_fn, workqueue_read_fn, 0, 0), NULL);

		T_ASSERT_MACH_SUCCESS(semaphore_create(mach_task_self(), &shared.rd_finished, SYNC_POLICY_FIFO, 0),
		                      "semaphore_create shared.rd_finished");

		T_QUIET;
		T_ASSERT_NE_UINT(shared.rd_finished, (unsigned)MACH_PORT_NULL, "semaphore_create");

		int changes = 1;
		struct kevent_qos_s events[] = {{
			.ident = (uint64_t)shared.rd_fd,
			.filter = EVFILT_READ,
			.flags = EV_ADD | EV_UDATA_SPECIFIC | EV_DISPATCH | EV_VANISHED,
			.fflags = NOTE_LOWAT,
			.data = 1,
			.qos = (int32_t)_pthread_qos_class_encode(EXPECTED_QOS,
					0, 0)
		}};

		for (;;) {
			int kev = kevent_qos(-1, changes == 0 ? NULL : events, changes,
					events, 1, NULL, NULL,
					KEVENT_FLAG_WORKQ | KEVENT_FLAG_ERROR_EVENTS);
			if (kev == -1 && errno == EINTR) {
				changes = 0;
				T_LOG("kevent_qos was interrupted");
				continue;
			}

			T_QUIET; T_ASSERT_POSIX_SUCCESS(kev, "kevent_qos");
			break;
		}

		wake_writer();
		break;
	}

	case DISPATCH_READ: {
		dispatch_source_t read_src;

		T_ASSERT_MACH_SUCCESS(semaphore_create(mach_task_self(), &shared.rd_finished, SYNC_POLICY_FIFO, 0),
		                      "semaphore_create shared.rd_finished");

		T_QUIET;
		T_ASSERT_NE_UINT(shared.rd_finished, (unsigned)MACH_PORT_NULL, "semaphore_create");

		read_src = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,
				(uintptr_t)fd, 0, NULL);
		T_QUIET; T_ASSERT_NOTNULL(read_src,
				"dispatch_source_create(DISPATCH_SOURCE_TYPE_READ)");

		dispatch_block_t handler = dispatch_block_create_with_qos_class(
				DISPATCH_BLOCK_ENFORCE_QOS_CLASS, EXPECTED_QOS, 0, ^{
			// T_MAYFAIL;
			// T_QUIET; T_ASSERT_EFFECTIVE_QOS_EQ(EXPECTED_QOS,
					// "read handler block should run at correct QoS");

			if (!handle_reading(fd_pair, fd)) {
				/* finished handling the fd, tear down the source */
				dispatch_source_cancel(read_src);
				dispatch_release(read_src);
				T_LOG("signal shared.rd_finished");
				semaphore_signal(shared.rd_finished);
			}
		});

		dispatch_source_set_event_handler(read_src, handler);
		dispatch_activate(read_src);

		wake_writer();
		break;
	}

	default:
		T_ASSERT_FAIL("unrecognized read mode: %d", mode);
		break;
	}

	if (shared.rd_finished) {
		T_LOG("wait shared.rd_finished");
		kern_return_t kret = semaphore_timedwait(shared.rd_finished, READ_timeout);
		if (kret == KERN_OPERATION_TIMED_OUT) {
			T_ASSERT_FAIL("reading timed out after %d seconds", READ_timeout.tv_sec);
		}
		T_QUIET;
		T_ASSERT_MACH_SUCCESS(kret, "semaphore_timedwait shared.rd_finished");
	}

	T_EXPECT_EQ_STR(final_string, EXPECTED_STRING,
			"reader should receive valid string");
	T_QUIET; T_ASSERT_POSIX_SUCCESS(close(fd), NULL);
}

#pragma mark file setup

static void
fd_pair_init(enum fd_pair fd_pair, int *rd_fd, int *wr_fd)
{
	switch (fd_pair) {
	case PTY_PAIR:
		T_ASSERT_POSIX_SUCCESS(openpty(rd_fd, wr_fd, NULL, NULL, NULL),
				NULL);
		break;

	case FIFO_PAIR: {
		char fifo_path[] = "/tmp/async-io-fifo.XXXXXX";
		T_QUIET; T_ASSERT_NOTNULL(mktemp(fifo_path), NULL);

		T_ASSERT_POSIX_SUCCESS(mkfifo(fifo_path, 0700), "mkfifo(%s, 0700)",
				fifo_path);
		/*
		 * Opening the read side of a pipe will block until the write
		 * side opens -- use O_NONBLOCK.
		 */
		*rd_fd = open(fifo_path, O_RDONLY | O_NONBLOCK);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(*rd_fd, "open(... O_RDONLY)");
		*wr_fd = open(fifo_path, O_WRONLY | O_NONBLOCK);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(*wr_fd, "open(... O_WRONLY)");
		break;
	}

	case PIPE_PAIR: {
		int pipe_fds[2];
		T_ASSERT_POSIX_SUCCESS(pipe(pipe_fds), NULL);
		*rd_fd = pipe_fds[0];
		*wr_fd = pipe_fds[1];
		break;
	}

	case SOCKET_PAIR: {
		int sock_fds[2];
		T_ASSERT_POSIX_SUCCESS(socketpair(AF_UNIX, SOCK_STREAM, 0, sock_fds),
				NULL);
		*rd_fd = sock_fds[0];
		*wr_fd = sock_fds[1];
		break;
	}

	default:
		T_ASSERT_FAIL("unknown descriptor pair type: %d", fd_pair);
		break;
	}

	T_QUIET; T_ASSERT_NE(*rd_fd, -1, "reading descriptor");
	T_QUIET; T_ASSERT_NE(*wr_fd, -1, "writing descriptor");
}

#pragma mark single process

static void
drive_threads(enum fd_pair fd_pair, enum read_mode rd_mode,
		enum write_mode wr_mode)
{
	pthread_t thread;

	shared.fd_pair = fd_pair;
	shared.rd_mode = rd_mode;
	shared.wr_mode = wr_mode;
	fd_pair_init(fd_pair, &(shared.rd_fd), &(shared.wr_fd));

	shared.wr_kind = THREAD_WRITER;
	T_ASSERT_MACH_SUCCESS(semaphore_create(mach_task_self(), &shared.wr_wait.sem, SYNC_POLICY_FIFO, 0),
	                      "semaphore_create shared.wr_wait.sem");

	T_QUIET;
	T_ASSERT_POSIX_ZERO(pthread_create(&thread, NULL, write_to_fd, NULL),
			NULL);
	T_LOG("created writer thread");

	read_from_fd(shared.rd_fd, fd_pair, rd_mode);

	T_ASSERT_POSIX_ZERO(pthread_join(thread, NULL), NULL);

	T_END;
}

#pragma mark multiple processes

static void __attribute__((noreturn))
drive_processes(enum fd_pair fd_pair, enum read_mode rd_mode, enum write_mode wr_mode)
{
	shared.fd_pair = fd_pair;
	shared.rd_mode = rd_mode;
	shared.wr_mode = wr_mode;
	fd_pair_init(fd_pair, &(shared.rd_fd), &(shared.wr_fd));

	shared.wr_kind = PROCESS_WRITER;
	int fds[2];
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pipe(fds), NULL);
	shared.wr_wait.out_fd = fds[0];
	shared.wr_wait.in_fd = fds[1];

	T_LOG("starting subprocesses");
	dt_helper_t helpers[2] = {
		dt_fork_helper("reader_helper"),
		dt_fork_helper("writer_helper")
	};

	close(shared.rd_fd);
	close(shared.wr_fd);

	dt_run_helpers(helpers, 2, 50000);
}

T_HELPER_DECL(reader_helper, "Read asynchronously")
{
	close(shared.wr_fd);
	read_from_fd(shared.rd_fd, shared.fd_pair, shared.rd_mode);
	T_END;
}

T_HELPER_DECL(writer_helper, "Write asynchronously")
{
	close(shared.rd_fd);
	write_to_fd(NULL);
}

#pragma mark tests

#define WR_DECL_PROCESSES(desc_name, fd_pair, write_name, write_str, \
				write_mode, read_name, read_mode) \
		T_DECL(desc_name##_r##read_name##_w##write_name##_procs, "read changes to a " \
				#desc_name " with " #read_name " and writing " #write_str \
				" across two processes") \
		{ \
			drive_processes(fd_pair, read_mode, write_mode); \
		}
#define WR_DECL_THREADS(desc_name, fd_pair, write_name, write_str, \
				write_mode, read_name, read_mode) \
		T_DECL(desc_name##_r##read_name##_w##write_name##_thds, "read changes to a " \
				#desc_name " with " #read_name " and writing " #write_str) \
		{ \
			drive_threads(fd_pair, read_mode, write_mode); \
		}

#define WR_DECL(desc_name, fd_pair, write_name, write_str, write_mode, \
		read_name, read_mode) \
		WR_DECL_PROCESSES(desc_name, fd_pair, write_name, write_str, \
				write_mode, read_name, read_mode) \
		WR_DECL_THREADS(desc_name, fd_pair, write_name, write_str, \
				write_mode, read_name, read_mode)

#define RD_DECL_SAFE(desc_name, fd_pair, read_name, read_mode) \
		WR_DECL(desc_name, fd_pair, full, "the full string", FULL_WRITE, \
				read_name, read_mode) \
		WR_DECL(desc_name, fd_pair, inc, "incrementally", \
				INCREMENTAL_WRITE, read_name, read_mode)

#define RD_DECL_DISPATCH_ONLY(suffix, desc_name, fd_pair, read_name, \
				read_mode) \
		WR_DECL##suffix(desc_name, fd_pair, inc_dispatch, \
				"incrementally with a dispatch source", \
				DISPATCH_INCREMENTAL_WRITE, read_name, read_mode)
#define RD_DECL_WORKQ_ONLY(suffix, desc_name, fd_pair, read_name, \
				read_mode) \
		WR_DECL##suffix(desc_name, fd_pair, inc_workq, \
				"incrementally with the workqueue", \
				WORKQ_INCREMENTAL_WRITE, read_name, read_mode)

#define RD_DECL(desc_name, fd_pair, read_name, read_mode) \
		RD_DECL_SAFE(desc_name, fd_pair, read_name, read_mode) \
		RD_DECL_DISPATCH_ONLY(, desc_name, fd_pair, read_name, read_mode)
		// RD_DECL_WORKQ_ONLY(, desc_name, fd_pair, read_name, read_mode)

/*
 * dispatch_source tests cannot share the same process as other workqueue
 * tests.
 */
#define RD_DECL_DISPATCH(desc_name, fd_pair, read_name, read_mode) \
		RD_DECL_SAFE(desc_name, fd_pair, read_name, read_mode) \
		RD_DECL_DISPATCH_ONLY(, desc_name, fd_pair, read_name, read_mode) \
		RD_DECL_WORKQ_ONLY(_PROCESSES, desc_name, fd_pair, read_name, \
				read_mode)

/*
 * Workqueue tests cannot share the same process as other workqueue or
 * dispatch_source tests.
#define RD_DECL_WORKQ(desc_name, fd_pair, read_name, read_mode) \
		RD_DECL_SAFE(desc_name, fd_pair, read_name, read_mode) \
		RD_DECL_DISPATCH_ONLY(_PROCESSES, desc_name, fd_pair, read_name, \
				read_mode) \
		RD_DECL_WORKQ_ONLY(_PROCESSES, desc_name, fd_pair, read_name, \
				read_mode)
 */

#define PAIR_DECL(desc_name, fd_pair) \
	RD_DECL(desc_name, fd_pair, poll, POLL_READ) \
	RD_DECL(desc_name, fd_pair, select, SELECT_READ) \
	RD_DECL(desc_name, fd_pair, kevent, KEVENT_READ) \
	RD_DECL(desc_name, fd_pair, kevent64, KEVENT64_READ) \
	RD_DECL(desc_name, fd_pair, kevent_qos, KEVENT_QOS_READ) \
	RD_DECL_DISPATCH(desc_name, fd_pair, dispatch_source, DISPATCH_READ)
	// RD_DECL_WORKQ(desc_name, fd_pair, workq, WORKQ_READ)

PAIR_DECL(tty, PTY_PAIR)
PAIR_DECL(pipe, PIPE_PAIR)
PAIR_DECL(fifo, FIFO_PAIR)
PAIR_DECL(socket, SOCKET_PAIR)
