#include <unistd.h>
#include <errno.h>
#include <sys/event.h>
#include <darwintest.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

/* <rdar://problem/28139044> EVFILT_USER doesn't properly support add&fire atomic combination
 *
 * Chek that using EV_ADD and EV_TRIGGER on a EV_USER actually trigger the event just added.
 *
 */

T_DECL(kqueue_add_and_trigger_evfilt_user, "Add and trigger EVFILT_USER events with kevent ")
{
	int kq_fd, ret;
	struct kevent ret_kev;
	const struct kevent kev = {
		.ident = 1,
		.filter = EVFILT_USER,
		.flags = EV_ADD | EV_CLEAR,
		.fflags = NOTE_TRIGGER,
	};
	const struct timespec timeout = {
		.tv_sec = 1,
		.tv_nsec = 0,
	};

	T_ASSERT_POSIX_SUCCESS((kq_fd = kqueue()), NULL);
	ret = kevent(kq_fd, &kev, 1, &ret_kev, 1, &timeout);

	T_ASSERT_POSIX_SUCCESS(ret, "kevent");

	T_ASSERT_EQ(ret, 1, "kevent with add and trigger, ret");
	T_ASSERT_EQ(ret_kev.ident, 1, "kevent with add and trigger, ident");
	T_ASSERT_EQ(ret_kev.filter, EVFILT_USER, "kevent with add and trigger, filter");
}
