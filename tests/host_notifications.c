#include <sys/time.h>
#include <mach/mach.h>
#include <mach/mach_host.h>

#include <darwintest.h>

static void do_test(int notify_type, void (^trigger_block)(void)){
	mach_port_t port;
	T_ASSERT_MACH_SUCCESS(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port), NULL);

	T_ASSERT_MACH_SUCCESS(host_request_notification(mach_host_self(), notify_type, port), NULL);

	trigger_block();

	struct {
		mach_msg_header_t hdr;
		mach_msg_trailer_t trailer;
	} message = { .hdr = {
		.msgh_bits = 0,
		.msgh_size = sizeof(mach_msg_header_t),
		.msgh_remote_port = MACH_PORT_NULL,
		.msgh_local_port = port,
		.msgh_voucher_port = MACH_PORT_NULL,
		.msgh_id = 0,
	}};

	T_ASSERT_EQ(MACH_RCV_TOO_LARGE, mach_msg_receive(&message.hdr), NULL);
	mach_msg_destroy(&message.hdr);
}

T_DECL(host_notify_calendar_change, "host_request_notification(HOST_NOTIFY_CALENDAR_CHANGE)", T_META_CHECK_LEAKS(false), T_META_LTEPHASE(LTE_POSTINIT))
{
	do_test(HOST_NOTIFY_CALENDAR_CHANGE, ^{
		struct timeval tm;
		if (gettimeofday(&tm, NULL) != 0 || settimeofday(&tm, NULL) != 0){
			T_SKIP("Unable to settimeofday()");
		}
	});
}

T_DECL(host_notify_calendar_set, "host_request_notification(HOST_NOTIFY_CALENDAR_SET)", T_META_CHECK_LEAKS(false), T_META_LTEPHASE(LTE_POSTINIT))
{
	do_test(HOST_NOTIFY_CALENDAR_SET, ^{
		struct timeval tm;
		if (gettimeofday(&tm, NULL) != 0 || settimeofday(&tm, NULL) != 0){
			T_SKIP("Unable to settimeofday()");
		}
	});
}
