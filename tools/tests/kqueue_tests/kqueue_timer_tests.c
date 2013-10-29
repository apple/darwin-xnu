#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int kq, passed, failed;

/*
 * Wait for given kevent, which should return in 'expected' usecs.
 */
int
do_simple_kevent(struct kevent64_s *kev, uint64_t expected)
{
	int ret;
	uint64_t elapsed_usecs, delta_usecs;
	struct timespec timeout;
	struct timeval before, after;

	/* time out after 1 sec extra delay */
	timeout.tv_sec = (expected / (1000 * 1000)) + 1; 
	timeout.tv_nsec = (expected % (1000 * 1000)) * 1000;

	/* measure time for the kevent */
	gettimeofday(&before, NULL);
	ret = kevent64(kq, kev, 1, kev, 1, 0, &timeout);
	gettimeofday(&after, NULL);

	if (ret < 1 || (kev->flags & EV_ERROR)) {
		printf("\tfailure: kevent returned %d, error %d\n", ret, 
				(ret == -1 ? errno : (int) kev->data));
		return 0;
	}

	/* did it work? */
	elapsed_usecs = (after.tv_sec - before.tv_sec) * (1000 * 1000) + 
		(after.tv_usec - before.tv_usec);
	delta_usecs = abs(elapsed_usecs - (expected));

	/* failure if we're 30% off, or 50 mics late */
	if (delta_usecs > (30 * expected / 100.0) && delta_usecs > 50) {
		printf("\tfailure: expected %lld usec, measured %lld usec.\n", 
				expected, elapsed_usecs);
		return 0;
	} else {
		printf("\tsuccess.\n");
		return 1;
	}
}

void
test_absolute_kevent(int time, int scale)
{
	struct timeval tv;
	struct kevent64_s kev;
	uint64_t nowus, expected, deadline;
	int ret;
	int timescale = 0;

	gettimeofday(&tv, NULL);
	nowus = tv.tv_sec * (1000 * 1000LL) + tv.tv_usec;

	switch (scale) {
	case NOTE_SECONDS:
		printf("Testing %d sec absolute timer...\n", time);
		timescale = 1000 * 1000;
		break;
	case NOTE_USECONDS:
		printf("Testing %d usec absolute timer...\n", time);
		timescale = 1;
		break;
	case 0:
		printf("Testing %d msec absolute timer...\n", time);
		timescale = 1000;
		break;
	default:
		printf("Failure: scale 0x%x not recognized.\n", scale);
		return;
	}

	expected = time * timescale;
	deadline = nowus / timescale + time;

	/* deadlines in the past should fire immediately */
	if (time < 0)
		expected = 0;
	
	EV_SET64(&kev, 1, EVFILT_TIMER, EV_ADD, 
			NOTE_ABSOLUTE | scale, deadline, 0,0,0);
	ret = do_simple_kevent(&kev, expected);

	if (ret)
		passed++;
	else
		failed++;
}

void
test_oneshot_kevent(int time, int scale)
{
	int ret;
	uint64_t expected = 0;
	struct kevent64_s kev;

	switch (scale) {
	case NOTE_SECONDS:
		printf("Testing %d sec interval timer...\n", time);
		expected = time * (1000 * 1000);
		break;
	case NOTE_USECONDS:
		printf("Testing %d usec interval timer...\n", time);
		expected = time;
		break;
	case NOTE_NSECONDS:
		printf("Testing %d nsec interval timer...\n", time);
		expected = time / 1000;
		break;
	case 0:
		printf("Testing %d msec interval timer...\n", time);
		expected = time * 1000;
		break;
	default:
		printf("Failure: scale 0x%x not recognized.\n", scale);
		return;
	}

	/* deadlines in the past should fire immediately */
	if (time < 0)
		expected = 0;
	
	EV_SET64(&kev, 2, EVFILT_TIMER, EV_ADD | EV_ONESHOT, scale, time, 
			0, 0, 0);
	ret = do_simple_kevent(&kev, expected);

	if (ret)
		passed++;
	else
		failed++;

}

void
test_repeating_kevent(int usec)
{
	struct kevent64_s kev;
	int expected_pops, ret;

	expected_pops = 1000 * 1000 / usec;
	printf("Testing repeating kevent for %d pops in a second...\n", 
		expected_pops);

	EV_SET64(&kev, 3, EVFILT_TIMER, EV_ADD, NOTE_USECONDS, usec, 0, 0, 0);
	ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
	if (ret != 0) {
		printf("\tfailure: kevent64 returned %d\n", ret);
		failed++;
		return;
	}

	/* sleep 1 second */
	usleep(1000 * 1000);
	ret = kevent64(kq, NULL, 0, &kev, 1, 0, NULL);
	if (ret != 1 || (kev.flags & EV_ERROR)) {
		printf("\tfailure: kevent64 returned %d\n", ret);
		failed++;
		return;
	}

	/* check how many times the timer fired: within 5%? */
	if (kev.data > expected_pops + (expected_pops / 20) ||
		kev.data < expected_pops - (expected_pops / 20)) {
		printf("\tfailure: saw %lld pops.\n", kev.data);
		failed++;
	} else {
		printf("\tsuccess: saw %lld pops.\n", kev.data);
		passed++;
	}

	EV_SET64(&kev, 3, EVFILT_TIMER, EV_DELETE, 0, 0, 0, 0, 0);
	ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL);
	if (ret != 0) {
		printf("\tfailed to stop repeating timer: %d\n", ret);
	}
}

void
test_updated_kevent(int first, int second)
{
	struct kevent64_s kev;
	int ret;

	printf("Testing update from %d to %d msecs...\n", first, second);

	EV_SET64(&kev, 4, EVFILT_TIMER, EV_ADD|EV_ONESHOT, 0, first, 0, 0, 0);
	ret = kevent64(kq, &kev, 1, NULL, 0, 0, NULL); 
	if (ret != 0) {
		printf("\tfailure: initial kevent returned %d\n", ret);
		failed++;
		return;
	}

	EV_SET64(&kev, 4, EVFILT_TIMER, EV_ONESHOT, 0, second, 0, 0, 0);
	if (second < 0)
		second = 0;	
	ret = do_simple_kevent(&kev, second * 1000);
	if (ret)
		passed++;
	else
		failed++;
}

int
main(void)
{
	struct timeval tv;
	struct kevent64_s kev;
	uint64_t nowms, deadline;

	kq = kqueue();
	assert(kq > 0);
	passed = 0;
	failed = 0;

	test_absolute_kevent(100, 0);
	test_absolute_kevent(200, 0);
	test_absolute_kevent(300, 0);
	test_absolute_kevent(1000, 0);
	test_absolute_kevent(500, NOTE_USECONDS);
	test_absolute_kevent(100, NOTE_USECONDS);
	test_absolute_kevent(5, NOTE_SECONDS);
	test_absolute_kevent(-1000, 0);

	test_oneshot_kevent(1, NOTE_SECONDS);
	test_oneshot_kevent(10, 0);
	test_oneshot_kevent(200, NOTE_USECONDS);
	test_oneshot_kevent(300000, NOTE_NSECONDS);
	test_oneshot_kevent(-1, NOTE_SECONDS);

	test_repeating_kevent(100 * 1000);
	test_repeating_kevent(5 * 1000);
	test_repeating_kevent(200);
	test_repeating_kevent(50);
	test_repeating_kevent(10);

	test_updated_kevent(1000, 2000);
	test_updated_kevent(2000, 1000);
	test_updated_kevent(1000, -1);

	printf("\nFinished: %d tests passed, %d failed.\n", passed, failed);

	exit(EXIT_SUCCESS);
}
