#include <darwintest.h>
#include <darwintest_utils.h>
#include <mach/mach.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>

#define ITER 100

T_DECL(ltable_exhaustion_test,
	"check if allocating not used ltable entries can panic the system",
	T_META_ASROOT(true))
{
	int n_ltable_entries,n_ltable_entries_after;
	size_t len = sizeof(int);
	int i;
	mach_port_name_t portset;

	/*
	 * Get how many ltable entries are allocated right now.
	 */
	T_EXPECT_POSIX_SUCCESS(sysctlbyname("kern.n_ltable_entries", &n_ltable_entries, &len, NULL, 0), "kern.n_ltable_entries");

	for (i = 0; i < ITER; i++) {
		mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &portset);
	}

	/*
	 * Get how many ltable entries are allocated after the loop. Other processes in the system might have allocated entries,
	 * so don't expect the same value.
	 */
	T_EXPECT_POSIX_SUCCESS(sysctlbyname("kern.n_ltable_entries", &n_ltable_entries_after, &len, NULL, 0), "kern.n_ltable_entries");

	T_EXPECT_LE(n_ltable_entries_after, n_ltable_entries+ITER, "ltable before %d after %d iter %d", n_ltable_entries, n_ltable_entries_after, ITER);
}
