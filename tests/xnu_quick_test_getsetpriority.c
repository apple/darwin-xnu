#include <darwintest.h>

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.quicktest"), T_META_CHECK_LEAKS(false));

T_DECL(getpriority_setpriority, "Tests getpriority and setpriority system calls", T_META_ASROOT(true))
{
	int my_priority;
	int my_new_priority;

	/* getpriority returns scheduling priority so -1 is a valid value */
	errno       = 0;
	my_priority = getpriority(PRIO_PROCESS, 0);

	T_WITH_ERRNO;
	T_ASSERT_FALSE(my_priority == -1 && errno != 0, "Verify getpriority is successful", NULL);

	/* change scheduling priority*/
	my_new_priority = (my_priority == PRIO_MIN) ? (my_priority + 10) : (PRIO_MIN);

	T_WITH_ERRNO;
	T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_PROCESS, 0, my_new_priority), "Change scheduling priority", NULL);

	/* verify change */
	errno       = 0;
	my_priority = getpriority(PRIO_PROCESS, 0);
	T_WITH_ERRNO;
	T_ASSERT_FALSE(my_priority == -1 && errno != 0, "Verify getpriority change is successful", NULL);

	T_WITH_ERRNO;
	T_ASSERT_EQ(my_priority, my_new_priority, "Verify setpriority correctly set scheduling priority", NULL);

	/* reset scheduling priority */
	T_WITH_ERRNO;
	T_ASSERT_POSIX_SUCCESS(setpriority(PRIO_PROCESS, 0, 0), "Reset scheduling priority", NULL);
}
