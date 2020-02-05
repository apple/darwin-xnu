#include <mach/task.h>
#include <mach/mach.h>
#include <kern/restartable.h>
#include <stdbool.h>
#include <darwintest.h>
#include <pthread.h>
#include <unistd.h>
#include <signal.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

extern task_restartable_range_t range;
extern void restartable_function(int *);
static int step = 0;

#if defined(__x86_64__)
__asm__("    .align 4\n"
		"    .text\n"
		"    .private_extern _restartable_function\n"
		"_restartable_function:\n"
		// this should use $arg1 but I don't know intel calling conventions
		// so the argument to restartable_function() is actually ignored
		// as we know what it is anyway, and Intel PC-relative addressing,
		// unlike ARM, is pretty readable
		"    incl _step(%rip)\n"
		"1:\n"
		"    pause\n"
		"    jmp 1b\n"
		"LExit_restartable_function:\n"
		"    ret\n");
#elif defined(__arm64__)
__asm__("    .align 4\n"
		"    .text\n"
		"    .private_extern _restartable_function\n"
		"_restartable_function:\n"
		"    ldr    x11, [x0]\n"
		"    add    x11, x11, #1\n"
		"    str    x11, [x0]\n"
		"1:\n"
		"    b 1b\n"
		"LExit_restartable_function:\n"
		"    ret\n");
#elif defined(__arm__)
__asm__("    .align 4\n"
		"    .text\n"
		"    .thumb\n"
		"    .private_extern _restartable_function\n"
		"    .thumb_func\n"
		"_restartable_function:\n"
		"0:\n"
		"    ldr    r12, [r0]\n"
		"    add    r12, r12, #1\n"
		"    str    r12, [r0]\n"
		"1:\n"
		"    b 1b\n"
		"LExit_restartable_function:\n"
		"    bx lr\n");
#elif defined(__i386__)
#define SKIP_TEST 1
#else
#error Architecture unsupported
#endif

#ifndef SKIP_TEST
__asm__("    .align 4\n"
		"    .data\n"
		"    .private_extern _range\n"
		"_range:\n"
#if __LP64__
		"    .quad _restartable_function\n"
#else
		"    .long _restartable_function\n"
		"    .long 0\n"
#endif
		"    .short LExit_restartable_function - _restartable_function\n"
		"    .short LExit_restartable_function - _restartable_function\n"
		"    .long 0\n");
#endif

static void
noop_signal(int signo __unused)
{
}

static void *
task_restartable_ranges_thread(void *_ctx)
{
	int *stepp = _ctx;
	restartable_function(stepp); // increments step
	T_PASS("was successfully restarted\n");
	(*stepp)++;
	return NULL;
}

static void
wait_for_step(int which)
{
	for (int i = 0; step != which && i < 10; i++) {
		usleep(100000);
	}
}

T_DECL(task_restartable_ranges, "test task_restartable_ranges")
{
#ifdef SKIP_TEST
	T_SKIP("Not supported");
#else
	kern_return_t kr;
	pthread_t th;
	int rc;

	signal(SIGUSR1, noop_signal);

	kr = task_restartable_ranges_register(mach_task_self(), &range, 1);
	T_ASSERT_MACH_SUCCESS(kr, "task_restartable_ranges_register");

	{
		rc = pthread_create(&th, NULL, &task_restartable_ranges_thread, &step);
		T_ASSERT_POSIX_SUCCESS(rc, "pthread_create");

		wait_for_step(1);
		T_ASSERT_EQ(step, 1, "The thread started (sync)");

		kr = task_restartable_ranges_synchronize(mach_task_self());
		T_ASSERT_MACH_SUCCESS(kr, "task_restartable_ranges_synchronize");

		T_LOG("wait for the function to be restarted (sync)");
		wait_for_step(2);
		T_ASSERT_EQ(step, 2, "The thread exited (sync)");
		pthread_join(th, NULL);
	}

	{
		rc = pthread_create(&th, NULL, &task_restartable_ranges_thread, &step);
		T_ASSERT_POSIX_SUCCESS(rc, "pthread_create");

		wait_for_step(3);
		T_ASSERT_EQ(step, 3, "The thread started (signal)");

		rc = pthread_kill(th, SIGUSR1);
		T_ASSERT_POSIX_SUCCESS(rc, "pthread_kill");

		T_LOG("wait for the function to be restarted (signal)");
		wait_for_step(4);
		T_ASSERT_EQ(step, 4, "The thread exited (signal)");
		pthread_join(th, NULL);
	}
#endif
}
