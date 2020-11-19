#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <darwintest.h>

static uint64_t stack_base, stack_end;

static void
signal_handler(int  __unused signum, struct __siginfo * __unused info, void * __unused uap)
{
	T_LOG("In signal handler\n");
	uint64_t signal_stack = (uint64_t)__builtin_frame_address(0);
	T_ASSERT_LE(stack_base, signal_stack, NULL);
	T_ASSERT_LE(signal_stack, stack_end, NULL);
	T_END;
}

T_DECL(signalstack, "Check that the signal stack is set up correctly", T_META_ASROOT(YES))
{
	void* stack_allocation = malloc(SIGSTKSZ);

	stack_base = (uint64_t)stack_allocation;
	stack_end = stack_base + SIGSTKSZ;

	T_LOG("stack base = 0x%llx\n", stack_base);
	T_LOG("stack end = 0x%llx\n", stack_end);

	stack_t alt_stack;
	alt_stack.ss_sp = stack_allocation;
	alt_stack.ss_size = SIGSTKSZ;
	alt_stack.ss_flags = 0;

	if (sigaltstack(&alt_stack, NULL) < 0) {
		T_FAIL("error: sigaltstack failed\n");
	}

	sigset_t signal_mask;
	sigemptyset(&signal_mask);

	struct sigaction sig_action;
	sig_action.sa_sigaction = signal_handler;
	sig_action.sa_mask = signal_mask;
	sig_action.sa_flags = SA_ONSTACK;

	if (sigaction(SIGUSR1, &sig_action, NULL) != 0) {
		T_FAIL("error: sigaction failed\n");
	}

	T_LOG("Sending a SIGUSR1\n");
	kill(getpid(), SIGUSR1);

	return;
}
