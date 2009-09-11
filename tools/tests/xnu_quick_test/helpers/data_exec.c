#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>

int test_func();
void	catch_segv(int);
jmp_buf resume;

#define func_len	256

#define ALT_STK_SIZE	(MINSIGSTKSZ + pagesize)

#if __i386__ || __ppc__
typedef	unsigned int		psint_t;
#endif
#if __x86_64__ || __ppc64__
typedef unsigned long long	psint_t;
#endif

int verbose = 0;

#define msg(...)	do { if (verbose) printf(__VA_ARGS__); } while (0);

/*
 * Test whether the architecture allows execution from the stack and heap data areas.  What's
 * allowed varies by architecture due to backwards compatibility.  We also run a separate test
 * where we turn on PROT_EXEC explicitly which should always allow execution to take place.
 *
 * The "expected" array tells us what the result of each test should be based on the architecture.
 * The code assumes the test numbers in the macros below are consecutive starting from 0.
 */

#define HEAP_TEST	0
#define HEAP_PROT_EXEC	1
#define STACK_TEST	2
#define STACK_PROT_EXEC	3

#define	SUCCEED	 1
#define FAIL	-1	/* can't use 0 since setjmp uses that */

int expected[4] = {
#if __i386__
	SUCCEED,		/* execute from heap */
	SUCCEED,		/* exeucte from heap with PROT_EXEC */
	FAIL,			/* execute from stack */
	SUCCEED,		/* exeucte from stack with PROT_EXEC */
#endif
#if __x86_64__
	FAIL,			/* execute from heap */
	SUCCEED,		/* exeucte from heap with PROT_EXEC */
	FAIL,			/* execute from stack */
	SUCCEED,		/* exeucte from stack with PROT_EXEC */
#endif
#if __ppc__
	SUCCEED,		/* execute from heap */
	SUCCEED,		/* exeucte from heap with PROT_EXEC */
	SUCCEED,		/* execute from stack */
	SUCCEED,		/* exeucte from stack with PROT_EXEC */
#endif
#if __ppc64__
	FAIL,			/* execute from heap */
	SUCCEED,		/* exeucte from heap with PROT_EXEC */
	FAIL,			/* execute from stack */
	SUCCEED,		/* exeucte from stack with PROT_EXEC */
#endif
};


main(int argc, char *argv[])
{
	int (*func)();
	int result, test;
	char buf[func_len + 4];
	psint_t base;
	unsigned int len;
	psint_t pagesize;
	size_t	count;
	stack_t sigstk;
	struct sigaction sigact;
	char *cmd_name;
	int c;

	cmd_name = argv[0];

	while ((c = getopt(argc, argv, "v")) != -1) {
		switch (c) {
		case 'v':
			verbose = 1;
			break;

		case '?':
		default:
			fprintf(stderr, "usage: data_exec [-v]\n");
			exit(1);
		}
	}

	pagesize = getpagesize();

	sigstk.ss_sp = malloc(ALT_STK_SIZE);
	sigstk.ss_size = ALT_STK_SIZE;
	sigstk.ss_flags = 0;

	if (sigaltstack(&sigstk, NULL) < 0) {
		perror("sigaltstack");
		exit(1);
	}

	sigact.sa_handler = catch_segv;
	sigact.sa_flags = SA_ONSTACK;
	sigemptyset(&sigact.sa_mask);

	if (sigaction(SIGSEGV, &sigact, NULL) == -1) {
		perror("sigaction SIGSEGV");
		exit(1);
	}

        if (sigaction(SIGBUS, &sigact, NULL) == -1) {
                perror("sigaction SIGBUS");
                exit(1);
        }

	test = HEAP_TEST;

restart:

	if ((result = setjmp(resume)) != 0) {
		if (result != expected[test]) {
			printf("%s: test %d failed, expected %d, got %d\n", cmd_name, test, expected[test], result);
			exit(2);
		}

		test++;
		goto restart;
	}

	switch (test) {
	case HEAP_TEST:
		msg("attempting to execute from malloc'ed area..\n");

		func = (void *)malloc(func_len);
	
		func = (void *)((char *)func + ((psint_t)test_func & 0x3));
	
		bcopy(test_func, func, func_len);
	
		result = (*func)();
		msg("execution suceeded, result is %d\n\n", result);
		longjmp(resume, SUCCEED);

	case HEAP_PROT_EXEC:
		msg("attempting to execute from malloc'ed area with PROT_EXEC..\n");

		func = (void *)malloc(func_len);
	
		func = (void *)((char *)func + ((psint_t)test_func & 0x3));
		bcopy(test_func, func, func_len);

		base = (psint_t)func & ~(pagesize - 1);
		len  = func_len + (psint_t)func - base;

		if(mprotect((void *)base, len, PROT_READ|PROT_WRITE|PROT_EXEC) == -1) {
			perror("mprotect of stack");
			exit(1);
		}

		result = (*func)();
		msg("execution suceeded, result is %d\n\n", result);
		longjmp(resume, SUCCEED);

	case STACK_TEST:
		msg("attempting to execute from stack...\n");

		func = (void *)(buf + ((psint_t)test_func & 0x3));
		bcopy(test_func, func, func_len);
	
		result = (*func)();
		msg("stack execution suceeded, result from stack exec is %d\n\n", result);
		longjmp(resume, SUCCEED);

	case STACK_PROT_EXEC:
		msg("attempting to execute from stack with PROT_EXEC...\n");

		func = (void *)(buf + ((psint_t)test_func & 0x3));
		bcopy(test_func, func, func_len);
	
		base = (psint_t)func & ~(pagesize - 1);
		len  = func_len + (psint_t)func - base;
	
		if(mprotect((void *)base, len, PROT_READ|PROT_WRITE|PROT_EXEC) == -1) {
			perror("mprotect of stack");
			exit(1);
		}
	
		result = (*func)();
		msg("stack execution suceeded, result from stack exec is %d\n", result);
		longjmp(resume, SUCCEED);
	}

	msg("All tests passed.\n");
	exit(0);
}


int
test_func()
{
	return 42;
}


void 
catch_segv(int sig)
{
	msg("got sig %d\n\n", sig);
	longjmp(resume, FAIL);
}
