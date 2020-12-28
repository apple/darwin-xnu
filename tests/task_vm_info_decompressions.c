#include <stdlib.h>
#include <stdio.h>
#include <mach/task_info.h>
#include <mach/mach.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/kern_memorystatus.h>
#include <sys/sysctl.h>
#include <stdatomic.h>

#include <darwintest.h>
#include <TargetConditionals.h>

#define KB 1024
#define MALLOC_SIZE_PER_THREAD (64 * KB)
#define freezer_path "/usr/local/bin/freeze"

/* BridgeOS could spend more time execv freezer */
#if TARGET_OS_BRIDGE
static int timeout = 600;
#else
static int timeout = 120;
#endif

static _Atomic int thread_malloc_count = 0;
static _Atomic int thread_thawed_count = 0;
static _Atomic int phase = 0;

struct thread_args {
	int    id;
};

static void
freeze_pid(pid_t pid)
{
	char pid_str[6];
	char *args[3];
	pid_t child_pid;
	int status;

	sprintf(pid_str, "%d", pid);
	child_pid = fork();
	if (child_pid == 0) {
		/* Launch freezer */
		args[0] = freezer_path;
		args[1] = pid_str;
		args[2] = NULL;
		execv(freezer_path, args);
		/* execve() does not return on success */
		perror("execve");
		T_FAIL("execve() failed");
	}

	/* Wait for freezer to complete */
	T_LOG("Waiting for freezer %d to complete", child_pid);
	while (0 == waitpid(child_pid, &status, WNOHANG)) {
		if (timeout < 0) {
			kill(child_pid, SIGKILL);
			T_FAIL("Freezer took too long to freeze the test");
		}
		sleep(1);
		timeout--;
	}
	if (WIFEXITED(status) != 1 || WEXITSTATUS(status) != 0) {
		T_FAIL("Freezer error'd out");
	}
}
static void *
worker_thread_function(void *args)
{
	struct thread_args *targs = args;
	int thread_id = targs->id;
	char *array;

	/* Allocate memory */
	array = malloc(MALLOC_SIZE_PER_THREAD);
	T_EXPECT_NOTNULL(array, "thread %d allocated heap memory to be dirtied", thread_id);

	/* Waiting for phase 1 (touch pages) to start */
	while (atomic_load(&phase) != 1) {
		;
	}

	/* Phase 1: touch pages */
	T_LOG("thread %d phase 1: dirtying %d heap pages (%d bytes)", thread_id, MALLOC_SIZE_PER_THREAD / (int)PAGE_SIZE, MALLOC_SIZE_PER_THREAD);
	memset(&array[0], 1, MALLOC_SIZE_PER_THREAD);
	atomic_fetch_add(&thread_malloc_count, 1);

	/* Wait for process to be frozen */
	while (atomic_load(&phase) != 2) {
		;
	}

	/* Phase 2, process thawed, trigger decompressions by re-faulting pages */
	T_LOG("thread %d phase 2: faulting pages back in to trigger decompressions", thread_id);
	memset(&array[0], 1, MALLOC_SIZE_PER_THREAD);

	/* Main thread will retrieve vm statistics once all threads are thawed */
	atomic_fetch_add(&thread_thawed_count, 1);

	free(array);


#if 0 /* Test if the thread's decompressions counter was added to the task decompressions counter when a thread terminates */
	if (thread_id < 2) {
		sleep(10);
	}
#endif

	return NULL;
}

static pthread_t*
create_threads(int nthreads, pthread_t *threads, struct thread_args *targs)
{
	int i;
	int err;
	pthread_attr_t attr;

	err = pthread_attr_init(&attr);
	T_ASSERT_POSIX_ZERO(err, "pthread_attr_init");
	for (i = 0; i < nthreads; i++) {
		targs[i].id = i;
		err = pthread_create(&threads[i], &attr, worker_thread_function, (void*)&targs[i]);
		T_QUIET; T_ASSERT_POSIX_ZERO(err, "pthread_create");
	}

	return threads;
}

static void
join_threads(int nthreads, pthread_t *threads)
{
	int i;
	int err;

	for (i = 0; i < nthreads; i++) {
		err = pthread_join(threads[i], NULL);
		T_QUIET; T_ASSERT_POSIX_ZERO(err, "pthread_join");
	}
}

T_DECL(task_vm_info_decompressions,
    "Test multithreaded per-task decompressions counter")
{
	int     err;
	int     ncpu;
	size_t  ncpu_size = sizeof(ncpu);
	int     npages;
	int     compressor_mode;
	size_t  compressor_mode_size = sizeof(compressor_mode);
	task_vm_info_data_t vm_info;
	mach_msg_type_number_t count;
	pthread_t *threads;
	struct thread_args *targs;

	T_SETUPBEGIN;

	/* Make sure freezer is enabled on target machine */
	err = sysctlbyname("vm.compressor_mode", &compressor_mode, &compressor_mode_size, NULL, 0);
	if (compressor_mode < 8) {
		T_SKIP("This test requires freezer which is not available on the testing platform (vm.compressor_mode is set to %d)", compressor_mode);
	}
#if TARGET_OS_BRIDGE
	T_SKIP("This test requires freezer which is not available on bridgeOS (vm.compressor_mode is set to %d)", compressor_mode);
#endif

	/* Set number of threads to ncpu available on testing device */
	err = sysctlbyname("hw.ncpu", &ncpu, &ncpu_size, NULL, 0);
	T_EXPECT_EQ_INT(0, err, "Detected %d cpus\n", ncpu);

	/* Set total number of pages to be frozen */
	npages = ncpu * MALLOC_SIZE_PER_THREAD / (int)PAGE_SIZE;
	T_LOG("Test will be freezing at least %d heap pages\n", npages);

	/* Change state to freezable */
	err = memorystatus_control(MEMORYSTATUS_CMD_SET_PROCESS_IS_FREEZABLE, getpid(), (uint32_t)1, NULL, 0);
	T_EXPECT_EQ(KERN_SUCCESS, err, "set pid %d to be freezable", getpid());

	/* Call into kernel to retrieve vm_info and make sure we do not have any decompressions before the test */
	count = TASK_VM_INFO_COUNT;
	err = task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&vm_info, &count);
	T_EXPECT_EQ(count, TASK_VM_INFO_COUNT, "count == TASK_VM_INFO_COUNT: %d", count);
	T_EXPECT_EQ_INT(0, err, "task_info(TASK_VM_INFO) returned 0");
	T_EXPECT_EQ_INT(0, vm_info.decompressions, "Expected 0 decompressions before test starts");

	/* Thread data */
	threads = malloc(sizeof(pthread_t) * (size_t)ncpu);
	targs = malloc(sizeof(struct thread_args) * (size_t)ncpu);

	T_SETUPEND;

	/* Phase 1: create threads to write to malloc memory */
	create_threads(ncpu, threads, targs);
	atomic_fetch_add(&phase, 1);

	/* Wait for all threads to dirty their malloc pages */
	while (atomic_load(&thread_malloc_count) != ncpu) {
		sleep(1);
	}
	T_EXPECT_EQ(ncpu, atomic_load(&thread_malloc_count), "%d threads finished writing to malloc pages\n", ncpu);

	/* Launch freezer to compress the dirty pages */
	T_LOG("Running freezer to compress pages for pid %d", getpid());
	freeze_pid(getpid());

	/* Phase 2: triger decompression in threads */
	atomic_fetch_add(&phase, 1);

	/* Wait for all threads to decompress their malloc pages */
	while (atomic_load(&thread_thawed_count) != ncpu) {
		sleep(1);
	}

	/* Phase 3: Call into kernel to retrieve vm_info and to get the updated decompressions counter */
	count = TASK_VM_INFO_COUNT;
	err = task_info(mach_task_self(), TASK_VM_INFO, (task_info_t)&vm_info, &count);
	T_EXPECT_EQ(count, TASK_VM_INFO_COUNT, "count == TASK_VM_INFO_COUNT: %d", count);
	T_EXPECT_EQ(0, err, "task_info(TASK_VM_INFO) returned 0");

	/* Make sure this task has decompressed at least all of the dirtied memory */
	T_EXPECT_GE_INT(vm_info.decompressions, npages, "decompressed %d pages (>= heap pages: %d)", vm_info.decompressions, npages);
	T_PASS("Correctly retrieve per-task decompressions stats");

	/* Cleanup */
	join_threads(ncpu, threads);
	free(threads);
	free(targs);
}
