#define PRIVATE
#include <System/sys/kdebug.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <dispatch/dispatch.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libproc.h>
#include <libgen.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/policy.h>
#include <mach/vm_param.h>
#include <os/assumes.h>
#include <os/overflow.h>
#include <pthread.h>
#include <pthread/qos_private.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/mman.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <unistd.h>
#undef PRIVATE

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

#define ACT_CHANGE_UID 1
#define ACT_CHANGE_RUID 2
#define ACT_EXIT 127

#define ACT_PHASE2 2
#define ACT_PHASE3 3
#define ACT_PHASE4 4
#define ACT_PHASE5 5

#define PIPE_IN 0
#define PIPE_OUT 1

#define CONF_THREAD_NAME "test_child_thread"
#define CONF_CMD_NAME getprogname()
#define CONF_PROC_COUNT 20
#define CONF_BLK_SIZE 4096
#define CONF_UID_VAL 999U
#define CONF_RUID_VAL 998U
#define CONF_GID_VAL 997U
#define CONF_NICE_VAL 5
#define CONF_NUM_THREADS 2

#define BASEPRI_DEFAULT 31
#define MAXPRI_USER 63

#define CONF_OPN_FILE_COUNT 3
#define CONF_TMP_FILE_PFX   "/tmp/xnu.tests.proc_info."
static int
CONF_TMP_FILE_OPEN(char path[PATH_MAX])
{
	static char stmp_path[PATH_MAX] = {};
	char *nm;
	if (path) {
		nm = path;
	} else {
		nm = stmp_path;
	}
	strlcpy(nm, CONF_TMP_FILE_PFX "XXXXXXXXXX", PATH_MAX);
	int fd = mkstemp(nm);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(fd, "mkstemp(" CONF_TMP_FILE_PFX "XXXXXXXXXX)");
	return fd;
}

uint32_t get_tty_dev(void);

#define WAIT_FOR_CHILDREN(pipefd, action, child_count)                           \
	do {                                                                         \
	        long ret;                                                                \
	        if (child_count == 1) {                                                  \
	                int child_ret_action = 999;                                          \
	                while (child_ret_action != action) {                                 \
	                        ret = read(pipefd, &child_ret_action, sizeof(child_ret_action)); \
	                }                                                                    \
	        } else {                                                                 \
	                int child_ready_count = child_count * (int)sizeof(action);           \
                                                                                 \
	                action = 0;                                                          \
	                while (child_ready_count) {                                          \
	                        ret = read(pipefd, &action, (int)sizeof(action));                \
	                        if (ret != -1) {                                                 \
	                                child_ready_count -= ret;                                    \
	                        } else {                                                         \
	                                T_FAIL("ERROR: Could not read from pipe() : %d", errno);     \
	                        }                                                                \
	                        if (action) {                                                    \
	                                T_FAIL("ERROR: Child action failed with error %d", action);  \
	                        }                                                                \
	                }                                                                    \
	        }                                                                        \
	} while (0)

#define PROC_INFO_CALL(struct_name, pid, flavor, proc_arg)                                                     \
	do {                                                                                                       \
	        struct struct_name * struct_var = malloc(sizeof(struct struct_name));                                  \
	        T_QUIET;                                                                                               \
	        T_ASSERT_NOTNULL(struct_var, "malloc() for " #flavor);                                                 \
	        retval = __proc_info(PROC_INFO_CALL_PIDINFO, pid, flavor, (uint64_t)proc_arg, (user_addr_t)struct_var, \
	                             (uint32_t)sizeof(struct struct_name));                                            \
                                                                                                               \
	        T_QUIET;                                                                                               \
	        T_EXPECT_POSIX_SUCCESS(retval, "__proc_info call for " #flavor);                                       \
	        T_ASSERT_EQ_INT(retval, (int)sizeof(struct struct_name), "__proc_info call for " #flavor);             \
	        ret_structs[i] = (void *)struct_var;                                                                   \
	        i++;                                                                                                   \
	} while (0)

uint32_t
get_tty_dev()
{
	struct stat buf;
	stat(ttyname(1), &buf);
	return (uint32_t)buf.st_rdev;
}

/*
 * Defined in libsyscall/wrappers/libproc/libproc.c
 * For API test only. For normal use, please use the libproc API instead.
 * DO NOT COPY
 */
extern int __proc_info(int32_t callnum, int32_t pid, uint32_t flavor, uint64_t arg, user_addr_t buffer, int32_t buffersize);
struct proc_config_s {
	int parent_pipe[2];
	int child_count;
	pid_t proc_grp_id;
	int child_pipe[CONF_PROC_COUNT][2];
	int child_pids[CONF_PROC_COUNT];
	void * cow_map; /* memory for cow test */
};
typedef struct proc_config_s * proc_config_t;

typedef void (^child_action_handler_t)(proc_config_t proc_config, int child_id);

enum proc_info_opt {
	P_UNIQIDINFO    = 0x01,
	C_UNIQIDINFO    = 0x02,
	PBSD_OLD        = 0x04,
	PBSD            = 0x08,
	PBSD_SHORT      = 0x10,
	PBSD_UNIQID     = 0x20,
	P_TASK_INFO     = 0x40,
	P_TASK_INFO_NEW = 0x80,
	PALL            = 0x100,
	THREAD_ADDR     = 0x200,
	PTHINFO_OLD     = 0x400,
	PTHINFO         = 0x800,
	PTHINFO_64      = 0x1000,
	PINFO_PATH      = 0x2000,
	PAI             = 0x4000,
	PREGINFO        = 0x8000,
	PREGINFO_PATH   = 0x10000,
	PREGINFO_PATH_2 = 0x20000,
	PREGINFO_PATH_3 = 0x40000,
	PVNINFO         = 0x80000
};

static int tmp_fd = -1;

static child_action_handler_t proc_info_listpids_handler = ^void (proc_config_t proc_config, int child_id) {
	close(proc_config->parent_pipe[PIPE_IN]);
	close(proc_config->child_pipe[child_id][PIPE_OUT]);
	long retval      = 0;
	int child_action = 0;
	retval           = write(proc_config->parent_pipe[PIPE_OUT], &child_action, sizeof(child_action));
	if (retval != -1) {
		while (child_action != ACT_EXIT) {
			retval = read(proc_config->child_pipe[child_id][PIPE_IN], &child_action, sizeof(child_action));
			if (retval == 0 || (retval == -1 && errno == EAGAIN)) {
				continue;
			}
			if (retval != -1) {
				switch (child_action) {
				case ACT_CHANGE_UID:
					/*
					 * Change uid
					 */
					retval = setuid(CONF_UID_VAL);
					break;
				case ACT_CHANGE_RUID:
					/*
					 * Change ruid
					 */
					retval = setreuid(CONF_RUID_VAL, (uid_t)-1);
					break;
				case ACT_EXIT:
					/*
					 * Exit
					 */
					break;
				}
			}
			if (child_action != ACT_EXIT) {
				retval = write(proc_config->parent_pipe[PIPE_OUT], &retval, sizeof(retval));
				if (retval == -1) {
					break;
				}
			}
		}
	}
	close(proc_config->parent_pipe[PIPE_OUT]);
	close(proc_config->child_pipe[child_id][PIPE_IN]);
	exit(0);
};

static child_action_handler_t proc_info_call_pidinfo_handler = ^void (proc_config_t proc_config, int child_id) {
	close(proc_config->parent_pipe[PIPE_IN]);
	close(proc_config->child_pipe[child_id][PIPE_OUT]);
	int action  = 0;
	long retval = 0;
	int i;
	void * tmp_map           = NULL;
	dispatch_queue_t q       = NULL;
	dispatch_semaphore_t sem = NULL;
	/*
	 * PHASE 1: Child ready and waits for parent to send next action
	 */
	T_LOG("Child ready to accept action from parent");
	retval = write(proc_config->parent_pipe[PIPE_OUT], &action, sizeof(action));
	if (retval != -1) {
		while (action != ACT_EXIT) {
			retval = read(proc_config->child_pipe[child_id][PIPE_IN], &action, sizeof(action));

			if (retval != -1) {
				retval = 0;
				switch (action) {
				case ACT_PHASE2: {
					/*
					 * Change uid, euid, guid, rgid, nice value
					 * Also change the svuid and svgid
					 */
					T_LOG("Child changing uid, euid, rguid, svuid, svgid and nice value");
					retval = nice(CONF_NICE_VAL);
					if (retval == -1) {
						T_LOG("(child) ERROR: nice() failed");
						break;
					}
					retval = setgid(CONF_GID_VAL);
					if (retval == -1) {
						T_LOG("(child) ERROR: setgid() failed");
						break;
					}
					retval = setreuid((uid_t)-1, CONF_RUID_VAL);
					if (retval == -1) {
						T_LOG("(child) ERROR: setreuid() failed");
						break;
					}
					break;
				}
				case ACT_PHASE3: {
					/*
					 * Allocate a page of memory
					 * Copy on write shared memory
					 *
					 * WARNING
					 * Don't add calls to T_LOG here as they can end up generating unwanted
					 * calls to mach_msg_send(). If curtask->messages_sent gets incremented
					 * at this point it will interfere with testing pti_messages_sent.
					 */
					retval  = 0;
					tmp_map = mmap(0, PAGE_SIZE, PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
					if (tmp_map == MAP_FAILED) {
						T_LOG("(child) ERROR: mmap() failed");
						retval = 1;
						break;
					}
					/*
					 * Get the page allocated
					 */
					int * map_ptr = (int *)tmp_map;
					for (i = 0; i < (int)(PAGE_SIZE / sizeof(int)); i++) {
						*map_ptr++ = i;
					}
					/*
					 * Cause copy on write to the page
					 */
					*((int *)(proc_config->cow_map)) = 20;

					break;
				}
				case ACT_PHASE4: {
					T_LOG("Child spending CPU cycles and changing thread name");
					retval                       = 0;
					int number                   = 1000;
					unsigned long long factorial = 1;
					int j;
					for (j = 1; j <= number; j++) {
						factorial *= (unsigned long long)j;
					}
					sysctlbyname("kern.threadname", NULL, 0, CONF_THREAD_NAME, strlen(CONF_THREAD_NAME));
					break;
				}
				case ACT_PHASE5: {
					/*
					 * Dispatch for Workq test
					 */
					T_LOG("Child creating a dispatch queue, and dispatching blocks on it");
					q = dispatch_queue_create("com.apple.test_proc_info.workqtest",
					    DISPATCH_QUEUE_CONCURRENT);                     // dispatch_get_global_queue(0, 0);
					sem = dispatch_semaphore_create(0);

					for (i = 0; i < CONF_NUM_THREADS; i++) {
						dispatch_async(q, ^{
								/*
								 * Block the thread, do nothing
								 */
								dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
							});
					}
					break;
				}
				case ACT_EXIT: {
					/*
					 * Exit
					 */
					if (sem) {
						for (i = 0; i < CONF_NUM_THREADS; i++) {
							dispatch_semaphore_signal(sem);
						}
					}

					if (tmp_map) {
						munmap(tmp_map, PAGE_SIZE);
					}

					if (proc_config->cow_map) {
						munmap(proc_config->cow_map, PAGE_SIZE);
					}

					break;
				}
				}
			}
			if (action != ACT_EXIT) {
				retval = write(proc_config->parent_pipe[PIPE_OUT], &action, sizeof(action));
				if (retval == -1) {
					break;
				}
			}
		}
		close(proc_config->parent_pipe[PIPE_OUT]);
		close(proc_config->child_pipe[child_id][PIPE_IN]);
		exit(0);
	}
};

static void
free_proc_config(proc_config_t proc_config)
{
	free(proc_config);
}

static void
send_action_to_child_processes(proc_config_t proc_config, int action)
{
	long err;
	for (int i = 0; i < proc_config->child_count; i++) {
		err = write(proc_config->child_pipe[i][PIPE_OUT], &action, sizeof(action));
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(err, "write() to child in send_action");
	}
	if (action != ACT_EXIT) {
		WAIT_FOR_CHILDREN(proc_config->parent_pipe[PIPE_IN], action, proc_config->child_count);
	}
}

static void
kill_child_processes(proc_config_t proc_config)
{
	int ret = 0;
	T_LOG("Killing child processes");
	send_action_to_child_processes(proc_config, ACT_EXIT);
	for (int child_id = 0; child_id < proc_config->child_count; child_id++) {
		close(proc_config->child_pipe[child_id][PIPE_OUT]);
		dt_waitpid(proc_config->child_pids[child_id], NULL, NULL, 5);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(ret, "killed child %d", child_id);
	}
	close(proc_config->parent_pipe[PIPE_IN]);
	munmap(proc_config->cow_map, PAGE_SIZE);
	T_LOG("Killed child processes");
}

static proc_config_t
spawn_child_processes(int child_count, child_action_handler_t child_handler)
{
	/*
	 * Spawn procs for Tests 1.2 and 1.3
	 */
	T_LOG("Spawning child processes...");
	proc_config_t proc_config = malloc(sizeof(*proc_config));
	int action                = 0;
	int err;

	setpgid(0, 0);
	proc_config->proc_grp_id = getpgid(0);

	proc_config->child_count = child_count;

	err = pipe(proc_config->parent_pipe);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(err, "pipe() call");

	/*
	 * Needed for ACT_PHASE3 tests
	 */
	proc_config->cow_map = mmap(0, PAGE_SIZE, PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	T_QUIET;
	T_ASSERT_NE_PTR(proc_config->cow_map, MAP_FAILED, "cow_map mmap()");
	*((int *)(proc_config->cow_map)) = 10;

	pid_t child_pid;
	int i;
	int child_id;
	for (i = 0; i < child_count; i++) {
		err = pipe(proc_config->child_pipe[i]);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(err, "pipe() call");

		child_pid = fork();
		child_id  = i;
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(child_pid, "fork() in parent process for child %d", child_id);

		if (child_pid == 0) {
			child_handler(proc_config, child_id);
		} else {
			proc_config->child_pids[child_id] = child_pid;
		}
		close(proc_config->child_pipe[child_id][PIPE_IN]);
	}
	/*
	 * Wait for the children processes to spawn
	 */
	close(proc_config->parent_pipe[PIPE_OUT]);
	WAIT_FOR_CHILDREN(proc_config->parent_pipe[PIPE_IN], action, child_count);

	return proc_config;
}

/*
 *  All PROC_INFO_CALL_PIDINFO __proc_info calls fire from this function.
 *  T_DECLs require different combinations of structs and different actions
 *  must occur in the child to get the data.  Instead of performing the setup
 *  in each T_DECL, this function accepts a bitmap and performs the necessary setup
 *  and cleanup work
 */

static void
proc_info_caller(int proc_info_opts, void ** ret_structs, int * ret_child_pid)
{
	int retval, i = 0;
	uint64_t * thread_addr = NULL;
	void * map_tmp         = NULL;
	static char tmp_path[PATH_MAX] = {};

	proc_config_t proc_config = spawn_child_processes(1, proc_info_call_pidinfo_handler);
	int child_pid             = proc_config->child_pids[0];
	/*
	 * These tests only require one child.
	 * Some DECLs need to know the child pid, so we pass that back if applicable
	 */
	if (ret_child_pid != NULL) {
		*ret_child_pid = child_pid;
	}

	if (proc_info_opts & P_UNIQIDINFO) {
		PROC_INFO_CALL(proc_uniqidentifierinfo, getpid(), PROC_PIDUNIQIDENTIFIERINFO, 0);
	}
	if (proc_info_opts & C_UNIQIDINFO) {
		PROC_INFO_CALL(proc_uniqidentifierinfo, child_pid, PROC_PIDUNIQIDENTIFIERINFO, 0);
	}
	if (proc_info_opts & PBSD_OLD) {
		PROC_INFO_CALL(proc_bsdinfo, child_pid, PROC_PIDTBSDINFO, 0);
	}

	/*
	 * Child Phase 2 Fires if opts require it
	 * Small nap after call to give child time to receive and execute the action
	 */

	if (proc_info_opts >= PBSD) {
		send_action_to_child_processes(proc_config, ACT_PHASE2);
	}

	if (proc_info_opts & PBSD) {
		PROC_INFO_CALL(proc_bsdinfo, child_pid, PROC_PIDTBSDINFO, 0);
	}

	if (proc_info_opts & PBSD_SHORT) {
		PROC_INFO_CALL(proc_bsdshortinfo, child_pid, PROC_PIDT_SHORTBSDINFO, 0);
	}

	if (proc_info_opts & PBSD_UNIQID) {
		PROC_INFO_CALL(proc_bsdinfowithuniqid, child_pid, PROC_PIDT_BSDINFOWITHUNIQID, 0);
	}
	if (proc_info_opts & P_TASK_INFO) {
		PROC_INFO_CALL(proc_taskinfo, child_pid, PROC_PIDTASKINFO, 0);
	}

	/*
	 * Child Phase 3 Fires
	 */
	if (proc_info_opts >= P_TASK_INFO_NEW) {
		send_action_to_child_processes(proc_config, ACT_PHASE3);
	}

	if (proc_info_opts & P_TASK_INFO_NEW) {
		PROC_INFO_CALL(proc_taskinfo, child_pid, PROC_PIDTASKINFO, 0);
	}

	if (proc_info_opts & PALL) {
		PROC_INFO_CALL(proc_taskallinfo, child_pid, PROC_PIDTASKALLINFO, 0);
	}
	/*
	 * This case breaks the pattern in that its proc_info call requires PALL,
	 * its value is required in some other proc_info calls
	 * and we never put the retval into our ret_structs
	 */
	if (proc_info_opts & THREAD_ADDR || proc_info_opts & PTHINFO_OLD || proc_info_opts & PTHINFO || proc_info_opts & PINFO_PATH) {
		struct proc_taskallinfo * pall = malloc(sizeof(struct proc_taskallinfo));
		T_QUIET;
		T_ASSERT_NOTNULL(pall, "malloc() for PROC_TASKALLINFO");

		retval = __proc_info(PROC_INFO_CALL_PIDINFO, child_pid, PROC_PIDTASKALLINFO, (uint32_t)0, (user_addr_t)pall,
		    (uint32_t)sizeof(struct proc_taskallinfo));
		T_QUIET;
		T_ASSERT_EQ_INT(retval, (int)sizeof(struct proc_taskallinfo), "__proc_info call for PROC_PIDTASKALLINFO in THREAD_ADDR");

		thread_addr = malloc(sizeof(uint64_t) * (unsigned long)(pall->ptinfo.pti_threadnum + 1));
		memset(thread_addr, 0, sizeof(uint64_t) * (unsigned long)(pall->ptinfo.pti_threadnum + 1));
		T_QUIET;
		T_ASSERT_NOTNULL(thread_addr, "malloc() for PROC_PIDLISTTHREADS");

		retval = __proc_info(PROC_INFO_CALL_PIDINFO, child_pid, PROC_PIDLISTTHREADS, (uint32_t)0, (user_addr_t)thread_addr,
		    (int32_t)(sizeof(uint64_t) * (unsigned long)(pall->ptinfo.pti_threadnum + 1)));
		T_LOG("(int)((unsigned long)retval / PROC_PIDLISTTHREADS_SIZE: %d",
		    (int)((unsigned long)retval / PROC_PIDLISTTHREADS_SIZE));
		T_ASSERT_GE_INT((int)((unsigned long)retval / PROC_PIDLISTTHREADS_SIZE), pall->ptinfo.pti_threadnum,
		    "__proc_info call for PROC_PIDLISTTHREADS");

		free(pall);
	}
	if (proc_info_opts & PTHINFO_OLD) {
		PROC_INFO_CALL(proc_threadinfo, child_pid, PROC_PIDTHREADINFO, thread_addr[0]);
	}

	/*
	 * Child Phase 4 Fires
	 */
	if (proc_info_opts >= PTHINFO) {
		send_action_to_child_processes(proc_config, ACT_PHASE4);
	}

	if (proc_info_opts & PTHINFO) {
		PROC_INFO_CALL(proc_threadinfo, child_pid, PROC_PIDTHREADINFO, thread_addr[0]);
	}
	if (proc_info_opts & PTHINFO_64) {
		mach_port_name_t child_task  = MACH_PORT_NULL;
		thread_array_t child_threads = NULL;
		mach_msg_type_number_t child_thread_count;
		thread_identifier_info_data_t child_thread_threadinfo;
		mach_msg_type_number_t thread_info_count = THREAD_IDENTIFIER_INFO_COUNT;
		struct proc_threadinfo * pthinfo_64      = malloc(sizeof(struct proc_threadinfo));
		T_QUIET;
		T_ASSERT_NOTNULL(pthinfo_64, "malloc() for PROC_THREADINFO");

		retval = task_for_pid(mach_task_self(), child_pid, &child_task);
		T_ASSERT_EQ_INT(retval, 0, "task_for_pid for PROC_PIDTHREADID64INFO");

		retval = task_threads(child_task, &child_threads, &child_thread_count);
		T_ASSERT_MACH_SUCCESS(retval, "task_threads() call for PROC_PIDTHREADID64INFO");

		retval = thread_info(child_threads[0], THREAD_IDENTIFIER_INFO, (thread_info_t)&child_thread_threadinfo, &thread_info_count);
		T_ASSERT_MACH_SUCCESS(retval, "thread_info call for PROC_PIDTHREADID64INFO");

		retval = __proc_info(PROC_INFO_CALL_PIDINFO, child_pid, PROC_PIDTHREADID64INFO, (uint64_t)child_thread_threadinfo.thread_id,
		    (user_addr_t)pthinfo_64, (uint32_t)sizeof(struct proc_threadinfo));
		T_ASSERT_EQ_INT(retval, (int)sizeof(struct proc_threadinfo), "__proc_info call for PROC_PIDTHREADID64INFO");

		ret_structs[i] = (void *)pthinfo_64;
		i++;

		mach_port_deallocate(mach_task_self(), child_task);
		mach_port_deallocate(mach_task_self(), child_threads[0]);
		child_threads[0] = MACH_PORT_NULL;
		child_task       = MACH_PORT_NULL;
	}
	if (proc_info_opts & PINFO_PATH) {
		PROC_INFO_CALL(proc_threadwithpathinfo, child_pid, PROC_PIDTHREADPATHINFO, thread_addr[0]);
	}

	if (proc_info_opts & PAI) {
		PROC_INFO_CALL(proc_archinfo, getpid(), PROC_PIDARCHINFO, 0);
	}

	vm_map_size_t map_tmp_sz = 0;
	if ((proc_info_opts & PREGINFO) | (proc_info_opts & PREGINFO_PATH) | (proc_info_opts & PREGINFO_PATH_2) |
	    (proc_info_opts & PREGINFO_PATH_3)) {
		tmp_fd = CONF_TMP_FILE_OPEN(tmp_path);

		/*
		 * subsequent checks assume that this data does *not* stay
		 * resident in the buffer cache, so set F_NOCACHE for direct
		 * to storage writing. NOTE: this works if the writes are
		 * page-aligned and > 2 pages in length.
		 */
		retval = fcntl(tmp_fd, F_NOCACHE, 1);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(retval, "fcntl(%d, F_NOCACHE) failed", tmp_fd);

		int npages_to_write = 10;
		map_tmp_sz = (vm_map_size_t)npages_to_write * (vm_map_size_t)PAGE_SIZE;

		/*
		 * To make sure we don't go through the cached write paths in
		 * the VM, we allocate a PAGE-aligned buffer that is > 2
		 * pages, and perform a write of the entire buffer (not in
		 * small page-aligned chunks).
		 */
		char *buf = valloc((size_t)map_tmp_sz);
		T_QUIET;
		T_ASSERT_NOTNULL(buf, "valloc(%d) failed", (int)map_tmp_sz);

		memset(buf, 0x5, map_tmp_sz);
		ssize_t bw = write(tmp_fd, buf, (size_t)map_tmp_sz);
		T_QUIET;
		T_ASSERT_GT_INT((int)bw, 0, "write(%d, buf, %d) failed", tmp_fd, (int)map_tmp_sz);

		free(buf);

		map_tmp_sz -= PAGE_SIZE;
		map_tmp = mmap(0, (size_t)map_tmp_sz, PROT_WRITE, MAP_PRIVATE, tmp_fd, (off_t)PAGE_SIZE);
		T_ASSERT_NE_PTR(map_tmp, MAP_FAILED, "mmap() for PROC_PIDREGIONINFO");

		T_LOG("file: %s is opened as fd %d and mapped at %llx with size %lu", tmp_path, tmp_fd, (uint64_t)map_tmp,
		    (unsigned long)PAGE_SIZE);

		/*
		 * unlink() the file to be nice, but do it _after_ we've
		 * already flushed and mapped the file. This will ensure that
		 * we don't end up writing to the buffer cache because the
		 * file is unlinked.
		 */
		if (!(proc_info_opts & PREGINFO_PATH_3)) {
			retval = unlink(tmp_path);
			T_QUIET;
			T_ASSERT_POSIX_SUCCESS(retval, "unlink(%s) failed", tmp_path);
		}
	}

	if (proc_info_opts & PREGINFO) {
		PROC_INFO_CALL(proc_regioninfo, getpid(), PROC_PIDREGIONINFO, map_tmp);
		ret_structs[i] = map_tmp;
		i++;
		ret_structs[i] = (void *)(uintptr_t)map_tmp_sz;
		i++;
	}
	if (proc_info_opts & PREGINFO_PATH) {
		PROC_INFO_CALL(proc_regionwithpathinfo, getpid(), PROC_PIDREGIONPATHINFO, map_tmp);
		ret_structs[i] = map_tmp;
		i++;
		ret_structs[i] = (void *)(uintptr_t)map_tmp_sz;
		i++;
	}
	if (proc_info_opts & PREGINFO_PATH_2) {
		PROC_INFO_CALL(proc_regionwithpathinfo, getpid(), PROC_PIDREGIONPATHINFO2, map_tmp);
		ret_structs[i] = map_tmp;
		i++;
		ret_structs[i] = (void *)(uintptr_t)map_tmp_sz;
		i++;
	}

	if (proc_info_opts & PREGINFO_PATH_3) {
		struct proc_regionwithpathinfo * preginfo_path = malloc(sizeof(struct proc_regionwithpathinfo));

		retval = __proc_info(PROC_INFO_CALL_PIDINFO, getpid(), PROC_PIDREGIONPATHINFO2, (uint64_t)map_tmp,
		    (user_addr_t)preginfo_path, (uint32_t)sizeof(struct proc_regionwithpathinfo));

		T_ASSERT_EQ_INT(retval, (int)sizeof(struct proc_regionwithpathinfo), "__proc_info call for PROC_PIDREGIONPATHINFO2");

		T_LOG("preginfo_path.prp_vip.vip_vi.vi_fsid.val 0: %d", preginfo_path->prp_vip.vip_vi.vi_fsid.val[0]);
		T_LOG("preginfo_path.prp_vip.vip_vi.vi_fsid.val 1: %d", preginfo_path->prp_vip.vip_vi.vi_fsid.val[1]);
		ret_structs[3] = (void *)(uintptr_t)preginfo_path->prp_vip.vip_vi.vi_fsid.val[0];
		ret_structs[4] = (void *)(uintptr_t)preginfo_path->prp_vip.vip_vi.vi_fsid.val[1];

		retval = __proc_info(PROC_INFO_CALL_PIDINFO, getpid(), PROC_PIDREGIONPATHINFO3,
		    (uint64_t)preginfo_path->prp_vip.vip_vi.vi_fsid.val[0] +
		    ((uint64_t)preginfo_path->prp_vip.vip_vi.vi_fsid.val[1] << 32),
		    (user_addr_t)preginfo_path,
		    (uint32_t)sizeof(struct proc_regionwithpathinfo));
		T_ASSERT_EQ_INT(retval, (int)sizeof(struct proc_regionwithpathinfo), "__proc_info call for PROC_PIDREGIONPATHWITHINFO3");
		ret_structs[0] = (void *)preginfo_path;
		ret_structs[1] = (void *)map_tmp;
		ret_structs[2] = (void *)(uintptr_t)map_tmp_sz;

		retval = unlink(tmp_path);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(retval, "unlink(%s) failed", preginfo_path->prp_vip.vip_path);
	}

	if (proc_info_opts & PVNINFO) {
		PROC_INFO_CALL(proc_vnodepathinfo, getpid(), PROC_PIDVNODEPATHINFO, 0);
	}

	kill_child_processes(proc_config);
	free_proc_config(proc_config);
	free(thread_addr);
	thread_addr = NULL;
	close(tmp_fd);
	tmp_fd = -1;
}

static void
free_proc_info(void ** proc_info, int num)
{
	for (int i = 0; i < num; i++) {
		free(proc_info[i]);
	}

	return;
}

/*
 *	Start DECLs
 */

T_DECL(proc_info_listpids_all_pids,
    "proc_info API test to verify PROC_INFO_CALL_LISTPIDS",
    T_META_ASROOT(true))
{
	/*
	 * Get the value of nprocs with no buffer sent in
	 */
	int num_procs;
	num_procs = __proc_info(PROC_INFO_CALL_LISTPIDS, PROC_ALL_PIDS, (uint32_t)getpid(), (uint32_t)0, (user_addr_t)0, (uint32_t)0);
	T_ASSERT_GE_INT(num_procs, 1, "verify valid value for nprocs: %d", num_procs);

	proc_config_t proc_config = spawn_child_processes(CONF_PROC_COUNT, proc_info_listpids_handler);

	num_procs = __proc_info(PROC_INFO_CALL_LISTPIDS, PROC_ALL_PIDS, (uint32_t)getpid(), (uint32_t)0, (user_addr_t)0, (uint32_t)0);

	int proc_count     = num_procs / (int)sizeof(pid_t);
	int proc_count_all = num_procs / (int)sizeof(pid_t);
	if (proc_count > (CONF_PROC_COUNT + 1)) {
		proc_count = CONF_PROC_COUNT + 1;
	}
	pid_t * proc_ids = malloc(sizeof(pid_t) * (unsigned long)proc_count);
	num_procs        = __proc_info(PROC_INFO_CALL_LISTPIDS, PROC_ALL_PIDS, (uint32_t)getpid(), (uint32_t)0, (user_addr_t)proc_ids,
	    (int32_t)(proc_count * (int)sizeof(pid_t)));
	num_procs = num_procs / (int)sizeof(pid_t);
	T_ASSERT_GE_INT(num_procs, proc_count, "Valid number of pids obtained for PROC_ALL_PIDS.");

	free(proc_ids);

	/*
	 * Grab list of all procs and make sure our spawned children are in the list.
	 */

	proc_ids  = malloc(sizeof(pid_t) * (unsigned long)proc_count_all);
	num_procs = __proc_info(PROC_INFO_CALL_LISTPIDS, PROC_ALL_PIDS, (uint32_t)getpid(), (uint32_t)0, (user_addr_t)proc_ids,
	    (int32_t)(proc_count_all * (int)sizeof(pid_t)));
	num_procs = num_procs / (int)sizeof(pid_t);

	int pid_match = 1;

	for (int i = 0; i < (CONF_PROC_COUNT - 1); i++) {
		for (int j = 0; j < num_procs; j++) {
			if (proc_ids[j] == proc_config->child_pids[i]) {
				break;
			} else if (j == (num_procs - 1)) {
				pid_match = 0;
				break;
			}
		}

		if (!pid_match) {
			break;
		}
	}

	T_ASSERT_EQ(pid_match, 1, "PROC_INFO_CALL_LISTPIDS contains our spawned children's pids");

	free(proc_ids);

	kill_child_processes(proc_config);
	free_proc_config(proc_config);

	errno     = 0;
	num_procs = __proc_info(PROC_INFO_CALL_LISTPIDS, PROC_ALL_PIDS, (uint32_t)getpid(), (uint32_t)0, (user_addr_t)proc_ids,
	    (uint32_t)(sizeof(pid_t) - 1));
	T_EXPECT_POSIX_ERROR(errno, ENOMEM, "Valid proc_info behavior when bufsize < sizeof(pid_t).");
}

T_DECL(proc_info_listpids_pgrp_only,
    "proc_info API test to verify PROC_INFO_CALL_LISTPIDS",
    T_META_ASROOT(true))
{
	proc_config_t proc_config = spawn_child_processes(CONF_PROC_COUNT, proc_info_listpids_handler);
	T_LOG("Test to verify PROC_PGRP_ONLY returns correct value");
	/*
	 * The number of obtained pids depends on size of buffer.
	 * count = childCount + 1(parent)
	 * So, we set it to one more than expected to capture any error.
	 */
	int proc_count   = CONF_PROC_COUNT + 2;
	pid_t * proc_ids = malloc(sizeof(*proc_ids) * (unsigned long)proc_count);
	int num_procs    = __proc_info(PROC_INFO_CALL_LISTPIDS, PROC_PGRP_ONLY, (uint32_t)proc_config->proc_grp_id, (uint32_t)0,
	    (user_addr_t)proc_ids, (int32_t)(proc_count * (int)sizeof(*proc_ids)));
	num_procs = num_procs / (int)sizeof(pid_t);
	T_ASSERT_EQ_INT(num_procs, CONF_PROC_COUNT + 1, "Valid number of pids obtained for PROC_PGRP_ONLY.");
	kill_child_processes(proc_config);
	free_proc_config(proc_config);
	free(proc_ids);
}

T_DECL(proc_info_listpids_ppid_only,
    "proc_info API test to verify PROC_INFO_CALL_LISTPIDS",
    T_META_ASROOT(true))
{
	proc_config_t proc_config = spawn_child_processes(CONF_PROC_COUNT, proc_info_listpids_handler);
	T_LOG("Test to verify PROC_PPID_ONLY returns correct value");
	/*
	 * Pass in the same (bigger) buffer but expect only the pids where ppid is pid of current proc.
	 */
	int proc_count   = CONF_PROC_COUNT + 2;
	pid_t * proc_ids = malloc(sizeof(*proc_ids) * (unsigned long)proc_count);
	int num_procs    = __proc_info(PROC_INFO_CALL_LISTPIDS, PROC_PPID_ONLY, (uint32_t)getpid(), (uint32_t)0, (user_addr_t)proc_ids,
	    (int32_t)(proc_count * (int)sizeof(*proc_ids)));
	num_procs = num_procs / (int)sizeof(pid_t);
	T_ASSERT_EQ_INT(num_procs, CONF_PROC_COUNT, "Valid number of pids obtained for PROC_PPID_ONLY.");
	kill_child_processes(proc_config);
	free_proc_config(proc_config);
	free(proc_ids);
}

T_DECL(proc_info_listpids_uid_only,
    "proc_info API test to verify PROC_INFO_CALL_LISTPIDS",
    T_META_ASROOT(true))
{
	proc_config_t proc_config = spawn_child_processes(CONF_PROC_COUNT, proc_info_listpids_handler);
	T_LOG("Test to verify PROC_UID_ONLY returns correct value");
	int proc_count   = CONF_PROC_COUNT + 2;
	pid_t * proc_ids = malloc(sizeof(*proc_ids) * (unsigned long)proc_count);
	send_action_to_child_processes(proc_config, ACT_CHANGE_UID);
	usleep(10000);
	int num_procs = __proc_info(PROC_INFO_CALL_LISTPIDS, PROC_UID_ONLY, CONF_UID_VAL, (uint32_t)0, (user_addr_t)proc_ids,
	    (int32_t)(proc_count * (int)sizeof(*proc_ids)));
	T_ASSERT_GE_ULONG((unsigned long)num_procs / sizeof(pid_t), (unsigned long)CONF_PROC_COUNT,
	    "Valid number of pids obtained for PROC_UID_ONLY.");
	kill_child_processes(proc_config);
	free_proc_config(proc_config);
	free(proc_ids);
}

T_DECL(proc_info_listpids_ruid_only,
    "proc_info API test to verify PROC_INFO_CALL_LISTPIDS",
    T_META_ASROOT(true))
{
	proc_config_t proc_config = spawn_child_processes(CONF_PROC_COUNT, proc_info_listpids_handler);
	T_LOG("Test to verify PROC_RUID_ONLY returns correct value");
	int proc_count   = CONF_PROC_COUNT + 2;
	pid_t * proc_ids = malloc(sizeof(*proc_ids) * (unsigned long)proc_count);
	send_action_to_child_processes(proc_config, ACT_CHANGE_RUID);
	usleep(10000);
	int num_procs = __proc_info(PROC_INFO_CALL_LISTPIDS, PROC_RUID_ONLY, CONF_RUID_VAL, (uint32_t)0, (user_addr_t)proc_ids,
	    (int32_t)(proc_count * (int)sizeof(*proc_ids)));
	T_ASSERT_GE_ULONG((unsigned long)num_procs / sizeof(pid_t), (unsigned long)CONF_PROC_COUNT,
	    "Valid number of pids obtained for PROC_RUID_ONLY.");
	kill_child_processes(proc_config);
	free_proc_config(proc_config);
	free(proc_ids);
}

T_DECL(proc_info_listpids_tty_only,
    "proc_info API test to verify PROC_INFO_CALL_LISTPIDS",
    T_META_ASROOT(true))
{
	int ret = isatty(STDOUT_FILENO);
	if (ret != 1) {
		T_SKIP("Not connected to tty...skipping test");
	}

	proc_config_t proc_config = spawn_child_processes(CONF_PROC_COUNT, proc_info_listpids_handler);

	T_LOG("Test to verify PROC_TTY_ONLY returns correct value");
	int proc_count   = CONF_PROC_COUNT + 2;
	pid_t * proc_ids = malloc(sizeof(*proc_ids) * (unsigned long)proc_count);
	int num_procs    = __proc_info(PROC_INFO_CALL_LISTPIDS, PROC_TTY_ONLY, get_tty_dev(), (uint32_t)0, (user_addr_t)proc_ids,
	    (int32_t)(proc_count * (int)sizeof(*proc_ids)));
	num_procs = num_procs / (int)sizeof(pid_t);
	T_ASSERT_GE_INT(num_procs, 0, "Valid number of pids returned by PROC_TTY_ONLY.");
	kill_child_processes(proc_config);
	free_proc_config(proc_config);
	free(proc_ids);
}

/*
 * Most of the following PROC_INFO_CALL_PIDINFO tests rely on a helper function (proc_info_caller) to make the necessary proc_info
 * calls on their behalf
 * In a previous iteration, these tests were all in one giant T_DECL and the helper function handles inter-DECL dependencies such as
 * a proc_info call relying on the results of a previous proc_info call or an assumed state that a child should be in.
 */

T_DECL(proc_info_pidinfo_proc_piduniqidentifierinfo,
    "Test to identify PROC_PIDUNIQIDENTIFIERINFO returns correct unique identifiers for process",
    T_META_ASROOT(true))
{
	void * proc_info[2];
	proc_info_caller(P_UNIQIDINFO | C_UNIQIDINFO, proc_info, NULL);
	struct proc_uniqidentifierinfo * p_uniqidinfo = (struct proc_uniqidentifierinfo *)proc_info[0];
	struct proc_uniqidentifierinfo * c_uniqidinfo = (struct proc_uniqidentifierinfo *)proc_info[1];

	T_EXPECT_NE_ULLONG(c_uniqidinfo->p_uniqueid, p_uniqidinfo->p_uniqueid, "p_uniqueid not unique for the process");

	for (size_t i = 0; i < 16; i++) {
		T_EXPECT_EQ_UCHAR(c_uniqidinfo->p_uuid[i], p_uniqidinfo->p_uuid[i], "p_uuid should be the same unique id");
	}
	T_EXPECT_EQ_ULLONG(c_uniqidinfo->p_puniqueid, p_uniqidinfo->p_uniqueid,
	    "p_puniqueid of child should be same as p_uniqueid for parent");

	free_proc_info(proc_info, 2);
}

T_DECL(proc_info_pidinfo_proc_pidtbsdinfo,
    "Test to verify PROC_PIDTBSDINFO returns valid information about the process",
    T_META_ASROOT(true))
{
	void * proc_info[2];
	int child_pid = 0;
	proc_info_caller(PBSD_OLD | PBSD, proc_info, &child_pid);
	struct proc_bsdinfo * pbsd_old = (struct proc_bsdinfo *)proc_info[0];
	struct proc_bsdinfo * pbsd     = (struct proc_bsdinfo *)proc_info[1];

	T_EXPECT_EQ_UINT((unsigned int)SRUN, pbsd->pbi_status, "PROC_PIDTBSDINFO shows Correct status");
	T_EXPECT_EQ_UINT(0U, pbsd->pbi_xstatus, "PROC_PIDTBSDINFO show Correct xstatus (exit status)");
	T_EXPECT_EQ_UINT(pbsd->pbi_pid, (unsigned int)child_pid, "PROC_PIDTBSDINFO returns valid pid");
	T_EXPECT_EQ_UINT(pbsd->pbi_ppid, (unsigned int)getpid(), "PROC_PIDTBSDINFO returns valid ppid");
	T_EXPECT_EQ_UINT(pbsd->pbi_uid, CONF_RUID_VAL, "PROC_PIDTBSDINFO returns valid uid");
	T_EXPECT_EQ_UINT(pbsd->pbi_gid, CONF_GID_VAL, "PROC_PIDTBSDINFO returns valid gid");
	T_EXPECT_EQ_UINT(pbsd->pbi_ruid, 0U, "PROC_PIDTBSDINFO returns valid ruid");
	T_EXPECT_EQ_UINT(pbsd->pbi_rgid, CONF_GID_VAL, "PROC_PIDTBSDINFO returns valid rgid");
	T_EXPECT_EQ_UINT(pbsd->pbi_svuid, CONF_RUID_VAL, "PROC_PIDTBSDINFO returns valid svuid");
	T_EXPECT_EQ_UINT(pbsd->pbi_svgid, CONF_GID_VAL, "PROC_PIDTBSDINFO returns valid svgid");
	T_EXPECT_EQ_UINT(pbsd->pbi_nice, CONF_NICE_VAL, "PROC_PIDTBSDINFO returns valid nice value");
	T_EXPECT_EQ_STR(pbsd->pbi_comm, CONF_CMD_NAME, "PROC_PIDTBSDINFO returns valid p_comm name");
	T_EXPECT_EQ_STR(pbsd->pbi_name, CONF_CMD_NAME, "PROC_PIDTBSDINFO returns valid p_name name");
	T_EXPECT_EQ_UINT(pbsd->pbi_flags, (pbsd_old->pbi_flags | PROC_FLAG_PSUGID), "PROC_PIDTBSDINFO returns valid flags");
	T_EXPECT_EQ_UINT(pbsd->pbi_nfiles, pbsd_old->pbi_nfiles, "PROC_PIDTBSDINFO returned valid pbi_nfiles");
	T_EXPECT_EQ_UINT(pbsd->pbi_pgid, (uint32_t)getpgid(getpid()), "PROC_PIDTBSDINFO returned valid pbi_pgid");
	T_EXPECT_EQ_UINT(pbsd->pbi_pjobc, pbsd->pbi_pjobc, "PROC_PIDTBSDINFO returned valid pbi_pjobc");
	T_EXPECT_NE_UINT(pbsd->e_tdev, 0U, "PROC_PIDTBSDINFO returned valid e_tdev");

	free_proc_info(proc_info, 2);
}

T_DECL(proc_info_pidt_shortbsdinfo,
    "Test to verify PROC_PIDT_SHORTBSDINFO returns valid information about the process",
    T_META_ASROOT(true))
{
	void * proc_info[2];
	int child_pid = 0;
	proc_info_caller(PBSD | PBSD_SHORT, proc_info, &child_pid);
	struct proc_bsdinfo * pbsd            = (struct proc_bsdinfo *)proc_info[0];
	struct proc_bsdshortinfo * pbsd_short = (struct proc_bsdshortinfo *)proc_info[1];

	T_EXPECT_EQ_UINT(pbsd_short->pbsi_pid, (unsigned int)child_pid, "PROC_PIDT_SHORTBSDINFO returns valid pid");
	T_EXPECT_EQ_UINT(pbsd_short->pbsi_ppid, (unsigned int)getpid(), "PROC_PIDT_SHORTBSDINFO returns valid ppid");
	T_EXPECT_EQ_UINT(pbsd_short->pbsi_pgid, (uint32_t)getpgid(getpid()), "PROC_PIDT_SHORTBSDINFO returned valid pbi_pgid");
	T_EXPECT_EQ_UINT((unsigned int)SRUN, pbsd_short->pbsi_status, "PROC_PIDT_SHORTBSDINFO shows Correct status");
	T_EXPECT_EQ_STR(pbsd_short->pbsi_comm, CONF_CMD_NAME, "PROC_PIDT_SHORTBSDINFO returns valid p_comm name");
	/*
	 * The short variant returns all flags except session flags, hence ignoring them here.
	 */
	T_EXPECT_EQ_UINT(pbsd_short->pbsi_flags, (pbsd->pbi_flags & (unsigned int)(~PROC_FLAG_CTTY)),
	    "PROC_PIDT_SHORTBSDINFO returns valid flags");
	T_EXPECT_EQ_UINT(pbsd_short->pbsi_uid, CONF_RUID_VAL, "PROC_PIDT_SHORTBSDINFO returns valid uid");
	T_EXPECT_EQ_UINT(pbsd_short->pbsi_gid, CONF_GID_VAL, "PROC_PIDT_SHORTBSDINFO returns valid gid");
	T_EXPECT_EQ_UINT(pbsd_short->pbsi_ruid, 0U, "PROC_PIDT_SHORTBSDINFO returns valid ruid");
	T_EXPECT_EQ_UINT(pbsd_short->pbsi_svuid, CONF_RUID_VAL, "PROC_PIDT_SHORTBSDINFO returns valid svuid");
	T_EXPECT_EQ_UINT(pbsd_short->pbsi_svgid, CONF_GID_VAL, "PROC_PIDT_SHORTBSDINFO returns valid svgid");

	free_proc_info(proc_info, 2);
}

T_DECL(proc_info_pidt_bsdinfowithuniqid,
    "Test to verify PROC_PIDT_BSDINFOWITHUNIQID returns valid information about the process",
    T_META_ASROOT(true))
{
	void * proc_info[4];
	int child_pid = 0;
	proc_info_caller(P_UNIQIDINFO | PBSD_OLD | PBSD | PBSD_UNIQID, proc_info, &child_pid);
	struct proc_uniqidentifierinfo * p_uniqidinfo = (struct proc_uniqidentifierinfo *)proc_info[0];
	struct proc_bsdinfo * pbsd_old                = (struct proc_bsdinfo *)proc_info[1];
	struct proc_bsdinfo * pbsd                    = (struct proc_bsdinfo *)proc_info[2];
	struct proc_bsdinfowithuniqid * pbsd_uniqid   = (struct proc_bsdinfowithuniqid *)proc_info[3];

	T_EXPECT_EQ_UINT((unsigned int)SRUN, pbsd->pbi_status, "PROC_PIDT_BSDINFOWITHUNIQID shows Correct status");
	T_EXPECT_EQ_UINT(0U, pbsd->pbi_xstatus, "PROC_PIDT_BSDINFOWITHUNIQID show Correct xstatus");
	T_EXPECT_EQ_UINT(pbsd_uniqid->pbsd.pbi_pid, (unsigned int)child_pid, "PROC_PIDT_BSDINFOWITHUNIQID returns valid pid");
	T_EXPECT_EQ_UINT(pbsd_uniqid->pbsd.pbi_ppid, (unsigned int)getpid(), "PROC_PIDT_BSDINFOWITHUNIQID returns valid ppid");
	T_EXPECT_EQ_UINT(pbsd_uniqid->pbsd.pbi_uid, CONF_RUID_VAL, "PROC_PIDT_BSDINFOWITHUNIQID returns valid uid");
	T_EXPECT_EQ_UINT(pbsd_uniqid->pbsd.pbi_gid, CONF_GID_VAL, "PROC_PIDT_BSDINFOWITHUNIQID returns valid gid");
	T_EXPECT_EQ_UINT(pbsd_uniqid->pbsd.pbi_ruid, 0U, "PROC_PIDT_BSDINFOWITHUNIQID returns valid ruid");
	T_EXPECT_EQ_UINT(pbsd_uniqid->pbsd.pbi_rgid, CONF_GID_VAL, "PROC_PIDT_BSDINFOWITHUNIQID returns valid rgid");
	T_EXPECT_EQ_UINT(pbsd_uniqid->pbsd.pbi_svuid, CONF_RUID_VAL, "PROC_PIDT_BSDINFOWITHUNIQID returns valid svuid");
	T_EXPECT_EQ_UINT(pbsd_uniqid->pbsd.pbi_svgid, CONF_GID_VAL, "PROC_PIDT_BSDINFOWITHUNIQID returns valid svgid");
	T_EXPECT_EQ_UINT(pbsd_uniqid->pbsd.pbi_nice, CONF_NICE_VAL, "PROC_PIDT_BSDINFOWITHUNIQID returns valid nice value");
	T_EXPECT_EQ_STR(pbsd_uniqid->pbsd.pbi_comm, CONF_CMD_NAME, "PROC_PIDT_BSDINFOWITHUNIQID returns valid p_comm name");
	T_EXPECT_EQ_STR(pbsd_uniqid->pbsd.pbi_name, CONF_CMD_NAME, "PROC_PIDT_BSDINFOWITHUNIQID returns valid p_name name");
	T_EXPECT_EQ_UINT(pbsd_uniqid->pbsd.pbi_flags, (pbsd_old->pbi_flags | PROC_FLAG_PSUGID),
	    "PROC_PIDT_BSDINFOWITHUNIQID returns valid flags");
	T_EXPECT_EQ_UINT(pbsd_uniqid->pbsd.pbi_nfiles, pbsd_old->pbi_nfiles, "PROC_PIDT_BSDINFOWITHUNIQID returned valid pbi_nfiles");
	T_EXPECT_EQ_UINT(pbsd_uniqid->pbsd.pbi_pgid, (uint32_t)getpgid(getpid()),
	    "PROC_PIDT_BSDINFOWITHUNIQID returned valid pbi_pgid");
	T_EXPECT_EQ_UINT(pbsd_uniqid->pbsd.pbi_pjobc, pbsd->pbi_pjobc, "PROC_PIDT_BSDINFOWITHUNIQID returned valid pbi_pjobc");
	T_EXPECT_NE_UINT(pbsd_uniqid->pbsd.e_tdev, 0U, "PROC_PIDT_BSDINFOWITHUNIQID returned valid e_tdev");
	T_EXPECT_NE_ULLONG(pbsd_uniqid->p_uniqidentifier.p_uniqueid, p_uniqidinfo->p_uniqueid,
	    "PROC_PIDT_BSDINFOWITHUNIQID returned valid p_uniqueid");
	for (int i = 0; i < 16; i++) {
		T_EXPECT_EQ_UCHAR(pbsd_uniqid->p_uniqidentifier.p_uuid[i], p_uniqidinfo->p_uuid[i],
		    "PROC_PIDT_BSDINFOWITHUNIQID reported valid p_uniqueid");
	}
	T_EXPECT_EQ_ULLONG(pbsd_uniqid->p_uniqidentifier.p_puniqueid, p_uniqidinfo->p_uniqueid,
	    "p_puniqueid of child should be same as p_uniqueid for parent");

	free_proc_info(proc_info, 4);
}

T_DECL(proc_info_proc_pidtask_info,
    "Test to verify PROC_PIDTASKINFO returns valid information about the process",
    T_META_ASROOT(true))
{
	void * proc_info[2];
	proc_info_caller(P_TASK_INFO | P_TASK_INFO_NEW, proc_info, NULL);
	struct proc_taskinfo * p_task_info     = (struct proc_taskinfo *)proc_info[0];
	struct proc_taskinfo * p_task_info_new = (struct proc_taskinfo *)proc_info[1];

	T_EXPECT_GE_ULLONG((p_task_info_new->pti_virtual_size - p_task_info->pti_virtual_size), (unsigned long long)PAGE_SIZE,
	    "PROC_PIDTASKINFO returned valid value for pti_virtual_size");
	T_EXPECT_GE_ULLONG((p_task_info_new->pti_resident_size - p_task_info->pti_resident_size), (unsigned long long)PAGE_SIZE,
	    "PROC_PIDTASKINFO returned valid value for pti_virtual_size");
	T_EXPECT_EQ_INT(p_task_info_new->pti_policy, POLICY_TIMESHARE, "PROC_PIDTASKINFO returned valid value for pti_virtual_size");
	T_EXPECT_GE_ULLONG(p_task_info->pti_threads_user, 1ULL, "PROC_PIDTASKINFO returned valid value for pti_threads_user");
#if defined(__arm__) || defined(__arm64__)
	T_EXPECT_GE_ULLONG(p_task_info->pti_threads_system, 0ULL, "PROC_PIDTASKINFO returned valid value for pti_threads_system");
	T_EXPECT_GE_ULLONG((p_task_info_new->pti_total_system - p_task_info->pti_total_system), 0ULL,
	    "PROC_PIDTASKINFO returned valid value for pti_total_system");
#else
	T_EXPECT_GE_ULLONG(p_task_info->pti_threads_system, 1ULL, "PROC_PIDTASKINFO returned valid value for pti_threads_system");
	T_EXPECT_GT_ULLONG((p_task_info_new->pti_total_system - p_task_info->pti_total_system), 0ULL,
	    "PROC_PIDTASKINFO returned valid value for pti_total_system");
#endif
	T_EXPECT_GT_ULLONG((p_task_info_new->pti_total_user - p_task_info->pti_total_user), 0ULL,
	    "PROC_PIDTASKINFO returned valid value for pti_total_user");
	T_EXPECT_GE_INT((p_task_info_new->pti_faults - p_task_info->pti_faults), 1,
	    "PROC_PIDTASKINFO returned valid value for pti_faults");
	T_EXPECT_GE_INT((p_task_info_new->pti_cow_faults - p_task_info->pti_cow_faults), 1,
	    "PROC_PIDTASKINFO returned valid value for pti_cow_faults");
	T_EXPECT_GE_INT((p_task_info_new->pti_syscalls_mach - p_task_info->pti_syscalls_mach), 0,
	    "PROC_PIDTASKINFO returned valid value for pti_syscalls_mach");
	T_EXPECT_GE_INT((p_task_info_new->pti_syscalls_unix - p_task_info->pti_syscalls_unix), 2,
	    "PROC_PIDTASKINFO returned valid value for pti_syscalls_unix");
	T_EXPECT_EQ_INT((p_task_info_new->pti_messages_sent - p_task_info->pti_messages_sent), 0,
	    "PROC_PIDTASKINFO returned valid value for pti_messages_sent");
	T_EXPECT_EQ_INT((p_task_info_new->pti_messages_received - p_task_info->pti_messages_received), 0,
	    "PROC_PIDTASKINFO returned valid value for pti_messages_received");
	T_EXPECT_EQ_INT(p_task_info_new->pti_priority, p_task_info->pti_priority,
	    "PROC_PIDTASKINFO returned valid value for pti_priority");
	T_EXPECT_GE_INT(p_task_info_new->pti_threadnum, 1, "PROC_PIDTASKINFO returned valid value for pti_threadnum");

	if (p_task_info_new->pti_threadnum > 1) {
		T_LOG("WARN: PROC_PIDTASKINFO returned threadnum greater than 1");
	}
	T_EXPECT_GE_INT(p_task_info_new->pti_numrunning, 0, "PROC_PIDTASKINFO returned valid value for pti_numrunning");
	T_EXPECT_GE_INT(p_task_info_new->pti_pageins, 0, "PROC_PIDTASKINFO returned valid value for pti_pageins");

	if (p_task_info_new->pti_pageins > 0) {
		T_LOG("WARN: PROC_PIDTASKINFO returned pageins greater than 0");
	}

	T_EXPECT_GE_INT(p_task_info_new->pti_csw, p_task_info->pti_csw, "PROC_PIDTASKINFO returned valid value for pti_csw");

	free_proc_info(proc_info, 2);
}

T_DECL(proc_info_proc_pidtaskallinfo,
    "Test to verify PROC_PIDTASKALLINFO returns valid information about the process",
    T_META_ASROOT(true))
{
	void * proc_info[4];
	int child_pid = 0;
	proc_info_caller(PBSD | PBSD_OLD | P_TASK_INFO | PALL, proc_info, &child_pid);
	struct proc_bsdinfo * pbsd         = (struct proc_bsdinfo *)proc_info[0];
	struct proc_bsdinfo * pbsd_old     = (struct proc_bsdinfo *)proc_info[1];
	struct proc_taskinfo * p_task_info = (struct proc_taskinfo *)proc_info[2];
	struct proc_taskallinfo * pall     = (struct proc_taskallinfo *)proc_info[3];

	T_EXPECT_EQ_UINT((unsigned int)SRUN, pbsd->pbi_status, "PROC_PIDTASKALLINFO shows Correct status");
	T_EXPECT_EQ_UINT(0U, pbsd->pbi_xstatus, "PROC_PIDTASKALLINFO show Correct xstatus");
	T_EXPECT_EQ_UINT(pall->pbsd.pbi_pid, (unsigned int)child_pid, "PROC_PIDTASKALLINFO returns valid pid");
	T_EXPECT_EQ_UINT(pall->pbsd.pbi_ppid, (unsigned int)getpid(), "PROC_PIDTASKALLINFO returns valid ppid");
	T_EXPECT_EQ_UINT(pall->pbsd.pbi_uid, CONF_RUID_VAL, "PROC_PIDTASKALLINFO returns valid uid");
	T_EXPECT_EQ_UINT(pall->pbsd.pbi_gid, CONF_GID_VAL, "PROC_PIDTASKALLINFO returns valid gid");
	T_EXPECT_EQ_UINT(pall->pbsd.pbi_ruid, 0U, "PROC_PIDTASKALLINFO returns valid ruid");
	T_EXPECT_EQ_UINT(pall->pbsd.pbi_rgid, CONF_GID_VAL, "PROC_PIDTASKALLINFO returns valid rgid");
	T_EXPECT_EQ_UINT(pall->pbsd.pbi_svuid, CONF_RUID_VAL, "PROC_PIDTASKALLINFO returns valid svuid");
	T_EXPECT_EQ_UINT(pall->pbsd.pbi_svgid, CONF_GID_VAL, "PROC_PIDTASKALLINFO returns valid svgid");
	T_EXPECT_EQ_INT(pall->pbsd.pbi_nice, CONF_NICE_VAL, "PROC_PIDTASKALLINFO returns valid nice value");
	T_EXPECT_EQ_STR(pall->pbsd.pbi_comm, CONF_CMD_NAME, "PROC_PIDTASKALLINFO returns valid p_comm name");
	T_EXPECT_EQ_STR(pall->pbsd.pbi_name, CONF_CMD_NAME, "PROC_PIDTASKALLINFO returns valid p_name name");
	T_EXPECT_EQ_UINT(pall->pbsd.pbi_flags, (pbsd_old->pbi_flags | PROC_FLAG_PSUGID), "PROC_PIDTASKALLINFO returns valid flags");
	T_EXPECT_EQ_UINT(pall->pbsd.pbi_nfiles, pbsd_old->pbi_nfiles, "PROC_PIDTASKALLINFO returned valid pbi_nfiles");
	T_EXPECT_EQ_UINT(pall->pbsd.pbi_pgid, (uint32_t)getpgid(getpid()), "PROC_PIDTASKALLINFO returned valid pbi_pgid");
	T_EXPECT_EQ_UINT(pall->pbsd.pbi_pjobc, pbsd->pbi_pjobc, "PROC_PIDTASKALLINFO returned valid pbi_pjobc");
	T_EXPECT_NE_UINT(pall->pbsd.e_tdev, 0U, "PROC_PIDTASKALLINFO returned valid e_tdev");

#if defined(__arm__) || defined(__arm64__)
	T_EXPECT_GE_ULLONG(pall->ptinfo.pti_threads_system, 0ULL, "PROC_PIDTASKALLINFO returned valid value for pti_threads_system");
	T_EXPECT_GE_ULLONG((pall->ptinfo.pti_total_system - p_task_info->pti_total_system), 0ULL,
	    "PROC_PIDTASKALLINFO returned valid value for pti_total_system");
#else
	T_EXPECT_GE_ULLONG(pall->ptinfo.pti_threads_system, 1ULL, "PROC_PIDTASKALLINFO returned valid value for pti_threads_system");
	T_EXPECT_GT_ULLONG((pall->ptinfo.pti_total_system - p_task_info->pti_total_system), 0ULL,
	    "PROC_PIDTASKALLINFO returned valid value for pti_total_system");
#endif /* ARM */

	T_EXPECT_GE_ULLONG((pall->ptinfo.pti_virtual_size - p_task_info->pti_virtual_size), (unsigned long long)PAGE_SIZE,
	    "PROC_PIDTASKALLINFO returned valid value for pti_virtual_size");
	T_EXPECT_GE_ULLONG((pall->ptinfo.pti_resident_size - p_task_info->pti_resident_size), (unsigned long long)PAGE_SIZE,
	    "PROC_PIDTASKALLINFO returned valid value for pti_virtual_size");
	T_EXPECT_EQ_INT(pall->ptinfo.pti_policy, POLICY_TIMESHARE, "PROC_PIDTASKALLINFO returned valid value for pti_virtual_size");
	T_EXPECT_GE_ULLONG(pall->ptinfo.pti_threads_user, 1ULL, "PROC_PIDTASKALLINFO returned valid value for pti_threads_user ");
	T_EXPECT_GT_ULLONG((pall->ptinfo.pti_total_user - p_task_info->pti_total_user), 0ULL,
	    "PROC_PIDTASKALLINFO returned valid value for pti_total_user");
	T_EXPECT_GE_INT((pall->ptinfo.pti_faults - p_task_info->pti_faults), 1,
	    "PROC_PIDTASKALLINFO returned valid value for pti_faults");
	T_EXPECT_GE_INT((pall->ptinfo.pti_cow_faults - p_task_info->pti_cow_faults), 1,
	    "PROC_PIDTASKALLINFO returned valid value for pti_cow_faults");
	T_EXPECT_GE_INT((pall->ptinfo.pti_syscalls_mach - p_task_info->pti_syscalls_mach), 0,
	    "PROC_PIDTASKALLINFO returned valid value for pti_syscalls_mach");
	T_EXPECT_GE_INT((pall->ptinfo.pti_syscalls_unix - p_task_info->pti_syscalls_unix), 2,
	    "PROC_PIDTASKALLINFO returned valid value for pti_syscalls_unix");
	T_EXPECT_EQ_INT((pall->ptinfo.pti_messages_sent - p_task_info->pti_messages_sent), 0,
	    "PROC_PIDTASKALLINFO returned valid value for pti_messages_sent");
	T_EXPECT_EQ_INT((pall->ptinfo.pti_messages_received - p_task_info->pti_messages_received), 0,
	    "PROC_PIDTASKALLINFO returned valid value for pti_messages_received");
	T_EXPECT_EQ_INT(pall->ptinfo.pti_priority, p_task_info->pti_priority,
	    "PROC_PIDTASKALLINFO returned valid value for pti_priority");
	T_EXPECT_GE_INT(pall->ptinfo.pti_threadnum, 1, "PROC_PIDTASKALLINFO returned valid value for pti_threadnum");
	if (pall->ptinfo.pti_threadnum > 1) {
		T_LOG("WARN: PROC_PIDTASKALLINFO returned threadnum greater than 1");
	}
	T_EXPECT_GE_INT(pall->ptinfo.pti_numrunning, 0, "PROC_PIDTASKALLINFO returned valid value for pti_numrunning");
	T_EXPECT_GE_INT(pall->ptinfo.pti_pageins, 0, "PROC_PIDTASKALLINFO returned valid value for pti_pageins");
	if (pall->ptinfo.pti_pageins > 0) {
		T_LOG("WARN: PROC_PIDTASKALLINFO returned pageins greater than 0");
	}
	T_EXPECT_GE_INT(pall->ptinfo.pti_csw, p_task_info->pti_csw, "PROC_PIDTASKALLINFO returned valid value for pti_csw");

	free_proc_info(proc_info, 4);
}

T_DECL(proc_info_proc_pidlistthreads,
    "Test to verify PROC_PIDLISTTHREADS returns valid information about process",
    T_META_ASROOT(true))
{
	void * proc_info[1];
	proc_info_caller(THREAD_ADDR, proc_info, NULL);
}

T_DECL(proc_info_proc_pidthreadinfo,
    "Test to verify PROC_PIDTHREADINFO returns valid information about the process",
    T_META_ASROOT(true))
{
	void * proc_info[2];
	int child_pid = 0;
	proc_info_caller(PTHINFO_OLD | PTHINFO, proc_info, &child_pid);
	struct proc_threadinfo * pthinfo_old = (struct proc_threadinfo *)proc_info[0];
	struct proc_threadinfo * pthinfo     = (struct proc_threadinfo *)proc_info[1];

	T_EXPECT_GT_ULLONG((pthinfo->pth_user_time - pthinfo_old->pth_user_time), 0ULL,
	    "PROC_PIDTHREADINFO returns valid value for pth_user_time");
	T_EXPECT_GE_ULLONG((pthinfo->pth_system_time - pthinfo_old->pth_system_time), 0ULL,
	    "PROC_PIDTHREADINFO returns valid value for pth_system_time");
	/*
	 * This is the scaled cpu usage percentage, since we are not
	 * doing a really long CPU bound task, it is (nearly) zero
	 */
	T_EXPECT_GE_INT(pthinfo->pth_cpu_usage, 0, "PROC_PIDTHREADINFO returns valid value for pth_cpu_usage");
	T_EXPECT_EQ_INT(pthinfo->pth_policy, POLICY_TIMESHARE, "PROC_PIDTHREADINFO returns valid value for pth_policy");
	if (!(pthinfo->pth_run_state == TH_STATE_WAITING) && !(pthinfo->pth_run_state == TH_STATE_RUNNING)) {
		T_EXPECT_EQ_INT(pthinfo->pth_run_state, -1, "PROC_PIDTHREADINFO returns valid value for pth_run_state");
	}
	/*
	 * This value is hardcoded to 0 in the source, hence it will always
	 * unconditionally return 0
	 */
	T_EXPECT_EQ_INT(pthinfo->pth_sleep_time, 0, "PROC_PIDTHREADINFO returns valid value for pth_sleep_time");
	T_EXPECT_LE_INT(pthinfo->pth_curpri, (BASEPRI_DEFAULT - CONF_NICE_VAL),
	    "PROC_PIDTHREADINFO returns valid value for pth_curpri");
	T_EXPECT_EQ_INT(pthinfo->pth_priority, (BASEPRI_DEFAULT - CONF_NICE_VAL),
	    "PROC_PIDTHREADINFO returns valid value for pth_priority");
	T_EXPECT_EQ_INT(pthinfo->pth_maxpriority, MAXPRI_USER, "PROC_PIDTHREADINFO returns valid value for pth_maxpriority");
	T_EXPECT_EQ_STR(pthinfo->pth_name, CONF_THREAD_NAME, "PROC_PIDTHREADINFO returns valid value for pth_name");

	free_proc_info(proc_info, 2);
}

T_DECL(proc_info_proc_threadid64info,
    "Test to verify PROC_PIDTHREADID64INFO returns valid information about the process",
    T_META_ASROOT(true))
{
	void * proc_info[2];
	proc_info_caller(PTHINFO | PTHINFO_64, proc_info, NULL);
	struct proc_threadinfo pthinfo    = *((struct proc_threadinfo *)proc_info[0]);
	struct proc_threadinfo pthinfo_64 = *((struct proc_threadinfo *)proc_info[1]);
	T_EXPECT_GE_ULLONG(pthinfo_64.pth_user_time, pthinfo.pth_user_time,
	    "PROC_PIDTHREADID64INFO returns valid value for pth_user_time");
	T_EXPECT_GE_ULLONG(pthinfo_64.pth_system_time, pthinfo.pth_system_time,
	    "PROC_PIDTHREADID64INFO returns valid value for pth_system_time");
	T_EXPECT_GE_INT(pthinfo_64.pth_cpu_usage, pthinfo.pth_cpu_usage,
	    "PROC_PIDTHREADID64INFO returns valid value for pth_cpu_usage");
	T_EXPECT_EQ_INT(pthinfo_64.pth_policy, POLICY_TIMESHARE, "PROC_PIDTHREADID64INFO returns valid value for pth_policy");
	if (!(pthinfo_64.pth_run_state == TH_STATE_WAITING) && !(pthinfo_64.pth_run_state == TH_STATE_RUNNING)) {
		T_EXPECT_EQ_INT(pthinfo_64.pth_run_state, -1, "PROC_PIDTHREADID64INFO returns valid value for pth_run_state");
	}
	T_EXPECT_EQ_INT(pthinfo_64.pth_sleep_time, 0, "PROC_PIDTHREADID64INFO returns valid value for pth_sleep_time");
	T_EXPECT_EQ_INT(pthinfo_64.pth_curpri, pthinfo.pth_curpri, "PROC_PIDTHREADID64INFO returns valid value for pth_curpri");
	T_EXPECT_EQ_INT(pthinfo_64.pth_priority, pthinfo.pth_priority, "PROC_PIDTHREADID64INFO returns valid value for pth_priority");
	T_EXPECT_EQ_INT(pthinfo_64.pth_maxpriority, pthinfo.pth_maxpriority,
	    "PROC_PIDTHREADID64INFO returns valid value for pth_maxpriority");
	T_EXPECT_EQ_STR(pthinfo_64.pth_name, CONF_THREAD_NAME, "PROC_PIDTHREADID64INFO returns valid value for pth_name");

	free_proc_info(proc_info, 2);
}

T_DECL(proc_info_proc_pidthreadpathinfo,
    "Test to verify PROC_PIDTHREADPATHINFO returns valid information about the process",
    T_META_ASROOT(true))
{
	void * proc_info[2];
	proc_info_caller(PTHINFO | PINFO_PATH, proc_info, NULL);
	struct proc_threadinfo pthinfo            = *((struct proc_threadinfo *)proc_info[0]);
	struct proc_threadwithpathinfo pinfo_path = *((struct proc_threadwithpathinfo *)proc_info[1]);

	T_EXPECT_GE_ULLONG(pinfo_path.pt.pth_user_time, pthinfo.pth_user_time,
	    "PROC_PIDTHREADPATHINFO returns valid value for pth_user_time");
	T_EXPECT_GE_ULLONG(pinfo_path.pt.pth_system_time, pthinfo.pth_system_time,
	    "PROC_PIDTHREADPATHINFO returns valid value for pth_system_time");
	T_EXPECT_GE_INT(pinfo_path.pt.pth_cpu_usage, pthinfo.pth_cpu_usage,
	    "PROC_PIDTHREADPATHINFO returns valid value for pth_cpu_usage");
	T_EXPECT_EQ_INT(pinfo_path.pt.pth_policy, POLICY_TIMESHARE, "PROC_PIDTHREADPATHINFO returns valid value for pth_policy");
	if (!(pinfo_path.pt.pth_run_state == TH_STATE_WAITING) && !(pinfo_path.pt.pth_run_state == TH_STATE_RUNNING)) {
		T_EXPECT_EQ_INT(pinfo_path.pt.pth_run_state, -1, "PROC_PIDTHREADPATHINFO returns valid value for pth_run_state");
	}
	T_EXPECT_EQ_INT(pinfo_path.pt.pth_sleep_time, 0, "PROC_PIDTHREADPATHINFO returns valid value for pth_sleep_time");
	T_EXPECT_EQ_INT(pinfo_path.pt.pth_curpri, pthinfo.pth_curpri, "PROC_PIDTHREADPATHINFO returns valid value for pth_curpri");
	T_EXPECT_EQ_INT(pinfo_path.pt.pth_priority, pthinfo.pth_priority,
	    "PROC_PIDTHREADPATHINFO returns valid value for pth_priority");
	T_EXPECT_EQ_INT(pinfo_path.pt.pth_maxpriority, pthinfo.pth_maxpriority,
	    "PROC_PIDTHREADPATHINFO returns valid value for pth_maxpriority");
	T_EXPECT_EQ_STR(pinfo_path.pt.pth_name, CONF_THREAD_NAME, "PROC_PIDTHREADPATHINFO returns valid value for pth_name");
	T_EXPECT_EQ_INT(pinfo_path.pvip.vip_vi.vi_type, VNON, "PROC_PIDTHREADPATHINFO valid vnode information");

	free_proc_info(proc_info, 2);
}

T_DECL(proc_info_proc_pidarchinfo,
    "Test to verify PROC_PIDARCHINFO returns valid information about the process",
    T_META_ASROOT(true))
{
	void * proc_info[1];
	proc_info_caller(PAI, proc_info, NULL);
	struct proc_archinfo pai = *((struct proc_archinfo *)proc_info[0]);

#if defined(__arm__) || defined(__arm64__)
	if (!((pai.p_cputype & CPU_TYPE_ARM) == CPU_TYPE_ARM) && !((pai.p_cputype & CPU_TYPE_ARM64) == CPU_TYPE_ARM64)) {
		T_EXPECT_EQ_INT(pai.p_cputype, CPU_TYPE_ARM, "PROC_PIDARCHINFO returned valid value for p_cputype");
	}
	T_EXPECT_EQ_INT((pai.p_cpusubtype & CPU_SUBTYPE_ARM_ALL), CPU_SUBTYPE_ARM_ALL,
	    "PROC_PIDARCHINFO returned valid value for p_cpusubtype");
#else
	if (!((pai.p_cputype & CPU_TYPE_X86) == CPU_TYPE_X86) && !((pai.p_cputype & CPU_TYPE_X86_64) == CPU_TYPE_X86_64)) {
		T_EXPECT_EQ_INT(pai.p_cputype, CPU_TYPE_X86, "PROC_PIDARCHINFO returned valid value for p_cputype");
	}
#endif
	free_proc_info(proc_info, 1);
}

T_DECL(proc_info_proc_pidregioninfo,
    "Test to verify PROC_PIDREGIONINFO returns valid information about the process",
    T_META_ASROOT(true))
{
	void * proc_info[3];
	proc_info_caller(PREGINFO, proc_info, NULL);

	struct proc_regioninfo preginfo = *((struct proc_regioninfo *)proc_info[0]);
	/*
	 *	map_tmp isn't a struct like the rest of our ret_structs, but we sneak it back because we need it
	 */
	void *map_tmp = proc_info[1];
	vm_map_size_t map_tmp_sz = (vm_map_size_t)(uintptr_t)proc_info[2];

	T_EXPECT_EQ_ULLONG(preginfo.pri_offset, (unsigned long long)PAGE_SIZE, "PROC_PIDREGIONINFO returns valid value for pri_offset");
	T_EXPECT_EQ_UINT((preginfo.pri_protection ^ (VM_PROT_READ | VM_PROT_WRITE)), 0U,
	    "PROC_PIDREGIONINFO returns valid value for pri_protection, expected read/write only");
	T_EXPECT_EQ_UINT((preginfo.pri_max_protection & (VM_PROT_READ | VM_PROT_WRITE)), (unsigned int)(VM_PROT_READ | VM_PROT_WRITE),
	    "PROC_PIDREGIONINFO returns valid value for pri_max_protection");
	T_EXPECT_EQ_UINT((preginfo.pri_inheritance ^ VM_INHERIT_COPY), 0U,
	    "PROC_PIDREGIONINFO returns valid value for pri_inheritance");
	T_EXPECT_EQ_UINT((preginfo.pri_behavior ^ VM_BEHAVIOR_DEFAULT), 0U, "PROC_PIDREGIONINFO returns valid value for pri_behavior");
	T_EXPECT_EQ_UINT(preginfo.pri_user_wired_count, 0U, "PROC_PIDREGIONINFO returns valid value for pri_user_wired_count");
	T_EXPECT_EQ_UINT(preginfo.pri_user_tag, 0U, "PROC_PIDREGIONINFO returns valid value for pri_user_tag");
	T_EXPECT_NE_UINT((preginfo.pri_flags ^ (PROC_REGION_SUBMAP | PROC_REGION_SHARED)), 0U,
	    "PROC_PIDREGIONINFO returns valid value for pri_flags");
	T_EXPECT_EQ_UINT(preginfo.pri_pages_resident, 0U, "PROC_PIDREGIONINFO returns valid value for pri_pages_resident");
	T_EXPECT_EQ_UINT(preginfo.pri_pages_shared_now_private, 0U,
	    "PROC_PIDREGIONINFO returns valid value for pri_pages_shared_now_private");
	T_EXPECT_EQ_UINT(preginfo.pri_pages_swapped_out, 0U, "PROC_PIDREGIONINFO returns valid value for pri_pages_swapped_out");
	T_EXPECT_EQ_UINT(preginfo.pri_pages_dirtied, 0U, "PROC_PIDREGIONINFO returns valid value for pri_pages_dirtied");
	T_EXPECT_EQ_UINT(preginfo.pri_ref_count, 2U, "PROC_PIDREGIONINFO returns valid value for pri_ref_count");
	T_EXPECT_EQ_UINT(preginfo.pri_shadow_depth, 1U, "PROC_PIDREGIONINFO returns valid value for pri_shadow_depth");
	T_EXPECT_EQ_UINT(preginfo.pri_share_mode, (unsigned int)SM_COW, "PROC_PIDREGIONINFO returns valid value for pri_share_mode");
	T_EXPECT_EQ_UINT(preginfo.pri_private_pages_resident, 0U,
	    "PROC_PIDREGIONINFO returns valid value for pri_private_pages_resident");
	T_EXPECT_GE_UINT(preginfo.pri_shared_pages_resident, 0U,
	    "PROC_PIDREGIONINFO returns valid value for pri_shared_pages_resident");
	T_EXPECT_EQ_ULLONG(preginfo.pri_address, (uint64_t)map_tmp, "PROC_PIDREGIONINFO returns valid value for pri_addr");
	T_EXPECT_NE_UINT(preginfo.pri_obj_id, 0U, "PROC_PIDREGIONINFO returns valid value for pri_obj_id");
	T_EXPECT_EQ_ULLONG(preginfo.pri_size, (unsigned long long)map_tmp_sz, "PROC_PIDREGIONINFO returns valid value for pri_size");
	T_EXPECT_EQ_UINT(preginfo.pri_depth, 0U, "PROC_PIDREGIONINFO returns valid value for pri_depth");

	int ret = 0;
	ret     = munmap(map_tmp, (size_t)map_tmp_sz);
	T_QUIET;
	T_EXPECT_POSIX_SUCCESS(ret, "munmap of map_tmp");
	free_proc_info(proc_info, 1);
}

T_DECL(proc_info_proc_pidregionpathinfo,
    "Test to verify PROC_PIDREGIONPATHINFO returns valid information about the process",
    T_META_ASROOT(true))
{
	void * proc_info[3];
	proc_info_caller(PREGINFO_PATH, proc_info, NULL);

	struct proc_regionwithpathinfo preginfo_path = *((struct proc_regionwithpathinfo *)proc_info[0]);
	/*
	 *	map_tmp isn't a struct like the rest of our ret_structs, but we sneak it back because we need it
	 */
	void *map_tmp = proc_info[1];
	vm_map_size_t map_tmp_sz = (vm_map_size_t)(uintptr_t)proc_info[2];

	T_EXPECT_EQ_ULLONG(preginfo_path.prp_prinfo.pri_offset, (uint64_t)PAGE_SIZE,
	    "PROC_PIDREGIONPATHINFO returns valid value for pri_offset");
	T_EXPECT_EQ_UINT((preginfo_path.prp_prinfo.pri_protection ^ (VM_PROT_READ | VM_PROT_WRITE)), 0U,
	    "PROC_PIDREGIONPATHINFO returns valid value for pri_protection, expected read/write only");
	T_EXPECT_EQ_UINT((preginfo_path.prp_prinfo.pri_max_protection & (VM_PROT_READ | VM_PROT_WRITE)),
	    (unsigned int)(VM_PROT_READ | VM_PROT_WRITE),
	    "PROC_PIDREGIONPATHINFO returns valid value for pri_max_protection");
	T_EXPECT_EQ_UINT((preginfo_path.prp_prinfo.pri_inheritance ^ VM_INHERIT_COPY), 0U,
	    "PROC_PIDREGIONPATHINFO returns valid value for pri_inheritance");
	T_EXPECT_EQ_UINT((preginfo_path.prp_prinfo.pri_behavior ^ VM_BEHAVIOR_DEFAULT), 0U,
	    "PROC_PIDREGIONPATHINFO returns valid value for pri_behavior");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_user_wired_count, 0U,
	    "PROC_PIDREGIONPATHINFO returns valid value for pri_user_wired_count");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_user_tag, 0U, "PROC_PIDREGIONPATHINFO returns valid value for pri_user_tag");
	T_EXPECT_NE_UINT((preginfo_path.prp_prinfo.pri_flags ^ (PROC_REGION_SUBMAP | PROC_REGION_SHARED)), 0U,
	    "PROC_PIDREGIONPATHINFO returns valid value for pri_flags");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_pages_resident, 0U,
	    "PROC_PIDREGIONPATHINFO returns valid value for pri_pages_resident");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_pages_shared_now_private, 0U,
	    "PROC_PIDREGIONPATHINFO returns valid value for pri_pages_shared_now_private");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_pages_swapped_out, 0U,
	    "PROC_PIDREGIONPATHINFO returns valid value for pri_pages_swapped_out");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_pages_dirtied, 0U,
	    "PROC_PIDREGIONPATHINFO returns valid value for pri_pages_dirtied");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_ref_count, 2U, "PROC_PIDREGIONPATHINFO returns valid value for pri_ref_count");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_shadow_depth, 1U,
	    "PROC_PIDREGIONPATHINFO returns valid value for pri_shadow_depth");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_share_mode, (unsigned int)SM_COW,
	    "PROC_PIDREGIONPATHINFO returns valid value for pri_share_mode");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_private_pages_resident, 0U,
	    "PROC_PIDREGIONPATHINFO returns valid value for pri_private_pages_resident");
	T_EXPECT_GE_UINT(preginfo_path.prp_prinfo.pri_shared_pages_resident, 0U,
	    "PROC_PIDREGIONPATHINFO returns valid value for pri_shared_pages_resident");
	T_EXPECT_EQ_ULLONG(preginfo_path.prp_prinfo.pri_address, (uint64_t)map_tmp,
	    "PROC_PIDREGIONPATHINFO returns valid value for pri_addr");
	T_EXPECT_NE_UINT(preginfo_path.prp_prinfo.pri_obj_id, 0U, "PROC_PIDREGIONPATHINFO returns valid value for pri_obj_id");
	T_EXPECT_EQ_ULLONG(preginfo_path.prp_prinfo.pri_size, (uint64_t)map_tmp_sz,
	    "PROC_PIDREGIONPATHINFO returns valid value for pri_size");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_depth, 0U, "PROC_PIDREGIONPATHINFO returns valid value for pri_depth");
	T_EXPECT_EQ_INT(preginfo_path.prp_vip.vip_vi.vi_type, VREG, "PROC_PIDREGIONPATHINFO returns valid value for vi_type");
	T_EXPECT_EQ_INT(preginfo_path.prp_vip.vip_vi.vi_pad, 0, "PROC_PIDREGIONPATHINFO returns valid value for vi_pad");
	T_EXPECT_NE_INT(preginfo_path.prp_vip.vip_vi.vi_fsid.val[0], 0,
	    "PROC_PIDREGIONPATHINFO returns valid value for vi_fsid.val[0]");
	T_EXPECT_NE_INT(preginfo_path.prp_vip.vip_vi.vi_fsid.val[1], 0,
	    "PROC_PIDREGIONPATHINFO returns valid value for vi_fsid.val[1]");
	T_EXPECT_NE_PTR((void *)(strcasestr(preginfo_path.prp_vip.vip_path, CONF_TMP_FILE_PFX)), NULL,
	    "PROC_PIDREGIONPATHINFO returns valid value for vi_path");
	/*
	 * Basic sanity checks for vnode stat returned by the API
	 */
	T_EXPECT_NE_UINT(preginfo_path.prp_vip.vip_vi.vi_stat.vst_dev, 0U, "PROC_PIDREGIONPATHINFO returns valid value for vst_dev");
	T_EXPECT_EQ_INT(((preginfo_path.prp_vip.vip_vi.vi_stat.vst_mode & S_IFMT) ^ S_IFREG), 0,
	    "PROC_PIDREGIONPATHINFO returns valid value for vst_mode");
	T_EXPECT_EQ_USHORT(preginfo_path.prp_vip.vip_vi.vi_stat.vst_nlink, (unsigned short)0, /* the file was unlink()'d! */
	    "PROC_PIDREGIONPATHINFO returns valid value for vst_nlink");
	T_EXPECT_NE_ULLONG(preginfo_path.prp_vip.vip_vi.vi_stat.vst_ino, 0ULL,
	    "PROC_PIDREGIONPATHINFO returns valid value for vst_ino");
	T_EXPECT_EQ_UINT(preginfo_path.prp_vip.vip_vi.vi_stat.vst_uid, 0U, "PROC_PIDREGIONPATHINFO returns valid value for vst_uid");
	T_EXPECT_EQ_UINT(preginfo_path.prp_vip.vip_vi.vi_stat.vst_gid, 0U, "PROC_PIDREGIONPATHINFO returns valid value for vst_gid");
	T_EXPECT_GE_LLONG(preginfo_path.prp_vip.vip_vi.vi_stat.vst_size, (off_t)CONF_BLK_SIZE,
	    "PROC_PIDREGIONPATHINFO returns valid value for vst_size");
	T_EXPECT_GE_LLONG(preginfo_path.prp_vip.vip_vi.vi_stat.vst_blocks, 1LL,
	    "PROC_PIDREGIONPATHINFO returns valid value for vst_blocks");
	T_EXPECT_GE_INT(preginfo_path.prp_vip.vip_vi.vi_stat.vst_blksize, CONF_BLK_SIZE,
	    "PROC_PIDREGIONPATHINFO returns valid value for vst_blksize");

	int ret = 0;
	ret     = munmap(map_tmp, (size_t)map_tmp_sz);
	T_QUIET;
	T_EXPECT_POSIX_SUCCESS(ret, "munmap of map_tmp");
	free_proc_info(proc_info, 1);
}

T_DECL(proc_info_proc_pidregionpathinfo2,
    "Test to verify PROC_PIDREGIONPATHINFO2 returns valid information about the process",
    T_META_ASROOT(true))
{
	void * proc_info[3];
	proc_info_caller(PREGINFO_PATH_2, proc_info, NULL);

	struct proc_regionwithpathinfo preginfo_path = *((struct proc_regionwithpathinfo *)proc_info[0]);
	/*
	 *	map_tmp isn't a struct like the rest of our ret_structs, but we sneak it back because we need it
	 */
	void *map_tmp = proc_info[1];
	vm_map_size_t map_tmp_sz = (vm_map_size_t)(uintptr_t)proc_info[2];

	T_EXPECT_EQ_ULLONG(preginfo_path.prp_prinfo.pri_offset, (uint64_t)PAGE_SIZE,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for pri_offset");
	T_EXPECT_EQ_UINT((preginfo_path.prp_prinfo.pri_protection ^ (VM_PROT_READ | VM_PROT_WRITE)), 0U,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for pri_protection, expected read/write only");
	T_EXPECT_EQ_UINT((preginfo_path.prp_prinfo.pri_max_protection & (VM_PROT_READ | VM_PROT_WRITE)),
	    (unsigned int)(VM_PROT_READ | VM_PROT_WRITE),
	    "PROC_PIDREGIONPATHINFO2 returns valid value for pri_max_protection");
	T_EXPECT_EQ_UINT((preginfo_path.prp_prinfo.pri_inheritance ^ VM_INHERIT_COPY), 0U,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for pri_inheritance");
	T_EXPECT_EQ_UINT((preginfo_path.prp_prinfo.pri_behavior ^ VM_BEHAVIOR_DEFAULT), 0U,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for pri_behavior");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_user_wired_count, 0U,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for pri_user_wired_count");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_user_tag, 0U, "PROC_PIDREGIONPATHINFO2 returns valid value for pri_user_tag");
	T_EXPECT_NE_UINT((preginfo_path.prp_prinfo.pri_flags ^ (PROC_REGION_SUBMAP | PROC_REGION_SHARED)), 0U,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for pri_flags");
	/*
	 * Following values are hard-coded to be zero in source
	 */
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_pages_resident, 0U,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for pri_pages_resident");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_pages_shared_now_private, 0U,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for pri_pages_shared_now_private");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_pages_swapped_out, 0U,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for pri_pages_swapped_out");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_pages_dirtied, 0U,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for pri_pages_dirtied");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_ref_count, 0U, "PROC_PIDREGIONPATHINFO2 returns valid value for pri_ref_count");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_shadow_depth, 0U,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for pri_shadow_depth");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_share_mode, 0U, "PROC_PIDREGIONPATHINFO2 returns valid value for pri_share_mode");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_private_pages_resident, 0U,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for pri_private_pages_resident");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_shared_pages_resident, 0U,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for pri_shared_pages_resident");
	T_EXPECT_EQ_ULLONG(preginfo_path.prp_prinfo.pri_address, (uint64_t)map_tmp,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for pri_addr");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_obj_id, 0U, "PROC_PIDREGIONPATHINFO2 returns valid value for pri_obj_id");
	T_EXPECT_EQ_ULLONG(preginfo_path.prp_prinfo.pri_size, (unsigned long long)map_tmp_sz,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for pri_size");
	T_EXPECT_EQ_UINT(preginfo_path.prp_prinfo.pri_depth, 0U, "PROC_PIDREGIONPATHINFO2 returns valid value for pri_depth");

	T_EXPECT_EQ_INT(preginfo_path.prp_vip.vip_vi.vi_type, VREG, "PROC_PIDREGIONPATHINFO2 returns valid value for vi_type");
	T_EXPECT_EQ_INT(preginfo_path.prp_vip.vip_vi.vi_pad, 0, "PROC_PIDREGIONPATHINFO2 returns valid value for vi_pad");
	T_EXPECT_NE_INT(preginfo_path.prp_vip.vip_vi.vi_fsid.val[0], 0,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for vi_fsid.val[0]:%d",
	    preginfo_path.prp_vip.vip_vi.vi_fsid.val[0]);
	T_EXPECT_NE_INT(preginfo_path.prp_vip.vip_vi.vi_fsid.val[1], 0,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for vi_fsid.val[1]:%d",
	    preginfo_path.prp_vip.vip_vi.vi_fsid.val[1]);
	T_EXPECT_NE_PTR((void *)(strcasestr(preginfo_path.prp_vip.vip_path, CONF_TMP_FILE_PFX)), NULL,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for vi_path");
	/*
	 * Basic sanity checks for vnode stat returned by the API
	 */
	T_EXPECT_NE_UINT(preginfo_path.prp_vip.vip_vi.vi_stat.vst_dev, 0U, "PROC_PIDREGIONPATHINFO2 returns valid value for vst_dev");
	T_EXPECT_EQ_UINT(((preginfo_path.prp_vip.vip_vi.vi_stat.vst_mode & S_IFMT) ^ S_IFREG), 0,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for vst_mode");
	T_EXPECT_EQ_USHORT(preginfo_path.prp_vip.vip_vi.vi_stat.vst_nlink, (unsigned short)0, /* the file was unlink()'d! */
	    "PROC_PIDREGIONPATHINFO2 returns valid value for vst_nlink");
	T_EXPECT_NE_ULLONG(preginfo_path.prp_vip.vip_vi.vi_stat.vst_ino, 0ULL,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for vst_ino");
	T_EXPECT_EQ_UINT(preginfo_path.prp_vip.vip_vi.vi_stat.vst_uid, 0U, "PROC_PIDREGIONPATHINFO2 returns valid value for vst_uid");
	T_EXPECT_EQ_UINT(preginfo_path.prp_vip.vip_vi.vi_stat.vst_gid, 0U, "PROC_PIDREGIONPATHINFO2 returns valid value for vst_gid");
	T_EXPECT_GE_LLONG(preginfo_path.prp_vip.vip_vi.vi_stat.vst_size, (off_t)CONF_BLK_SIZE,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for vst_size");
	T_EXPECT_GE_LLONG(preginfo_path.prp_vip.vip_vi.vi_stat.vst_blocks, 1LL,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for vst_blocks");
	T_EXPECT_GE_UINT(preginfo_path.prp_vip.vip_vi.vi_stat.vst_blksize, CONF_BLK_SIZE,
	    "PROC_PIDREGIONPATHINFO2 returns valid value for vst_blksize");

	int ret = 0;
	ret     = munmap(map_tmp, (size_t)map_tmp_sz);
	T_QUIET;
	T_EXPECT_POSIX_SUCCESS(ret, "munmap of map_tmp");
	free_proc_info(proc_info, 1);
}

T_DECL(proc_info_proc_pidregionpathinfo3,
    "Test to verify PROC_PIDREGIONPATHINFO3 returns valid information about the process",
    T_META_ASROOT(true))
{
	void * proc_info[5];
	proc_info_caller(PREGINFO_PATH_3, proc_info, NULL);

	struct proc_regionwithpathinfo preginfo_path = *((struct proc_regionwithpathinfo *)proc_info[0]);
	void *map_tmp = proc_info[1];
	vm_map_size_t map_tmp_sz = (vm_map_size_t)(uintptr_t)proc_info[2];

	/* The *info3 version of this call returns any open file that lives on the same file system */
	T_EXPECT_EQ_INT(preginfo_path.prp_vip.vip_vi.vi_fsid.val[0], (int)(uintptr_t)proc_info[3],
	    "PROC_PIDREGIONPATHINFO3 returns valid value for vi_fsid.val[0]");
	T_EXPECT_EQ_INT(preginfo_path.prp_vip.vip_vi.vi_fsid.val[1], (int)(uintptr_t)proc_info[4],
	    "PROC_PIDREGIONPATHINFO3 returns valid value for vi_fsid.val[1]");

	int ret = 0;
	ret     = munmap(map_tmp, (size_t)map_tmp_sz);
	T_QUIET;
	T_EXPECT_POSIX_SUCCESS(ret, "munmap of map_tmp");
	free_proc_info(proc_info, 1);
}

T_DECL(proc_info_proc_pidvnodepathinfo,
    "Test to verify PROC_PIDVNODEPATHINFO returns valid information about the process",
    T_META_ASROOT(true))
{
	void * proc_info[1];
	proc_info_caller(PVNINFO, proc_info, NULL);
	struct proc_vnodepathinfo pvninfo = *((struct proc_vnodepathinfo *)proc_info[0]);

	T_EXPECT_EQ_INT(pvninfo.pvi_cdir.vip_vi.vi_type, VDIR, "PROC_PIDVNODEPATHINFO returns valid value for vi_type");
	T_EXPECT_EQ_INT(pvninfo.pvi_cdir.vip_vi.vi_pad, 0, "PROC_PIDVNODEPATHINFO returns valid value for vi_pad");
	T_EXPECT_NE_INT(pvninfo.pvi_cdir.vip_vi.vi_fsid.val[0], 0, "PROC_PIDVNODEPATHINFO returns valid value for vi_fsid.val[0]");
	T_EXPECT_NE_INT(pvninfo.pvi_cdir.vip_vi.vi_fsid.val[1], 0, "PROC_PIDVNODEPATHINFO returns valid value for vi_fsid.val[1]");
	/*
	 * Basic sanity checks for vnode stat returned by the API
	 */
	T_EXPECT_NE_UINT(pvninfo.pvi_cdir.vip_vi.vi_stat.vst_dev, 0U, "PROC_PIDVNODEPATHINFO returns valid value for vst_dev");
	T_EXPECT_EQ_INT(((pvninfo.pvi_cdir.vip_vi.vi_stat.vst_mode & S_IFMT) ^ S_IFDIR), 0,
	    "PROC_PIDVNODEPATHINFO returns valid value for vst_mode");
	T_EXPECT_GE_USHORT(pvninfo.pvi_cdir.vip_vi.vi_stat.vst_nlink, (unsigned short)2,
	    "PROC_PIDVNODEPATHINFO returns valid value for vst_nlink");
	T_EXPECT_NE_ULLONG(pvninfo.pvi_cdir.vip_vi.vi_stat.vst_ino, 0ULL, "PROC_PIDVNODEPATHINFO returns valid value for vst_ino");
	T_EXPECT_GE_UINT(pvninfo.pvi_cdir.vip_vi.vi_stat.vst_uid, 0U, "PROC_PIDVNODEPATHINFO returns valid value for vst_uid");
	T_EXPECT_GE_UINT(pvninfo.pvi_cdir.vip_vi.vi_stat.vst_gid, 0U, "PROC_PIDVNODEPATHINFO returns valid value for vst_gid");
	T_EXPECT_GT_LLONG(pvninfo.pvi_cdir.vip_vi.vi_stat.vst_size, 0LL, "PROC_PIDVNODEPATHINFO returns valid value for vst_size");
	T_EXPECT_GE_LLONG(pvninfo.pvi_cdir.vip_vi.vi_stat.vst_blocks, 0LL, "PROC_PIDVNODEPATHINFO returns valid value for vst_blocks");
	T_EXPECT_GE_UINT(pvninfo.pvi_cdir.vip_vi.vi_stat.vst_blksize, CONF_BLK_SIZE,
	    "PROC_PIDVNODEPATHINFO returns valid value for vst_blksize");

	free_proc_info(proc_info, 1);
}
/*
 * The remaining tests break from the pattern of the other PROC_INFO_CALL_PIDINFO tests.
 * We call proc_info directly as it's more efficient
 */

T_DECL(proc_info_pidinfo_proc_pidlistfds,
    "proc_info API tests to verify PROC_INFO_CALL_PIDINFO/PROC_PIDLISTFDS",
    T_META_ASROOT(true))
{
	int retval;
	int orig_nfiles              = 0;
	struct proc_fdinfo * fd_info = NULL;

	T_LOG("Test to verify PROC_PIDLISTFDS returns sane number of open files");
	retval      = __proc_info(PROC_INFO_CALL_PIDINFO, getpid(), PROC_PIDLISTFDS, (uint32_t)0, (user_addr_t)0, (uint32_t)0);
	orig_nfiles = retval / (int)sizeof(struct proc_fdinfo);
	T_EXPECT_GE_INT(orig_nfiles, CONF_OPN_FILE_COUNT, "The number of open files is lower than expected.");

	/*
	 * Allocate a buffer of expected size + 1 to ensure that
	 * the API still returns expected size
	 * i.e. 3 + 1 = 4 open fds
	 */
	T_LOG("Test to verify PROC_PIDLISTFDS returns valid fd information");
	fd_info = malloc(sizeof(*fd_info) * 5);
	tmp_fd = CONF_TMP_FILE_OPEN(NULL);
	T_LOG("tmp_fd val:%d", tmp_fd);
	T_QUIET;
	T_EXPECT_POSIX_SUCCESS(tmp_fd, "open() for PROC_PIDLISTFDS");

	retval = __proc_info(PROC_INFO_CALL_PIDINFO, getpid(), PROC_PIDLISTFDS, (uint32_t)0, (user_addr_t)fd_info,
	    (uint32_t)(sizeof(*fd_info) * 5));
	retval = retval / (int)sizeof(struct proc_fdinfo);

	close(tmp_fd);

	for (int i = 0; i < retval; i++) {
		/*
		 * Check only for the fd that we control.
		 */
		if (tmp_fd != fd_info[i].proc_fd) {
			continue;
		}
		T_EXPECT_EQ_UINT(fd_info[i].proc_fdtype, (unsigned int)PROX_FDTYPE_VNODE, "Correct proc_fdtype for returned fd");
	}

	T_EXPECT_GE_INT(retval, 4, "Correct number of fds was returned.");

	tmp_fd = -1;
	free(fd_info);
	fd_info = NULL;
}

T_DECL(proc_info_proc_pidpathinfo,
    "Test to verify PROC_PIDPATHINFO returns valid information about the process",
    T_META_ASROOT(true))
{
	char * pid_path = NULL;
	pid_path        = malloc(sizeof(char) * PROC_PIDPATHINFO_MAXSIZE);
	T_EXPECT_NOTNULL(pid_path, "malloc for PROC_PIDPATHINFO");
	int retval = __proc_info(PROC_INFO_CALL_PIDINFO, getpid(), PROC_PIDPATHINFO, (uint64_t)0, (user_addr_t)pid_path,
	    (uint32_t)PROC_PIDPATHINFO_MAXSIZE);
	T_EXPECT_EQ_INT(retval, 0, "__proc_info call for PROC_PIDPATHINFO");

	T_EXPECT_NE_PTR((void *)(strcasestr(pid_path, CONF_CMD_NAME)), NULL, "PROC_PIDPATHINFOreturns valid value for pid_path");
	free(pid_path);
	pid_path = NULL;
}

T_DECL(proc_info_proc_pidlistfileports,
    "Test to verify PROC_PIDLISTFILEPORTS returns valid information about the process",
    T_META_ASROOT(true))
{
	struct proc_fileportinfo * fileport_info = NULL;
	mach_port_t tmp_file_port                = MACH_PORT_NULL;
	proc_config_t proc_config                = spawn_child_processes(1, proc_info_call_pidinfo_handler);
	int child_pid                            = proc_config->child_pids[0];

	/*
	 * Create a file port
	 */
	tmp_fd     = CONF_TMP_FILE_OPEN(NULL);
	int retval = fileport_makeport(tmp_fd, &tmp_file_port);
	T_EXPECT_POSIX_SUCCESS(retval, "fileport_makeport() for PROC_PIDLISTFILEPORTS");

	/*
	 * Like the other APIs, this returns the actual count + 20. Hence we expect it to be atleast 1 (that we created)
	 */
	retval = __proc_info(PROC_INFO_CALL_PIDINFO, getpid(), PROC_PIDLISTFILEPORTS, (uint64_t)0, (user_addr_t)0, (uint32_t)0);
	T_EXPECT_GE_INT(retval / (int)sizeof(fileport_info), 1,
	    "__proc_info call for PROC_PIDLISTFILEPORTS to get total ports in parent");

	/*
	 * Child doesn't have any fileports, should return zero
	 */
	retval = __proc_info(PROC_INFO_CALL_PIDINFO, child_pid, PROC_PIDLISTFILEPORTS, (uint64_t)0, (user_addr_t)0, (uint32_t)0);
	T_EXPECT_EQ_INT(retval / (int)sizeof(fileport_info), 0,
	    "__proc_info call for PROC_PIDLISTFILEPORTS to get total ports in child");

	fileport_info = malloc(sizeof(*fileport_info) * (size_t)retval);
	retval        = __proc_info(PROC_INFO_CALL_PIDINFO, getpid(), PROC_PIDLISTFILEPORTS, (uint64_t)0, (user_addr_t)fileport_info,
	    (uint32_t)sizeof(*fileport_info));
	T_EXPECT_EQ_INT(retval, (int)sizeof(*fileport_info), "__proc_info call for PROC_PIDLISTFILEPORTS");

	T_EXPECT_NE_UINT(fileport_info->proc_fileport, (uint32_t)0, "PROC_PIDLISTFILEPORTS returns valid value for proc_fileport");
	T_EXPECT_EQ_UINT(fileport_info->proc_fdtype, (uint32_t)PROX_FDTYPE_VNODE,
	    "PROC_PIDLISTFILEPORTS returns valid value for proc_fdtype");

	/*
	 * Cleanup for the fileport
	 */
	mach_port_deallocate(mach_task_self(), tmp_file_port);
	tmp_file_port = MACH_PORT_NULL;
	free(fileport_info);
	fileport_info = NULL;
	close(tmp_fd);
	tmp_fd = -1;
	free_proc_config(proc_config);
}

T_DECL(proc_info_proc_pidcoalitioninfo,
    "Test to verify PROC_PIDCOALITIONINFO returns valid information about the process",
    T_META_ASROOT(true))
{
	proc_config_t proc_config = spawn_child_processes(1, proc_info_call_pidinfo_handler);
	int child_pid             = proc_config->child_pids[0];

	struct proc_pidcoalitioninfo pci_parent;
	struct proc_pidcoalitioninfo pci_child;
	int retval = __proc_info(PROC_INFO_CALL_PIDINFO, getpid(), PROC_PIDCOALITIONINFO, (uint64_t)0, (user_addr_t)&pci_parent,
	    (uint32_t)sizeof(pci_parent));
	T_EXPECT_EQ_INT(retval, (int)sizeof(pci_parent), "__proc_info call for PROC_PIDCOALITIONINFO (parent)");
	retval = __proc_info(PROC_INFO_CALL_PIDINFO, child_pid, PROC_PIDCOALITIONINFO, (uint64_t)0, (user_addr_t)&pci_child,
	    (uint32_t)sizeof(pci_child));
	T_EXPECT_EQ_INT(retval, (int)sizeof(pci_child), "__proc_info call for PROC_PIDCOALITIONINFO (child)");

	/*
	 * Coalition IDs should match for child and parent
	 */
	for (int i = 0; i < COALITION_NUM_TYPES; i++) {
		T_EXPECT_EQ_ULLONG(pci_parent.coalition_id[i], pci_child.coalition_id[i],
		    "PROC_PIDCOALITIONINFO returns valid value for coalition_id");
	}

	free_proc_config(proc_config);
}

T_DECL(proc_info_proc_pidworkqueueinfo,
    "Test to verify PROC_PIDWORKQUEUEINFO returns valid information about the process",
    T_META_ASROOT(true))
{
	proc_config_t proc_config = spawn_child_processes(1, proc_info_call_pidinfo_handler);
	int child_pid             = proc_config->child_pids[0];
	send_action_to_child_processes(proc_config, ACT_PHASE5);

	struct proc_workqueueinfo pwqinfo;
	usleep(10000);
	int retval = __proc_info(PROC_INFO_CALL_PIDINFO, child_pid, PROC_PIDWORKQUEUEINFO, (uint64_t)0, (user_addr_t)&pwqinfo,
	    (uint32_t)sizeof(pwqinfo));
	T_EXPECT_EQ_INT(retval, (int)sizeof(pwqinfo), "__proc_info call for PROC_PIDWORKQUEUEINFO");

	int ncpu         = 0;
	size_t ncpu_size = sizeof(ncpu);
	retval           = sysctlbyname("hw.ncpu", (void *)&ncpu, &ncpu_size, NULL, 0);
	T_EXPECT_EQ_INT(retval, 0, "sysctl() for PROC_PIDWORKQUEUEINFO");
	T_EXPECT_GE_UINT(pwqinfo.pwq_nthreads, (uint32_t)1, "PROC_PIDWORKQUEUEINFO returns valid value for pwq_nthreads");
	T_EXPECT_GE_UINT(pwqinfo.pwq_blockedthreads + pwqinfo.pwq_runthreads, (uint32_t)1,
	    "PROC_PIDWORKQUEUEINFO returns valid value for pwqinfo.pwq_runthreads/pwq_blockedthreads");
	T_EXPECT_EQ_UINT(pwqinfo.pwq_state, (uint32_t)0, "PROC_PIDWORKQUEUEINFO returns valid value for pwq_state");

	kill_child_processes(proc_config);
	free_proc_config(proc_config);
}
T_DECL(proc_info_proc_pidnoteexit,
    "Test to verify PROC_PIDNOTEEXIT returns valid information about the process",
    T_META_ASROOT(true))
{
	/*
	 * Ask the child to close pipe and quit, cleanup pipes for parent
	 */
	proc_config_t proc_config = spawn_child_processes(1, proc_info_call_pidinfo_handler);
	int child_pid             = proc_config->child_pids[0];
	send_action_to_child_processes(proc_config, ACT_EXIT);

	uint32_t exit_data = 0;
	int retval = __proc_info(PROC_INFO_CALL_PIDINFO, child_pid, PROC_PIDNOTEEXIT, (uint64_t)(NOTE_EXITSTATUS | NOTE_EXIT_DETAIL),
	    (user_addr_t)&exit_data, (uint32_t)sizeof(exit_data));
	T_EXPECT_EQ_INT(retval, (int)sizeof(exit_data), "__proc_info call for PROC_PIDNOTEEXIT");

	T_EXPECT_EQ_UINT(exit_data, 0U, "PROC_PIDNOTEEXIT returned valid value for exit_data");

	free_proc_config(proc_config);
}

T_DECL(proc_info_negative_tests,
    "Test to validate PROC_INFO_CALL_PIDINFO for invalid arguments",
    T_META_ASROOT(true))
{
	proc_config_t proc_config = spawn_child_processes(1, proc_info_call_pidinfo_handler);
	int child_pid             = proc_config->child_pids[0];
	uint32_t exit_data        = 0;

	int retval =
	    __proc_info(PROC_INFO_CALL_PIDINFO, child_pid, PROC_PIDNOTEEXIT, (uint64_t)0, (user_addr_t)&exit_data, (uint32_t)0);
	T_EXPECT_EQ_INT(errno, ENOMEM, "PROC_INFO_CALL_PIDINFO call should fail with ENOMEM if buffersize is zero");
	retval = __proc_info(PROC_INFO_CALL_PIDINFO, child_pid, PROC_PIDPATHINFO, (uint64_t)0, (user_addr_t)&exit_data,
	    (uint32_t)PROC_PIDPATHINFO_MAXSIZE + 1);
	T_EXPECT_EQ_INT(errno, EOVERFLOW,
	    "PROC_INFO_CALL_PIDINFO call should fail with EOVERFLOW if buffersize is larger than PROC_PIDPATHINFO_MAXSIZE");
	retval = __proc_info(PROC_INFO_CALL_PIDINFO, -1, PROC_PIDNOTEEXIT, (uint64_t)0, (user_addr_t)&exit_data,
	    (uint32_t)sizeof(exit_data));
	T_EXPECT_EQ_INT(errno, ESRCH, "PROC_INFO_CALL_PIDINFO call should fail with ESRCH for invalid process id");
	retval = __proc_info(PROC_INFO_CALL_PIDINFO, child_pid, -1U, (uint64_t)0, (user_addr_t)&exit_data, (uint32_t)sizeof(exit_data));
	T_EXPECT_EQ_INT(errno, EINVAL, "PROC_INFO_CALL_PIDINFO call should fail with EINVAL for invalid flavor");
	retval = __proc_info(PROC_INFO_CALL_PIDINFO, 0, PROC_PIDWORKQUEUEINFO, (uint64_t)0, (user_addr_t)0, (uint32_t)0);
	T_EXPECT_EQ_INT(errno, EINVAL,
	    "PROC_INFO_CALL_PIDINFO call should fail with EINVAL if flavor is PROC_PIDWORKQUEUEINFO and pid=0");

	free_proc_config(proc_config);
}

/*
 * END PROC_INFO_CALL_PIDINFO DECLs
 */

#pragma mark proc_list_uptrs

#define NUPTRS 4
static uint64_t uptrs[NUPTRS] = {0x1122334455667788ULL, 0x99aabbccddeeff00ULL, 0xaabbaaddccaaffeeULL, 0xcc000011ccaa7755ULL};

static const char * uptr_names[NUPTRS];

static void
print_uptrs(int argc, char * const * argv)
{
	for (int i = 0; i < argc; i++) {
		char * end;
		unsigned long pid = strtoul(argv[i], &end, 0);
		if (pid > INT_MAX) {
			printf("error: pid '%lu' would overflow an integer\n", pid);
		}
		if (end == argv[i]) {
			printf("error: could not parse '%s' as a pid\n", argv[i]);
			continue;
		}
		int uptrs_count = proc_list_uptrs((int)pid, NULL, 0);
		if (uptrs_count == 0) {
			printf("no uptrs for process %d\n", (int)pid);
			return;
		}

		/* extra space */
		unsigned int uptrs_len = (unsigned int)uptrs_count + 32;

		uint64_t * uptrs_alloc = malloc(sizeof(uint64_t) * uptrs_len);
		os_assert(uptrs_alloc != NULL);

		uptrs_count = proc_list_uptrs((int)pid, uptrs_alloc, (uint32_t)(sizeof(uint64_t) * uptrs_len));
		printf("process %d has %d uptrs:\n", (int)pid, uptrs_count);
		if (uptrs_count > (int)uptrs_len) {
			uptrs_count = (int)uptrs_len;
		}
		for (int j = 0; j < uptrs_count; j++) {
			printf("%#17" PRIx64 "\n", uptrs_alloc[j]);
		}
	}
}

T_DECL(proc_list_uptrs, "the kernel should return any up-pointers it knows about")
{
	if (argc > 0) {
		print_uptrs(argc, argv);
		T_SKIP("command line invocation of tool, not test");
	}

	unsigned int cur_uptr = 0;

	int kq = kqueue();
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(kq, "kqueue");

	/*
	 * Should find uptrs on file-type knotes and generic knotes (two
	 * different search locations, internally).
	 */
	struct kevent64_s events[2];
	memset(events, 0, sizeof(events));

	uptr_names[cur_uptr] = "kqueue file-backed knote";
	events[0].filter     = EVFILT_WRITE;
	events[0].ident      = STDOUT_FILENO;
	events[0].flags      = EV_ADD;
	events[0].udata      = uptrs[cur_uptr++];

	uptr_names[cur_uptr] = "kqueue non-file-backed knote";
	events[1].filter     = EVFILT_USER;
	events[1].ident      = 1;
	events[1].flags      = EV_ADD;
	events[1].udata      = uptrs[cur_uptr++];

	int kev_err = kevent64(kq, events, sizeof(events) / sizeof(events[0]), NULL, 0, KEVENT_FLAG_IMMEDIATE, NULL);
	T_ASSERT_POSIX_SUCCESS(kev_err, "register events with kevent64");

	/*
	 * Should find uptrs both on a kevent_id kqueue and in a workloop
	 * kqueue's knote's udata field.
	 */
	uptr_names[cur_uptr] = "dynamic kqueue non-file-backed knote";
	struct kevent_qos_s events_id[] = {{
						   .filter = EVFILT_USER,
						   .ident = 1,
						   .flags = EV_ADD,
						   .qos = (int)_pthread_qos_class_encode(QOS_CLASS_DEFAULT, 0, 0),
						   .udata = uptrs[cur_uptr++]
					   }};

	uptr_names[cur_uptr] = "dynamic kqueue ID";
	kev_err = kevent_id(uptrs[cur_uptr++], events_id, 1, NULL, 0, NULL, NULL, KEVENT_FLAG_WORKLOOP | KEVENT_FLAG_IMMEDIATE);
	T_ASSERT_POSIX_SUCCESS(kev_err, "register event with kevent_id");

	errno           = 0;
	int uptrs_count = proc_list_uptrs(getpid(), NULL, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(uptrs_count, "proc_list_uptrs");
	T_QUIET;
	T_EXPECT_EQ(uptrs_count, NUPTRS, "should see correct number of up-pointers");

	uint64_t uptrs_obs[NUPTRS] = {0};
	uptrs_count                = proc_list_uptrs(getpid(), uptrs_obs, sizeof(uptrs_obs));
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(uptrs_count, "proc_list_uptrs");

	for (int i = 0; i < uptrs_count; i++) {
		int found = -1;
		for (int j = 0; j < NUPTRS; j++) {
			if (uptrs_obs[i] == uptrs[j]) {
				found = j;
				goto next;
			}
		}
		T_FAIL("unexpected up-pointer found: %#" PRIx64, uptrs_obs[i]);
next:           ;
		if (found != -1) {
			T_PASS("found up-pointer for %s", uptr_names[found]);
		}
	}

	uint64_t up_overflow[2] = {0};
	uptrs_count = proc_list_uptrs(getpid(), up_overflow, sizeof(uint64_t) + 1);
	T_ASSERT_EQ(up_overflow[1], (uint64_t)0, "overflow check");
}

#pragma mark dynamic kqueue info

#define EXPECTED_ID UINT64_C(0x1122334455667788)
#define EXPECTED_UDATA UINT64_C(0x99aabbccddeeff00)
#ifndef KQ_WORKLOOP
#define KQ_WORKLOOP 0x80
#endif

static void
setup_kevent_id(kqueue_id_t id)
{
	struct kevent_qos_s events_id[] = {{
						   .filter = EVFILT_USER,
						   .ident = 1,
						   .flags = EV_ADD,
						   .qos = (int)_pthread_qos_class_encode(QOS_CLASS_DEFAULT, 0, 0),
						   .udata = EXPECTED_UDATA
					   }};

	int err = kevent_id(id, events_id, 1, NULL, 0, NULL, NULL, KEVENT_FLAG_WORKLOOP | KEVENT_FLAG_IMMEDIATE);
	T_ASSERT_POSIX_SUCCESS(err, "register event with kevent_id");
}

static kqueue_id_t *
list_kqids(pid_t pid, int * nkqids_out)
{
	int kqids_len = 256;
	int nkqids;
	kqueue_id_t * kqids = NULL;
	uint32_t kqids_size;

retry:
	if (os_mul_overflow(sizeof(kqueue_id_t), kqids_len, &kqids_size)) {
		T_QUIET;
		T_ASSERT_GT(kqids_len, PROC_PIDDYNKQUEUES_MAX, NULL);
		kqids_len = PROC_PIDDYNKQUEUES_MAX;
		goto retry;
	}
	if (!kqids) {
		kqids = malloc(kqids_size);
		T_QUIET;
		T_ASSERT_NOTNULL(kqids, "malloc(%" PRIu32 ")", kqids_size);
	}

	nkqids = proc_list_dynkqueueids(pid, kqids, kqids_size);
	if (nkqids > kqids_len && kqids_len < PROC_PIDDYNKQUEUES_MAX) {
		kqids_len *= 2;
		if (kqids_len > PROC_PIDDYNKQUEUES_MAX) {
			kqids_len = PROC_PIDDYNKQUEUES_MAX;
		}
		free(kqids);
		kqids = NULL;
		goto retry;
	}

	*nkqids_out = nkqids;
	return kqids;
}

T_DECL(list_dynamic_kqueues, "the kernel should list IDs of dynamic kqueues", T_META_ALL_VALID_ARCHS(true))
{
	int nkqids;
	bool found = false;

	setup_kevent_id(EXPECTED_ID);
	kqueue_id_t * kqids = list_kqids(getpid(), &nkqids);
	T_ASSERT_GE(nkqids, 1, "at least one dynamic kqueue is listed");
	for (int i = 0; i < nkqids; i++) {
		if (kqids[i] == EXPECTED_ID) {
			found = true;
			T_PASS("found expected dynamic kqueue ID");
		} else {
			T_LOG("found another dynamic kqueue with ID %#" PRIx64, kqids[i]);
		}
	}

	if (!found) {
		T_FAIL("could not find dynamic ID of kqueue created");
	}

	free(kqids);
}

T_DECL(dynamic_kqueue_basic_info, "the kernel should report valid basic dynamic kqueue info", T_META_ALL_VALID_ARCHS(true))
{
	struct kqueue_info kqinfo;
	int ret;

	setup_kevent_id(EXPECTED_ID);
	ret = proc_piddynkqueueinfo(getpid(), PROC_PIDDYNKQUEUE_INFO, EXPECTED_ID, &kqinfo, sizeof(kqinfo));
	T_ASSERT_POSIX_SUCCESS(ret, "proc_piddynkqueueinfo(... PROC_PIDDYNKQUEUE_INFO ...)");
	T_QUIET;
	T_ASSERT_GE(ret, (int)sizeof(kqinfo), "PROC_PIDDYNKQUEUE_INFO should return the right size");

	T_EXPECT_NE(kqinfo.kq_state & KQ_WORKLOOP, 0U, "kqueue info should be for a workloop kqueue");
	T_EXPECT_EQ(kqinfo.kq_stat.vst_ino, EXPECTED_ID, "inode field should be the kqueue's ID");
}

T_DECL(dynamic_kqueue_extended_info, "the kernel should report valid extended dynamic kqueue info", T_META_ALL_VALID_ARCHS(true))
{
	struct kevent_extinfo kqextinfo[1];
	int ret;

	setup_kevent_id(EXPECTED_ID);
	ret = proc_piddynkqueueinfo(getpid(), PROC_PIDDYNKQUEUE_EXTINFO, EXPECTED_ID, kqextinfo, sizeof(kqextinfo));
	T_ASSERT_POSIX_SUCCESS(ret, "proc_piddynkqueueinfo(... PROC_PIDDYNKQUEUE_EXTINFO ...)");
	T_QUIET;
	T_ASSERT_EQ(ret, 1, "PROC_PIDDYNKQUEUE_EXTINFO should return a single knote");

	T_EXPECT_EQ(kqextinfo[0].kqext_kev.ident, 1ULL, "kevent identifier matches what was configured");
	T_EXPECT_EQ(kqextinfo[0].kqext_kev.filter, (short)EVFILT_USER, "kevent filter matches what was configured");
	T_EXPECT_EQ(kqextinfo[0].kqext_kev.udata, EXPECTED_UDATA, "kevent udata matches what was configured");
}

#pragma mark proc_listpids

T_DECL(list_kdebug_pids, "the kernel should report processes that are filtered by kdebug",
    T_META_ASROOT(YES), T_META_RUN_CONCURRENTLY(false))
{
	int mib[4] = {CTL_KERN, KERN_KDEBUG};
	int npids;
	int pids[1];
	int ret;
	kd_regtype reg;
	size_t regsize = sizeof(reg);

	mib[2] = KERN_KDREMOVE;
	ret    = sysctl(mib, 3, NULL, NULL, NULL, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "KERN_KDREMOVE sysctl");

	mib[2] = KERN_KDSETBUF;
	mib[3] = 100000;
	ret    = sysctl(mib, 4, NULL, NULL, NULL, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "KERN_KDSETBUF sysctl");

	mib[2] = KERN_KDSETUP;
	ret    = sysctl(mib, 3, NULL, NULL, NULL, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "KERN_KDSETUP sysctl");

	npids = proc_listpids(PROC_KDBG_ONLY, 0, pids, sizeof(pids));
	T_EXPECT_EQ(npids, 0, "no processes should be filtered initially");

	reg.type   = KDBG_TYPENONE;
	reg.value1 = (unsigned int)getpid();
	reg.value2 = 1; /* set the pid in the filter */
	mib[2]     = KERN_KDPIDTR;
	ret        = sysctl(mib, 3, &reg, &regsize, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "KERN_KDPIDTR sysctl to set a pid in the filter");

	npids = proc_listpids(PROC_KDBG_ONLY, 0, pids, sizeof(pids));
	npids /= 4;
	T_EXPECT_EQ(npids, 1, "a process should be filtered");
	T_EXPECT_EQ(pids[0], getpid(), "process filtered should be the one that was set");

	mib[2] = KERN_KDREMOVE;
	ret    = sysctl(mib, 3, NULL, NULL, NULL, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "KERN_KDREMOVE sysctl");
}

#pragma mark misc

static int prf_fd;
static char prf_path[PATH_MAX];
static void
prf_end(void)
{
	close(prf_fd);
	unlink(prf_path);
}

T_DECL(proc_regionfilename, "proc_regionfilename() should work")
{
	static char expected[] = "'very rigorous maritime engineering standards' && the front fell off";
	static char real[sizeof(expected)];
	int rc;
	void *addr;

	prf_fd = CONF_TMP_FILE_OPEN(prf_path);
	T_ATEND(prf_end);

	rc = (int) write(prf_fd, expected, sizeof(expected));
	T_ASSERT_POSIX_SUCCESS(rc, "write to tmpfile");

	addr = mmap(0, 0x1000, PROT_READ, MAP_PRIVATE, prf_fd, 0);
	T_WITH_ERRNO;
	T_ASSERT_NE_PTR(addr, MAP_FAILED, "mmap of tmpfile");

	T_WITH_ERRNO;
	T_ASSERT_GT(proc_regionfilename(getpid(), (uint64_t) addr, real, MAXPATHLEN), 0, "proc_regionfilename");
	T_EXPECT_EQ_STR(basename(prf_path), basename(real), "filename");
}

T_DECL(proc_regionpath, "PROC_PIDREGIONPATH should return addr, length and path")
{
	int rc;
	struct proc_regionpath path;
	static char some_text[] = "'very rigorous maritime engineering standards' && the front fell off";
	unsigned long rounded_length = (sizeof(some_text) & (unsigned long) ~(PAGE_SIZE - 1)) + PAGE_SIZE;
	void *addr;

	prf_fd = CONF_TMP_FILE_OPEN(prf_path);
	T_ATEND(prf_end);

	rc = (int) write(prf_fd, some_text, sizeof(some_text));
	T_ASSERT_POSIX_SUCCESS(rc, "write to tmpfile");

	addr = mmap(0, PAGE_SIZE, PROT_READ, MAP_PRIVATE, prf_fd, 0);
	T_WITH_ERRNO;
	T_ASSERT_NE_PTR(addr, MAP_FAILED, "mmap of tmpfile");

	rc = proc_pidinfo(getpid(), PROC_PIDREGIONPATH, (uint64_t)addr, &path, sizeof(struct proc_regionpath));
	T_ASSERT_POSIX_SUCCESS(rc, "proc_pidinfo");

	T_ASSERT_EQ((unsigned long) path.prpo_regionlength, rounded_length, "regionlength must match");
	T_ASSERT_EQ_PTR((void *) path.prpo_addr, addr, "addr must match");

	rc = proc_pidinfo(getpid(), PROC_PIDREGIONPATH, (uint64_t)((char *) addr + 20), &path, sizeof(struct proc_regionpath));
	T_ASSERT_POSIX_SUCCESS(rc, "proc_pidinfo 20 bytes past the base address");

	T_ASSERT_EQ((unsigned long) path.prpo_regionlength, rounded_length, "regionlength must match, even when 20 bytes past the base address");
	T_ASSERT_EQ_PTR((void *) path.prpo_addr, addr, "addr must match, even when 20 bytes past the base address");
}
