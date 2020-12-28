#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif

#include <darwintest.h>

#include <mach/host_priv.h>
#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/mach_vm.h>
#include <mach/processor_set.h>
#include <mach/task.h>
#include <sys/sysctl.h>
#include <unistd.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.ipc"),
    T_META_RUN_CONCURRENTLY(true));

/*
 * Attempt to inspect kernel_task using a task_inspect_t.  Interact with the
 * kernel in the same way top(1) and lsmp(1) do.
 */

static void
check_secure_kernel(void)
{
	int secure_kern = 0;
	size_t secure_kern_size = sizeof(secure_kern);

	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.secure_kernel", &secure_kern,
	    &secure_kern_size, NULL, 0), NULL);

	if (secure_kern) {
		T_SKIP("secure kernel: processor_set_tasks will not return kernel_task");
	}
}

static void
attempt_kernel_inspection(task_t task)
{
	pid_t pid = (pid_t)-1;
	mach_msg_type_number_t i, count, thcnt;
	struct task_basic_info_64 ti;
	thread_act_array_t threads;

	T_QUIET;
	T_EXPECT_MACH_SUCCESS(pid_for_task(task, &pid), NULL);
	T_LOG("Checking pid %d", pid);

	if (pid != 0) {
		return;
	}

	T_LOG("found kernel_task, attempting to inspect");

	count = TASK_BASIC_INFO_64_COUNT;
	T_EXPECT_MACH_SUCCESS(task_info(task, TASK_BASIC_INFO_64, (task_info_t)&ti,
	    &count), "task_info(... TASK_BASIC_INFO_64 ...)");

	T_EXPECT_MACH_SUCCESS(task_threads(task, &threads, &thcnt), "task_threads");
	T_LOG("Found %d kernel threads.", thcnt);
	for (i = 0; i < thcnt; i++) {
		kern_return_t kr;
		thread_basic_info_data_t basic_info;
		mach_msg_type_number_t bi_count = THREAD_BASIC_INFO_COUNT;

		kr = thread_info(threads[i], THREAD_BASIC_INFO,
		    (thread_info_t)&basic_info, &bi_count);
		/*
		 * Ignore threads that have gone away.
		 */
		if (kr == MACH_SEND_INVALID_DEST) {
			T_LOG("ignoring thread that has been destroyed");
			continue;
		}
		T_EXPECT_MACH_SUCCESS(kr, "thread_info(... THREAD_BASIC_INFO ...)");
		(void)mach_port_deallocate(mach_task_self(), threads[i]);
	}
	mach_vm_deallocate(mach_task_self(),
	    (mach_vm_address_t)(uintptr_t)threads,
	    thcnt * sizeof(*threads));

	ipc_info_space_basic_t basic_info;
	T_EXPECT_MACH_SUCCESS(mach_port_space_basic_info(task, &basic_info), "mach_port_space_basic_info");

	ipc_info_space_t info_space;
	ipc_info_name_array_t table;
	ipc_info_tree_name_array_t tree;
	mach_msg_type_number_t tblcnt = 0, treecnt = 0;
	T_EXPECT_MACH_SUCCESS(mach_port_space_info(task, &info_space, &table,
	    &tblcnt, &tree, &treecnt), "mach_port_space_info");
	if (tblcnt > 0) {
		mach_vm_deallocate(mach_task_self(),
		    (mach_vm_address_t)(uintptr_t)table,
		    tblcnt * sizeof(*table));
	}
	if (treecnt > 0) {
		mach_vm_deallocate(mach_task_self(),
		    (mach_vm_address_t)(uintptr_t)tree,
		    treecnt * sizeof(*tree));
	}

	T_END;
}

T_DECL(inspect_kernel_task,
    "ensure that kernel task can be inspected",
    T_META_CHECK_LEAKS(false),
    T_META_ASROOT(true))
{
	processor_set_name_array_t psets;
	processor_set_t pset;
	task_array_t tasks;
	mach_msg_type_number_t i, j, tcnt, pcnt = 0;
	mach_port_t self = mach_host_self();

	check_secure_kernel();

	T_ASSERT_MACH_SUCCESS(host_processor_sets(self, &psets, &pcnt),
	    NULL);

	for (i = 0; i < pcnt; i++) {
		T_ASSERT_MACH_SUCCESS(host_processor_set_priv(self, psets[i], &pset), NULL);
		T_LOG("Checking pset %d/%d", i, pcnt - 1);

		tcnt = 0;
		T_ASSERT_MACH_SUCCESS(processor_set_tasks(pset, &tasks, &tcnt), NULL);

		for (j = 0; j < tcnt; j++) {
			attempt_kernel_inspection(tasks[j]);
			mach_port_deallocate(self, tasks[j]);
		}

		/* free tasks array */
		mach_vm_deallocate(mach_task_self(),
		    (mach_vm_address_t)(uintptr_t)tasks,
		    tcnt * sizeof(*tasks));
		mach_port_deallocate(mach_task_self(), pset);
		mach_port_deallocate(mach_task_self(), psets[i]);
	}
	mach_vm_deallocate(mach_task_self(),
	    (mach_vm_address_t)(uintptr_t)psets,
	    pcnt * sizeof(*psets));

	T_FAIL("could not find kernel_task in list of tasks returned");
}
