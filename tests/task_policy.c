#include <darwintest.h>
#include <signal.h>
#include <spawn.h>
#include <unistd.h>

#include <mach/mach.h>
#include <mach/mach_types.h>
#include <mach/task.h>
#include <mach/task_policy.h>

extern char **environ;

int task_inspect_for_pid(mach_port_name_t target_tport, int pid, mach_port_name_t *t);
int task_for_pid(mach_port_name_t target_tport, int pid, mach_port_name_t *t);
int task_name_for_pid(mach_port_name_t target_tport, int pid, mach_port_name_t *t);

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

#if defined(UNENTITLED)

T_DECL(task_policy_set_task_name, "task_policy_set with task name (not entitled)")
{
	struct task_qos_policy qosinfo = {
		.task_latency_qos_tier = LATENCY_QOS_TIER_0,
		.task_throughput_qos_tier = THROUGHPUT_QOS_TIER_0,
	};
	task_name_t task_name = TASK_NAME_NULL;

	T_SETUPBEGIN;
	T_ASSERT_MACH_SUCCESS(task_name_for_pid(mach_task_self(), getpid(),
	    &task_name), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_ERROR(task_policy_set(task_name,
	    TASK_BASE_QOS_POLICY,
	    (task_policy_t)&qosinfo,
	    TASK_QOS_POLICY_COUNT),
	    KERN_INVALID_ARGUMENT, NULL);
}

T_DECL(task_policy_set_task, "task_policy_set with task (not entitled)")
{
	struct task_qos_policy qosinfo = {
		.task_latency_qos_tier = LATENCY_QOS_TIER_0,
		.task_throughput_qos_tier = THROUGHPUT_QOS_TIER_0,
	};

	T_ASSERT_MACH_SUCCESS(task_policy_set(mach_task_self(),
	    TASK_BASE_QOS_POLICY,
	    (task_policy_t)&qosinfo,
	    TASK_QOS_POLICY_COUNT),
	    NULL);
}

T_DECL(task_policy_set_inspect, "task_policy_set with task inspect (not entitled)")
{
	struct task_qos_policy qosinfo = {
		.task_latency_qos_tier = LATENCY_QOS_TIER_0,
		.task_throughput_qos_tier = THROUGHPUT_QOS_TIER_0,
	};
	task_inspect_t task_inspect = TASK_INSPECT_NULL;

	T_SETUPBEGIN;
	T_ASSERT_MACH_SUCCESS(task_inspect_for_pid(mach_task_self(), getpid(),
	    &task_inspect), NULL);
	T_SETUPEND;


	T_ASSERT_MACH_ERROR(task_policy_set(task_inspect,
	    TASK_BASE_QOS_POLICY,
	    (task_policy_t)&qosinfo,
	    TASK_QOS_POLICY_COUNT),
	    KERN_INVALID_ARGUMENT, NULL);
}

T_DECL(task_policy_set_foreign_task, "task_policy_set for foreign task (not entitled)", T_META_ASROOT(true))
{
	struct task_qos_policy qosinfo = {
		.task_latency_qos_tier = LATENCY_QOS_TIER_0,
		.task_throughput_qos_tier = THROUGHPUT_QOS_TIER_0,
	};
	task_t task = TASK_NULL;
	kern_return_t ret = KERN_FAILURE;
	char *args[] = { "sleep", "10", NULL };
	pid_t pid = 0;

	T_SETUPBEGIN;

	ret = posix_spawnp(&pid, args[0], NULL, NULL, args, environ);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "spawning sleep 10");

	T_ASSERT_MACH_SUCCESS(task_for_pid(mach_task_self(), pid,
	    &task), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_SUCCESS(task_policy_set(task,
	    TASK_BASE_QOS_POLICY,
	    (task_policy_t)&qosinfo,
	    TASK_QOS_POLICY_COUNT),
	    NULL);

	ret = kill(pid, SIGTERM);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "killing sleep");
}

T_DECL(task_policy_set_foreign_task_name, "task_policy_set for foreign task name (not entitled)", T_META_ASROOT(true))
{
	struct task_qos_policy qosinfo = {
		.task_latency_qos_tier = LATENCY_QOS_TIER_0,
		.task_throughput_qos_tier = THROUGHPUT_QOS_TIER_0,
	};
	task_name_t task_name = TASK_NAME_NULL;
	kern_return_t ret = KERN_FAILURE;
	char *args[] = { "sleep", "10", NULL };
	pid_t pid = 0;

	T_SETUPBEGIN;

	ret = posix_spawnp(&pid, args[0], NULL, NULL, args, environ);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "spawning sleep 10");

	T_ASSERT_MACH_SUCCESS(task_name_for_pid(mach_task_self(), pid,
	    &task_name), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_ERROR(task_policy_set(task_name,
	    TASK_BASE_QOS_POLICY,
	    (task_policy_t)&qosinfo,
	    TASK_QOS_POLICY_COUNT),
	    KERN_INVALID_ARGUMENT, NULL);

	ret = kill(pid, SIGTERM);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "killing sleep");
}

T_DECL(task_policy_set_foreign_task_inspect, "task_policy_set for foreign task inspect (not entitled)", T_META_ASROOT(true))
{
	struct task_qos_policy qosinfo = {
		.task_latency_qos_tier = LATENCY_QOS_TIER_0,
		.task_throughput_qos_tier = THROUGHPUT_QOS_TIER_0,
	};
	task_inspect_t task_inspect = TASK_INSPECT_NULL;
	kern_return_t ret = KERN_FAILURE;
	char *args[] = { "sleep", "10", NULL };
	pid_t pid = 0;

	T_SETUPBEGIN;

	ret = posix_spawnp(&pid, args[0], NULL, NULL, args, environ);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "spawning sleep 10");

	T_ASSERT_MACH_SUCCESS(task_inspect_for_pid(mach_task_self(), pid,
	    &task_inspect), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_ERROR(task_policy_set(task_inspect,
	    TASK_BASE_QOS_POLICY,
	    (task_policy_t)&qosinfo,
	    TASK_QOS_POLICY_COUNT),
	    KERN_INVALID_ARGUMENT, NULL);

	ret = kill(pid, SIGTERM);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "killing sleep");
}

T_DECL(task_policy_get_name, "task_policy_get with task name (not entitled)")
{
	task_name_t task_name = TASK_NAME_NULL;
	struct task_category_policy role[TASK_CATEGORY_POLICY_COUNT];
	mach_msg_type_number_t count = TASK_CATEGORY_POLICY_COUNT;
	boolean_t get_default = FALSE;

	T_SETUPBEGIN;
	T_ASSERT_MACH_SUCCESS(task_name_for_pid(mach_task_self(), getpid(),
	    &task_name), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_ERROR(task_policy_get(task_name,
	    TASK_CATEGORY_POLICY,
	    (task_policy_t)role,
	    &count,
	    &get_default),
	    KERN_INVALID_ARGUMENT, NULL);
}

T_DECL(task_policy_get_task, "task_policy_get with task (not entitled)")
{
	struct task_category_policy role[TASK_CATEGORY_POLICY_COUNT];
	mach_msg_type_number_t count = TASK_CATEGORY_POLICY_COUNT;
	boolean_t get_default = FALSE;

	T_ASSERT_MACH_SUCCESS(task_policy_get(mach_task_self(),
	    TASK_CATEGORY_POLICY,
	    (task_policy_t)role,
	    &count,
	    &get_default),
	    NULL);
}

T_DECL(task_policy_get_inspect, "task_policy_get with task inspect (not entitled)")
{
	task_inspect_t task_inspect = TASK_INSPECT_NULL;
	struct task_category_policy role[TASK_CATEGORY_POLICY_COUNT];
	mach_msg_type_number_t count = TASK_CATEGORY_POLICY_COUNT;
	boolean_t get_default = FALSE;

	T_SETUPBEGIN;
	T_ASSERT_MACH_SUCCESS(task_inspect_for_pid(mach_task_self(), getpid(),
	    &task_inspect), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_SUCCESS(task_policy_get(task_inspect,
	    TASK_CATEGORY_POLICY,
	    (task_policy_t)role,
	    &count,
	    &get_default),
	    NULL);
}

T_DECL(task_policy_get_foreign_task_inspect, "task_policy_get for foreign task inspect (not entitled)", T_META_ASROOT(true))
{
	task_inspect_t task_inspect = TASK_INSPECT_NULL;
	struct task_category_policy role[TASK_CATEGORY_POLICY_COUNT];
	mach_msg_type_number_t count = TASK_CATEGORY_POLICY_COUNT;
	boolean_t get_default = FALSE;
	kern_return_t ret = KERN_FAILURE;
	char *args[] = { "sleep", "10", NULL };
	pid_t pid = 0;

	T_SETUPBEGIN;

	ret = posix_spawnp(&pid, args[0], NULL, NULL, args, environ);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "spawning sleep 10");

	T_ASSERT_MACH_SUCCESS(task_inspect_for_pid(mach_task_self(), pid,
	    &task_inspect), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_SUCCESS(task_policy_get(task_inspect,
	    TASK_CATEGORY_POLICY,
	    (task_policy_t)role,
	    &count,
	    &get_default),
	    NULL);

	ret = kill(pid, SIGTERM);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "killing sleep");
}

T_DECL(task_policy_get_foreign_task, "task_policy_get for foreign task (not entitled)", T_META_ASROOT(true))
{
	task_t task = TASK_NULL;
	struct task_category_policy role[TASK_CATEGORY_POLICY_COUNT];
	mach_msg_type_number_t count = TASK_CATEGORY_POLICY_COUNT;
	boolean_t get_default = FALSE;
	kern_return_t ret = KERN_FAILURE;
	char *args[] = { "sleep", "10", NULL };
	pid_t pid = 0;

	T_SETUPBEGIN;

	ret = posix_spawnp(&pid, args[0], NULL, NULL, args, environ);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "spawning sleep 10");

	T_ASSERT_MACH_SUCCESS(task_for_pid(mach_task_self(), pid,
	    &task), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_SUCCESS(task_policy_get(task,
	    TASK_CATEGORY_POLICY,
	    (task_policy_t)role,
	    &count,
	    &get_default),
	    NULL);

	ret = kill(pid, SIGTERM);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "killing sleep");
}

T_DECL(task_policy_get_foreign_task_name, "task_policy_get for foreign task name (not entitled)")
{
	task_name_t task_name = TASK_NAME_NULL;
	struct task_category_policy role[TASK_CATEGORY_POLICY_COUNT];
	mach_msg_type_number_t count = TASK_CATEGORY_POLICY_COUNT;
	boolean_t get_default = FALSE;
	kern_return_t ret = KERN_FAILURE;
	char *args[] = { "sleep", "10", NULL };
	pid_t pid = 0;

	T_SETUPBEGIN;

	ret = posix_spawnp(&pid, args[0], NULL, NULL, args, environ);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "spawning sleep 10");

	T_ASSERT_MACH_SUCCESS(task_name_for_pid(mach_task_self(), pid,
	    &task_name), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_ERROR(task_policy_get(task_name,
	    TASK_CATEGORY_POLICY,
	    (task_policy_t)role,
	    &count,
	    &get_default),
	    KERN_INVALID_ARGUMENT, NULL);

	ret = kill(pid, SIGTERM);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "killing sleep");
}

#else /* ENTITLED */

T_DECL(task_policy_set_task_name_entitled, "task_policy_set with task name (entitled)", T_META_ASROOT(true), T_META_ASROOT(true))
{
	struct task_qos_policy qosinfo = {
		.task_latency_qos_tier = LATENCY_QOS_TIER_0,
		.task_throughput_qos_tier = THROUGHPUT_QOS_TIER_0,
	};
	task_name_t task_name = TASK_NAME_NULL;

	T_SETUPBEGIN;
	T_ASSERT_MACH_SUCCESS(task_name_for_pid(mach_task_self(), getpid(),
	    &task_name), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_SUCCESS(task_policy_set(task_name,
	    TASK_BASE_QOS_POLICY,
	    (task_policy_t)&qosinfo,
	    TASK_QOS_POLICY_COUNT),
	    NULL);
}

T_DECL(task_policy_set_task_entitled, "task_policy_set with task (entitled)")
{
	struct task_qos_policy qosinfo = {
		.task_latency_qos_tier = LATENCY_QOS_TIER_0,
		.task_throughput_qos_tier = THROUGHPUT_QOS_TIER_0,
	};

	T_ASSERT_MACH_SUCCESS(task_policy_set(mach_task_self(),
	    TASK_BASE_QOS_POLICY,
	    (task_policy_t)&qosinfo,
	    TASK_QOS_POLICY_COUNT),
	    NULL);
}

T_DECL(task_policy_set_inspect_entitled, "task_policy_set with task inspect (entitled)")
{
	struct task_qos_policy qosinfo = {
		.task_latency_qos_tier = LATENCY_QOS_TIER_0,
		.task_throughput_qos_tier = THROUGHPUT_QOS_TIER_0,
	};
	task_inspect_t task_inspect = TASK_INSPECT_NULL;

	T_SETUPBEGIN;
	T_ASSERT_MACH_SUCCESS(task_inspect_for_pid(mach_task_self(), getpid(),
	    &task_inspect), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_SUCCESS(task_policy_set(task_inspect,
	    TASK_BASE_QOS_POLICY,
	    (task_policy_t)&qosinfo,
	    TASK_QOS_POLICY_COUNT),
	    NULL);
}

T_DECL(task_policy_set_foreign_task_entitled, "task_policy_set for foreign task (entitled)", T_META_ASROOT(true))
{
	struct task_qos_policy qosinfo = {
		.task_latency_qos_tier = LATENCY_QOS_TIER_0,
		.task_throughput_qos_tier = THROUGHPUT_QOS_TIER_0,
	};
	task_t task = TASK_NULL;
	kern_return_t ret = KERN_FAILURE;
	char *args[] = { "sleep", "10", NULL };
	pid_t pid = 0;

	T_SETUPBEGIN;

	ret = posix_spawnp(&pid, args[0], NULL, NULL, args, environ);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "spawning sleep 10");

	T_ASSERT_MACH_SUCCESS(task_for_pid(mach_task_self(), pid,
	    &task), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_SUCCESS(task_policy_set(task,
	    TASK_BASE_QOS_POLICY,
	    (task_policy_t)&qosinfo,
	    TASK_QOS_POLICY_COUNT),
	    NULL);

	ret = kill(pid, SIGTERM);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "killing sleep");
}

T_DECL(task_policy_set_foreign_task_name_entitled, "task_policy_set for foreign task name (entitled)", T_META_ASROOT(true), T_META_ASROOT(true))
{
	struct task_qos_policy qosinfo = {
		.task_latency_qos_tier = LATENCY_QOS_TIER_0,
		.task_throughput_qos_tier = THROUGHPUT_QOS_TIER_0,
	};
	task_name_t task_name = TASK_NAME_NULL;
	kern_return_t ret = KERN_FAILURE;
	char *args[] = { "sleep", "10", NULL };
	pid_t pid = 0;

	T_SETUPBEGIN;

	ret = posix_spawnp(&pid, args[0], NULL, NULL, args, environ);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "spawning sleep 10");

	T_ASSERT_MACH_SUCCESS(task_name_for_pid(mach_task_self(), pid,
	    &task_name), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_SUCCESS(task_policy_set(task_name,
	    TASK_BASE_QOS_POLICY,
	    (task_policy_t)&qosinfo,
	    TASK_QOS_POLICY_COUNT),
	    NULL);

	ret = kill(pid, SIGTERM);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "killing sleep");
}

T_DECL(task_policy_set_foreign_task_inspect_entitled, "task_policy_set for foreign task inspect (entitled)", T_META_ASROOT(true))
{
	struct task_qos_policy qosinfo = {
		.task_latency_qos_tier = LATENCY_QOS_TIER_0,
		.task_throughput_qos_tier = THROUGHPUT_QOS_TIER_0,
	};
	task_inspect_t task_inspect = TASK_INSPECT_NULL;
	kern_return_t ret = KERN_FAILURE;
	char *args[] = { "sleep", "10", NULL };
	pid_t pid = 0;

	T_SETUPBEGIN;

	ret = posix_spawnp(&pid, args[0], NULL, NULL, args, environ);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "spawning sleep 10");

	T_ASSERT_MACH_SUCCESS(task_inspect_for_pid(mach_task_self(), pid,
	    &task_inspect), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_SUCCESS(task_policy_set(task_inspect,
	    TASK_BASE_QOS_POLICY,
	    (task_policy_t)&qosinfo,
	    TASK_QOS_POLICY_COUNT),
	    NULL);

	ret = kill(pid, SIGTERM);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "killing sleep");
}

T_DECL(task_policy_get_name_entitled, "task_policy_get with task name (entitled)", T_META_ASROOT(true))
{
	task_name_t task_name = TASK_NAME_NULL;
	struct task_category_policy role[TASK_CATEGORY_POLICY_COUNT];
	mach_msg_type_number_t count = TASK_CATEGORY_POLICY_COUNT;
	boolean_t get_default = FALSE;

	T_SETUPBEGIN;
	T_ASSERT_MACH_SUCCESS(task_name_for_pid(mach_task_self(), getpid(),
	    &task_name), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_SUCCESS(task_policy_get(task_name,
	    TASK_CATEGORY_POLICY,
	    (task_policy_t)role,
	    &count,
	    &get_default),
	    NULL);
}

T_DECL(task_policy_get_task_entitled, "task_policy_get with task (entitled)")
{
	struct task_category_policy role[TASK_CATEGORY_POLICY_COUNT];
	mach_msg_type_number_t count = TASK_CATEGORY_POLICY_COUNT;
	boolean_t get_default = FALSE;

	T_ASSERT_MACH_SUCCESS(task_policy_get(mach_task_self(),
	    TASK_CATEGORY_POLICY,
	    (task_policy_t)role,
	    &count,
	    &get_default),
	    NULL);
}

T_DECL(task_policy_get_inspect_entitled, "task_policy_get with task inspect (entitled)")
{
	task_inspect_t task_inspect = TASK_INSPECT_NULL;
	struct task_category_policy role[TASK_CATEGORY_POLICY_COUNT];
	mach_msg_type_number_t count = TASK_CATEGORY_POLICY_COUNT;
	boolean_t get_default = FALSE;

	T_SETUPBEGIN;
	T_ASSERT_MACH_SUCCESS(task_inspect_for_pid(mach_task_self(), getpid(),
	    &task_inspect), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_SUCCESS(task_policy_get(task_inspect,
	    TASK_CATEGORY_POLICY,
	    (task_policy_t)role,
	    &count,
	    &get_default),
	    NULL);
}

T_DECL(task_policy_get_foreign_task_inspect_entitled, "task_policy_get for foreign task inspect (entitled)", T_META_ASROOT(true))
{
	task_inspect_t task_inspect = TASK_INSPECT_NULL;
	struct task_category_policy role[TASK_CATEGORY_POLICY_COUNT];
	mach_msg_type_number_t count = TASK_CATEGORY_POLICY_COUNT;
	boolean_t get_default = FALSE;
	kern_return_t ret = KERN_FAILURE;
	char *args[] = { "sleep", "10", NULL };
	pid_t pid = 0;

	T_SETUPBEGIN;

	ret = posix_spawnp(&pid, args[0], NULL, NULL, args, environ);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "spawning sleep 10");

	T_ASSERT_MACH_SUCCESS(task_inspect_for_pid(mach_task_self(), pid,
	    &task_inspect), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_SUCCESS(task_policy_get(task_inspect,
	    TASK_CATEGORY_POLICY,
	    (task_policy_t)role,
	    &count,
	    &get_default),
	    NULL);

	ret = kill(pid, SIGTERM);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "killing sleep");
}

T_DECL(task_policy_get_foreign_task_entitled, "task_policy_get for foreign task (entitled)", T_META_ASROOT(true))
{
	task_t task = TASK_NULL;
	struct task_category_policy role[TASK_CATEGORY_POLICY_COUNT];
	mach_msg_type_number_t count = TASK_CATEGORY_POLICY_COUNT;
	boolean_t get_default = FALSE;
	kern_return_t ret = KERN_FAILURE;
	char *args[] = { "sleep", "10", NULL };
	pid_t pid = 0;

	T_SETUPBEGIN;

	ret = posix_spawnp(&pid, args[0], NULL, NULL, args, environ);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "spawning sleep 10");

	T_ASSERT_MACH_SUCCESS(task_for_pid(mach_task_self(), pid,
	    &task), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_SUCCESS(task_policy_get(task,
	    TASK_CATEGORY_POLICY,
	    (task_policy_t)role,
	    &count,
	    &get_default),
	    NULL);

	ret = kill(pid, SIGTERM);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "killing sleep");
}

T_DECL(task_policy_get_foreign_task_name_entitled, "task_policy_get for foreign task name (entitled)", T_META_ASROOT(true))
{
	task_name_t task_name = TASK_NAME_NULL;
	struct task_category_policy role[TASK_CATEGORY_POLICY_COUNT];
	mach_msg_type_number_t count = TASK_CATEGORY_POLICY_COUNT;
	boolean_t get_default = FALSE;
	kern_return_t ret = KERN_FAILURE;
	char *args[] = { "sleep", "10", NULL };
	pid_t pid = 0;

	T_SETUPBEGIN;

	ret = posix_spawnp(&pid, args[0], NULL, NULL, args, environ);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "spawning sleep 10");

	T_ASSERT_MACH_SUCCESS(task_name_for_pid(mach_task_self(), pid,
	    &task_name), NULL);
	T_SETUPEND;

	T_ASSERT_MACH_SUCCESS(task_policy_get(task_name,
	    TASK_CATEGORY_POLICY,
	    (task_policy_t)role,
	    &count,
	    &get_default),
	    NULL);

	ret = kill(pid, SIGTERM);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "killing sleep");
}

#endif /* UNENTITLED */
