#include <darwintest.h>
#include <inttypes.h>
#if __arm64__
#include <mach/arm/processor_info.h>
#endif /* __arm64__ */
#include <mach/mach.h>
#include <stdlib.h>
#include <unistd.h>

T_GLOBAL_META(T_META_ASROOT(true),
    T_META_RUN_CONCURRENTLY(true));

T_DECL(processor_cpu_stat64,
    "ensure 64-bit processor statistics are reported correctly",
    T_META_NAMESPACE("xnu.arm"))
{
#if !__arm64__
	T_SKIP("processor statistics only available on ARM");
#else /* !__arm64__ */
	host_t host = mach_host_self();
	host_t priv_port = MACH_PORT_NULL;

	kern_return_t kr = host_get_host_priv_port(host, &priv_port);
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(kr, "host_get_host_priv_port");
	T_QUIET;
	T_ASSERT_NE(priv_port, MACH_PORT_NULL, "valid host priv port");

	processor_port_array_t cpu_ports = NULL;
	mach_msg_type_number_t cpu_count = 0;
	kr = host_processors(priv_port, &cpu_ports, &cpu_count);
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(kr, "host_processors");
	T_QUIET;
	T_ASSERT_NOTNULL(cpu_ports, "valid processor port array");
	T_QUIET;
	T_ASSERT_GT(cpu_count, (mach_msg_type_number_t)0,
	    "non-zero CPU count");

	T_LOG("found %d CPUs", cpu_count);

	struct processor_cpu_stat64 *prestats = calloc(cpu_count,
	    sizeof(*prestats));
	T_WITH_ERRNO;
	T_QUIET;
	T_ASSERT_NOTNULL(prestats, "allocate space for stats (pre)");
	memset(prestats, 0xff, cpu_count * sizeof(*prestats));

	for (int i = 0; i < (int)cpu_count; i++) {
		mach_msg_type_number_t info_count = PROCESSOR_CPU_STAT64_COUNT;
		kr = processor_info(cpu_ports[i], PROCESSOR_CPU_STAT64, &host,
		    (processor_info_t)&prestats[i], &info_count);
		T_ASSERT_MACH_SUCCESS(kr,
		    "processor_info(%d, PROCESSOR_CPU_STAT64, ...)", i);

		T_QUIET;
		T_ASSERT_EQ(info_count, PROCESSOR_CPU_STAT64_COUNT,
		    "received enough CPU statistics");
	}

	sleep(1);

	struct processor_cpu_stat64 *poststats = calloc(cpu_count - 1,
	    sizeof(*poststats));
	T_WITH_ERRNO;
	T_QUIET;
	T_ASSERT_NOTNULL(poststats, "allocate space for stats (post)");

	for (int i = 0; i < (int)cpu_count; i++) {
		mach_msg_type_number_t info_count = PROCESSOR_CPU_STAT64_COUNT;
		kr = processor_info(cpu_ports[i], PROCESSOR_CPU_STAT64, &host,
		    (processor_info_t)&poststats[i], &info_count);
		T_ASSERT_MACH_SUCCESS(kr,
		    "processor_info(%d, PROCESSOR_CPU_STAT64, ...)", i);

		T_QUIET;
		T_ASSERT_EQ(info_count, PROCESSOR_CPU_STAT64_COUNT,
		    "received enough CPU statistics");
	}

	for (int i = 0; i < (int)cpu_count; i++) {
#define CHECK_STAT_FIELD(field) \
	        T_EXPECT_GE(poststats[i].field, prestats[i].field, \
	        "CPU %d's " #field " is monotonically increasing (+%" PRIu64 \
	        ")", i, poststats[i].field - prestats[i].field)

		CHECK_STAT_FIELD(irq_ex_cnt);
		CHECK_STAT_FIELD(ipi_cnt);
		CHECK_STAT_FIELD(timer_cnt);
		CHECK_STAT_FIELD(undef_ex_cnt);
		CHECK_STAT_FIELD(unaligned_cnt);
		CHECK_STAT_FIELD(vfp_cnt);
		CHECK_STAT_FIELD(vfp_shortv_cnt);
		CHECK_STAT_FIELD(data_ex_cnt);
		CHECK_STAT_FIELD(instr_ex_cnt);
		CHECK_STAT_FIELD(pmi_cnt);

#undef CHECK_STAT_FIELD
	}

	free(prestats);
	free(poststats);
#endif /* __arm64__ */
}
