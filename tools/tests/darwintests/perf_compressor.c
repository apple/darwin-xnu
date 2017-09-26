#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif
#include <darwintest.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sysctl.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm.perf"),
	T_META_CHECK_LEAKS(false)
);

enum {
	ALL_ZEROS,
	MOSTLY_ZEROS,
	RANDOM,
	TYPICAL
};

void allocate_zero_pages(char **buf, int num_pages, int vmpgsize);
void allocate_mostly_zero_pages(char **buf, int num_pages, int vmpgsize);
void allocate_random_pages(char **buf, int num_pages, int vmpgsize);
void allocate_representative_pages(char **buf, int num_pages, int vmpgsize);
void allocate_pages(int size_mb, int page_type);
void run_compressor_test(int size_mb, int page_type);

void allocate_zero_pages(char **buf, int num_pages, int vmpgsize) {
	int i;

	for (i = 0; i < num_pages; i++) {
		buf[i] = (char*)malloc((size_t)vmpgsize * sizeof(char));
		memset(buf[i], 0, vmpgsize);
	}
}

void allocate_mostly_zero_pages(char **buf, int num_pages, int vmpgsize) {
	int i, j;

	for (i = 0; i < num_pages; i++) {
		buf[i] = (char*)malloc((size_t)vmpgsize * sizeof(char));
		memset(buf[i], 0, vmpgsize);
		for (j = 0; j < 40; j++) {
			buf[i][j] = (char)(j+1);
		}
	}
}

void allocate_random_pages(char **buf, int num_pages, int vmpgsize) {
	int i;

	for (i = 0; i < num_pages; i++) {
		buf[i] = (char*)malloc((size_t)vmpgsize * sizeof(char));
		arc4random_buf((void*)buf[i], (size_t)vmpgsize);
	}
}

// Gives us the compression ratio we see in the typical case (~2.7)
void allocate_representative_pages(char **buf, int num_pages, int vmpgsize) {
	int i, j;
	char val;

	for (j = 0; j < num_pages; j++) {
		buf[j] = (char*)malloc((size_t)vmpgsize * sizeof(char));
		val = 0;
		for (i = 0; i < vmpgsize; i += 16) {
			memset(&buf[j][i], val, 16);
			if (i < 3700 * (vmpgsize / 4096)) {
				val++;
			}
		}
	}
}

void allocate_pages(int size_mb, int page_type) {
	int num_pages = 0;
	int vmpgsize, i, j;
	char **buf;
	size_t vmpgsize_length;

	vmpgsize_length = sizeof(vmpgsize);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.pagesize", &vmpgsize, &vmpgsize_length, NULL, 0),
			"failed to query vm.pagesize");
	if (vmpgsize == 0) {
		T_FAIL("vm.pagesize set to zero");
	}

	num_pages = size_mb * 1024 * 1024 / vmpgsize;
	buf = (char**)malloc(sizeof(char*) * (size_t)num_pages);

	// Switch on the type of page requested
	switch(page_type) {
		case ALL_ZEROS:
			allocate_zero_pages(buf, num_pages, vmpgsize);
			break;
		case MOSTLY_ZEROS:
			allocate_mostly_zero_pages(buf, num_pages, vmpgsize);
			break;
		case RANDOM:
			allocate_random_pages(buf, num_pages, vmpgsize);
			break;
		case TYPICAL:
			allocate_representative_pages(buf, num_pages, vmpgsize);
			break;
		default:
			T_FAIL("unknown page type");
			break;
	}

	for(j = 0; j < num_pages; j++) {
		i = buf[j][1];
	}
}


void run_compressor_test(int size_mb, int page_type) {

#ifndef CONFIG_FREEZE
	T_SKIP("Task freeze not supported.");
#endif

	dt_stat_t r = dt_stat_create("(input bytes / compressed bytes)", "compression_ratio");
	dt_stat_time_t s = dt_stat_time_create("compressor_latency");

	while (!dt_stat_stable(s)) {
		pid_t pid;
		int parent_pipe[2], child_pipe[2];

		T_QUIET; T_ASSERT_POSIX_SUCCESS(pipe(parent_pipe), "pipe failed");
		T_QUIET; T_ASSERT_POSIX_SUCCESS(pipe(child_pipe), "pipe failed");

		pid = fork();
		T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "fork failed with %d", errno);

		if (pid == 0) {
			int val = 1;

			close(child_pipe[0]);
			close(parent_pipe[1]);
			allocate_pages(size_mb, page_type);

			// Indicates to the parent that the child has finished allocating pages
			write(child_pipe[1], &val, sizeof(val));

			// Parent is done with the freeze, ok to exit now
			read(parent_pipe[0], &val, sizeof(val));
			if (val != 2) {
				T_FAIL("pipe read error");
			}
			close(child_pipe[1]);
			close(parent_pipe[0]);
			exit(0);

		} else {
			int val, ret;
			int64_t compressed_before, compressed_after, input_before, input_after;
			dt_stat_token start_token;
			size_t length = sizeof(compressed_before);

			close(child_pipe[1]);
			close(parent_pipe[0]);

			// Wait for the child to finish allocating pages
			read(child_pipe[0], &val, sizeof(val));
			if (val != 1) {
				T_FAIL("pipe read error");
			}
			// Just to be extra sure that the child has finished allocating all of its pages
			usleep(100);

			T_LOG("attempting to freeze pid %d\n", pid);

			T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.compressor_compressed_bytes", &compressed_before, &length, NULL, 0),
					"failed to query vm.compressor_compressed_bytes");
			T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.compressor_input_bytes", &input_before, &length, NULL, 0),
					"failed to query vm.compressor_input_bytes");

			start_token = dt_stat_time_begin(s);
			ret = sysctlbyname("kern.memorystatus_freeze", NULL, NULL, &pid, (size_t)sizeof(int));
			dt_stat_time_end(s, start_token);

			T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.compressor_compressed_bytes", &compressed_after, &length, NULL, 0),
					"failed to query vm.compressor_compressed_bytes");
			T_QUIET; T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.compressor_input_bytes", &input_after, &length, NULL, 0),
					"failed to query vm.compressor_input_bytes");

			T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "sysctl kern.memorystatus_freeze failed on pid %d", pid);

			dt_stat_add(r, (double)(input_after - input_before)/(double)(compressed_after - compressed_before));

			val = 2;
			// Ok for the child to exit now
			write(parent_pipe[1], &val, sizeof(val));
			usleep(100);

			close(child_pipe[0]);
			close(parent_pipe[1]);
		}
	}

	dt_stat_finalize(s);
	dt_stat_finalize(r);
}

// Numbers for 10MB and above are fairly reproducible. Anything smaller shows a lot of variation.
T_DECL(compr_10MB_zero, "Compressor latencies") {
	run_compressor_test(10, ALL_ZEROS);
}

T_DECL(compr_10MB_mostly_zero, "Compressor latencies") {
	run_compressor_test(10, MOSTLY_ZEROS);
}

T_DECL(compr_10MB_random, "Compressor latencies") {
	run_compressor_test(10, RANDOM);
}

T_DECL(compr_10MB_typical, "Compressor latencies") {
	run_compressor_test(10, TYPICAL);
}

T_DECL(compr_100MB_zero, "Compressor latencies") {
	run_compressor_test(100, ALL_ZEROS);
}

T_DECL(compr_100MB_mostly_zero, "Compressor latencies") {
	run_compressor_test(100, MOSTLY_ZEROS);
}

T_DECL(compr_100MB_random, "Compressor latencies") {
	run_compressor_test(100, RANDOM);
}

T_DECL(compr_100MB_typical, "Compressor latencies") {
	run_compressor_test(100, TYPICAL);
}

