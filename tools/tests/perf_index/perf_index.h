#ifndef __PERF_INDEX_H_
#define __PERF_INDEX_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>

#define DECL_VALIDATE(validatetest) int validatetest(int test_argc, const char **test_argv)
#define DECL_INIT(inittest) void inittest(int num_threads, long long length, int test_argc, const char **test_argv)
#define DECL_TEST(test) void test(int thread_id, int num_threads, long long length, int test_argc, const char **test_argv)
#define DECL_CLEANUP(cleanuptest) void cleanuptest(int num_threads, long long length)

#define MAXPATHLEN 1024

typedef DECL_INIT((*init_func));
typedef DECL_TEST((*stress_func));
typedef DECL_CLEANUP((*cleanup_func));
typedef DECL_VALIDATE((*validate_func));

typedef struct {
  char *name;
  init_func init;
  stress_func stress;
  cleanup_func cleanup;
  validate_func validate;
} stress_test_t;

extern const stress_test_t cpu_test;
extern const stress_test_t memory_test;
extern const stress_test_t syscall_test;
extern const stress_test_t fault_test;
extern const stress_test_t zfod_test;
extern const stress_test_t file_local_create_test;
extern const stress_test_t file_local_write_test;
extern const stress_test_t file_local_read_test;
extern const stress_test_t file_ram_create_test;
extern const stress_test_t file_ram_write_test;
extern const stress_test_t file_ram_read_test;
extern const stress_test_t iperf_test;
extern const stress_test_t compile_test;

DECL_VALIDATE(no_validate);
DECL_VALIDATE(validate_iperf);

DECL_INIT(stress_memory_init);
DECL_INIT(stress_syscall_init);
DECL_INIT(stress_fault_init);
DECL_INIT(stress_file_local_create_init);
DECL_INIT(stress_file_local_read_init);
DECL_INIT(stress_file_local_write_init);
DECL_INIT(stress_file_ram_create_init);
DECL_INIT(stress_file_ram_read_init);
DECL_INIT(stress_file_ram_write_init);
DECL_INIT(compile_init);
DECL_INIT(stress_general_init);

DECL_TEST(stress_memory);
DECL_TEST(stress_cpu);
DECL_TEST(stress_syscall);
DECL_TEST(stress_fault);
DECL_TEST(stress_zfod);
DECL_TEST(stress_file_local_create);
DECL_TEST(stress_file_local_read);
DECL_TEST(stress_file_local_write);
DECL_TEST(stress_file_ram_create);
DECL_TEST(stress_file_ram_read);
DECL_TEST(stress_file_ram_write);
DECL_TEST(iperf);
DECL_TEST(compile);
DECL_TEST(stress_general);

DECL_CLEANUP(stress_general_cleanup);
DECL_CLEANUP(stress_file_local_create_cleanup);
DECL_CLEANUP(stress_file_local_read_cleanup);
DECL_CLEANUP(stress_file_local_write_cleanup);
DECL_CLEANUP(stress_file_ram_create_cleanup);
DECL_CLEANUP(stress_file_ram_read_cleanup);
DECL_CLEANUP(stress_file_ram_write_cleanup);
DECL_CLEANUP(compile_cleanup);

void stress_file_create(const char *fs_path, int thread_id, int num_threads, long long length);

void stress_file_write_init(const char *fs_path, int num_threads, long long length);
void stress_file_write(const char *fs_path, int thread_id, int num_threads, long long length, long long max_file_size);

void stress_file_read_init(const char *fs_path, int num_threads, long long length, long long max_file_size);
void stress_file_read(const char *fs_path, int thread_id, int num_threads, long long length, long long max_file_size);
void stress_file_read_cleanup(const char *fs_path, int num_threads, long long length);

void md5_hash(uint8_t *message, uint64_t len, uint32_t *hash);

#endif
