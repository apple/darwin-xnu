#include <fcntl.h>
#include "perf_index.h"
#include <errno.h>


const stress_test_t file_local_create_test = {"file_create", &stress_file_local_create_init, &stress_file_local_create, &stress_file_local_create_cleanup, &no_validate};
const stress_test_t file_local_write_test = {"file_write", &stress_file_local_write_init, &stress_file_local_write, &stress_file_local_write_cleanup, &no_validate};
const stress_test_t file_local_read_test =  {"file_read", &stress_file_local_read_init, &stress_file_local_read, &stress_file_local_read_cleanup, &no_validate};

static char fs_path[MAXPATHLEN];

static void setup_local_volume(void) {
  snprintf(fs_path, MAXPATHLEN, "%s", "/tmp");
}

DECL_INIT(stress_file_local_read_init) {
  setup_local_volume();
  stress_file_read_init(fs_path, num_threads, length, 0L);
}

DECL_TEST(stress_file_local_read) {
  stress_file_read(fs_path, thread_id, num_threads, length, 0L);
}

DECL_CLEANUP(stress_file_local_read_cleanup) {
  stress_file_read_cleanup(fs_path, num_threads, length);
}

DECL_INIT(stress_file_local_write_init) {
  setup_local_volume();
  stress_file_write_init(fs_path, num_threads, length);
}

DECL_TEST(stress_file_local_write) {
  stress_file_write(fs_path, thread_id, num_threads, length, 0L);
}

DECL_CLEANUP(stress_file_local_write_cleanup) {
}

DECL_INIT(stress_file_local_create_init) {
  setup_local_volume();
}

DECL_TEST(stress_file_local_create) {
  stress_file_create(fs_path, thread_id, num_threads, length);
}

DECL_CLEANUP(stress_file_local_create_cleanup) {
}
