#include <fcntl.h>
#include "perf_index.h"
#include <errno.h>

#define MAX_FILE_SIZE 536870912L

const stress_test_t file_ram_create_test = {"ram_file_create", &stress_file_ram_create_init, &stress_file_ram_create, &stress_file_ram_create_cleanup, &no_validate};
const stress_test_t file_ram_write_test = {"ram_file_write", &stress_file_ram_write_init, &stress_file_ram_write, &stress_file_ram_write_cleanup, &no_validate};
const stress_test_t file_ram_read_test = {"ram_file_read", &stress_file_ram_read_init, &stress_file_ram_read, &stress_file_ram_read_cleanup, &no_validate};

static const char ramdiskname[] = "StressRamDisk";

static const char fs_path[MAXPATHLEN] = "/Volumes/StressRamDisk";

static void setup_ram_volume(void) {
  char *cmd;
  assert(asprintf(&cmd, "diskutil erasevolume HFS+ \"%s\" `hdiutil attach -nomount ram://1500000` >/dev/null", ramdiskname) >= 0);
  assert(system(cmd) == 0);
  free(cmd);
}

static void cleanup_ram_volume(void) {
  char *cmd;
  assert(asprintf(&cmd, "umount -f %s >/dev/null", fs_path) >= 0);
  assert(system(cmd) == 0);
  free(cmd);
}

DECL_INIT(stress_file_ram_read_init) {
  setup_ram_volume();
  stress_file_read_init(fs_path, num_threads, length, MAX_FILE_SIZE);
}

DECL_TEST(stress_file_ram_read) {
  stress_file_read(fs_path, thread_id, num_threads, length, MAX_FILE_SIZE);
}

DECL_CLEANUP(stress_file_ram_read_cleanup) {
  cleanup_ram_volume();
}

DECL_INIT(stress_file_ram_write_init) {
  setup_ram_volume();
  stress_file_write_init(fs_path, num_threads, length);
}

DECL_TEST(stress_file_ram_write) {
  stress_file_write(fs_path, thread_id, num_threads, length, MAX_FILE_SIZE);
}

DECL_CLEANUP(stress_file_ram_write_cleanup) {
  cleanup_ram_volume();
}

DECL_INIT(stress_file_ram_create_init) {
  setup_ram_volume();
}

DECL_TEST(stress_file_ram_create) {
  stress_file_create(fs_path, thread_id, num_threads, length);
}

DECL_CLEANUP(stress_file_ram_create_cleanup) {
  cleanup_ram_volume();
}
