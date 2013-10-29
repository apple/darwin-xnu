#include <fcntl.h>
#include "perf_index.h"
#include <errno.h>

void stress_file_create(const char *fs_path, int thread_id, int num_threads, long long length) {
  long long i;
  int fd;
  char filepath[MAXPATHLEN];
  for(i=0; i<length; i++) {
    snprintf(filepath, MAXPATHLEN, "%s/file_create-%d-%lld", fs_path, thread_id, i);
    fd = open(filepath, O_CREAT | O_EXCL | O_WRONLY, 0644);
    assert(fd>=0);
    close(fd);
  }
  for(i=0; i<length; i++) {
    snprintf(filepath, MAXPATHLEN, "%s/file_create-%d-%lld", fs_path, thread_id, i);
    assert(unlink(filepath)>=0);
  }
}
