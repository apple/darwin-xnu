#include <fcntl.h>
#include "perf_index.h"
#include <errno.h>

#define MAXFILESIZE 8589934592L

static int *fds = NULL;
static char writebuff[4096];

void stress_file_write_init(const char *fs_path, int num_threads, long long length) {
  int i;
  char filepath[MAXPATHLEN];

  if(fds == NULL)
    fds = (int*)malloc(sizeof(int)*num_threads);
  for(i=0; i<num_threads; i++) {
    snprintf(filepath, sizeof(filepath), "%s/file_write-%d", fs_path, i);
    fds[i] = open(filepath, O_CREAT | O_EXCL | O_WRONLY, 0644);
    assert(fds[i] > 0);
  }
  bzero(writebuff, sizeof(writebuff));
}

void stress_file_write(const char *fs_path, int thread_id, int num_threads, long long length, long long max_file_size) {
  long long left;
  size_t file_offset = 0;
  int writelen;
  char filepath[MAXPATHLEN];
  int fd = fds[thread_id];

  if(max_file_size == 0)
    max_file_size = MAXFILESIZE;

  for(left=length; left>0;) {
    writelen = sizeof(writebuff) < left ? sizeof(writebuff) : left;
    assert(write(fd, writebuff, writelen) == writelen);
    left -= writelen;
    file_offset += writelen;
    if(file_offset>max_file_size/num_threads) {
      lseek(fd, 0, SEEK_SET);
      file_offset = 0;
    }
  }
  snprintf(filepath, sizeof(filepath), "%s/file_write-%d", fs_path, thread_id);
  assert(unlink(filepath)>=0);
}
