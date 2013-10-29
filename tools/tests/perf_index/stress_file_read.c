#include <fcntl.h>
#include "perf_index.h"
#include <errno.h>

#define MAXFILESIZE 8589934592L
#define MIN(a,b) ((a)<(b) ? (a) : (b))

static char readbuff[4096];

void stress_file_read_init(const char *fs_path, int num_threads, long long length, long long max_file_size) {
  int fd;
  char filepath[MAXPATHLEN];
  long long left;
  size_t writelen;

  if(max_file_size == 0)
    max_file_size = MAXFILESIZE;

  left = MIN(length, max_file_size/num_threads);

  snprintf(filepath, sizeof(filepath), "%s/file_read", fs_path);
  fd = open(filepath, O_CREAT | O_EXCL | O_WRONLY, 0644);
  assert(fd > 0);
  bzero(readbuff, sizeof(readbuff));

  while(left > 0) {
    writelen = sizeof(readbuff) < left ? sizeof(readbuff) : left;
    assert(write(fd, readbuff, writelen) == writelen);
    left -= writelen;
  }
}

void stress_file_read(const char *fs_path, int thread_id, int num_threads, long long length, long long max_file_size) {
  long long left;
  size_t file_offset = 0;
  int readlen;
  int fd;
  char filepath[MAXPATHLEN];
  long long filesize;


  if(max_file_size == 0)
    max_file_size = MAXFILESIZE;
  filesize =  MIN(length, max_file_size/num_threads);

  snprintf(filepath, sizeof(filepath), "%s/file_read", fs_path);
  fd = open(filepath, O_RDONLY);
  assert(fd > 0);
  for(left=length; left>0;) {
    readlen = sizeof(readbuff) < left ? sizeof(readbuff) : left;
    if(file_offset+readlen > filesize) {
      lseek(fd, 0, SEEK_SET);
      file_offset = 0;
      continue;
    }
    assert(read(fd, readbuff, readlen) == readlen);
    left -= readlen;
    file_offset += readlen;
  }
}

void stress_file_read_cleanup(const char *fs_path, int num_threads, long long length) {
  char filepath[MAXPATHLEN];
  snprintf(filepath, sizeof(filepath), "%s/file_read", fs_path);
  assert(unlink(filepath)>=0);
}
