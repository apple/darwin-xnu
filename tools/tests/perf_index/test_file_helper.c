#include "test_file_helper.h"
#include "fail.h"
#include <stdlib.h>
#include <fcntl.h>
#include <sys/param.h>
#include <assert.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>

static char readbuff[4096];
static char writebuff[4096];
static int* fds = NULL;

char* setup_tempdir(char* buf) {
    strcpy(buf, "/tmp/perfindex.XXXXXX");
    return mkdtemp(buf);
}

int cleanup_tempdir(char* path) {
    return rmdir(path);
}

int test_file_create(char* path, int thread_id, int num_threads, long long length) {
  long long i;
  int fd;
  int retval;
  char filepath[MAXPATHLEN];

  for(i=0; i<length; i++) {
    snprintf(filepath, MAXPATHLEN, "%s/file_create-%d-%lld", path, thread_id, i);
    fd = open(filepath, O_CREAT | O_EXCL | O_WRONLY, 0644);
    VERIFY(fd >= 0, "open failed");

    close(fd);
  }

  for(i=0; i<length; i++) {
    snprintf(filepath, MAXPATHLEN, "%s/file_create-%d-%lld", path, thread_id, i);
    retval = unlink(filepath);
    VERIFY(retval == 0, "unlink failed");
  }

  return PERFINDEX_SUCCESS;
}

int test_file_read_setup(char* path, int num_threads, long long length, long long max_file_size) {
    int fd;
    char filepath[MAXPATHLEN];
    long long left;
    int retval;
    size_t writelen;

    if(max_file_size == 0)
        max_file_size = MAXFILESIZE;

    left = MIN(length, max_file_size/num_threads);

    snprintf(filepath, sizeof(filepath), "%s/file_read", path);
    fd = open(filepath, O_CREAT | O_EXCL | O_WRONLY, 0644);
    printf("%d\n", fd);
    VERIFY(fd >= 0, "open failed");

    bzero(readbuff, sizeof(readbuff));

    while(left > 0) {
        writelen = sizeof(readbuff) < left ? sizeof(readbuff) : left;
        retval = write(fd, readbuff, writelen);
        VERIFY(retval == writelen, "write failed");
        left -= writelen;
    }

    return PERFINDEX_SUCCESS;
}

int test_file_read(char* path, int thread_id, int num_threads, long long length, long long max_file_size) {
    long long left;
    size_t file_offset = 0;
    int readlen;
    int fd;
    int retval;
    char filepath[MAXPATHLEN];
    long long filesize;


    if(max_file_size == 0)
        max_file_size = MAXFILESIZE;
    filesize =  MIN(length, max_file_size/num_threads);

    snprintf(filepath, sizeof(filepath), "%s/file_read", path);
    fd = open(filepath, O_RDONLY);
    VERIFY(fd >= 0, "open failed");

    for(left=length; left>0;) {
        readlen = sizeof(readbuff) < left ? sizeof(readbuff) : left;
        if(file_offset+readlen > filesize) {
            retval = lseek(fd, 0, SEEK_SET);


            VERIFY(retval >= 0, "lseek failed");

            file_offset = 0;
            continue;
        }
        retval = read(fd, readbuff, readlen);
        VERIFY(retval == readlen, "read failed");
        left -= readlen;
        file_offset += readlen;
    }
    return PERFINDEX_SUCCESS;
}

int test_file_read_cleanup(char* path, int num_threads, long long length) {
    char filepath[MAXPATHLEN];
    int retval;

    snprintf(filepath, sizeof(filepath), "%s/file_read", path);
    retval = unlink(filepath);
    VERIFY(retval == 0, "unlink failed");

    return PERFINDEX_SUCCESS;
}

int test_file_write_setup(char* path, int num_threads, long long length) {
    int i;
    char filepath[MAXPATHLEN];

    if(fds == NULL) {
        fds = (int*)malloc(sizeof(int)*num_threads);
        VERIFY(fds, "malloc failed");
    }

    for(i=0; i<num_threads; i++) {
        snprintf(filepath, sizeof(filepath), "%s/file_write-%d", path, i);
        fds[i] = open(filepath, O_CREAT | O_EXCL | O_WRONLY, 0644);
        if(fds[i] < 0) {
            free(fds);
            fds = NULL;
            FAIL("open failed");
        }
    }

    bzero(writebuff, sizeof(writebuff));

    return PERFINDEX_SUCCESS;
}

int test_file_write(char* path, int thread_id, int num_threads, long long length, long long max_file_size) {
    long long left;
    size_t file_offset = 0;
    int writelen;
    int retval;
    int fd = fds[thread_id];

    if(max_file_size == 0)
        max_file_size = MAXFILESIZE;

    for(left=length; left>0;) {
        writelen = sizeof(writebuff) < left ? sizeof(writebuff) : left;
        retval = write(fd, writebuff, writelen);
        VERIFY(retval == writelen, "write failed");

        left -= writelen;
        file_offset += writelen;
        if(file_offset>max_file_size/num_threads) {
            retval = lseek(fd, 0, SEEK_SET);
            VERIFY(retval >= 0, "leeks failed");
            file_offset = 0;
        }
    }

    return PERFINDEX_SUCCESS;
}


int test_file_write_cleanup(char* path, int num_threads, long long length) {
    int i;
    char filepath[MAXPATHLEN];
    int retval;

    for(i=0; i<num_threads; i++) {
        snprintf(filepath, sizeof(filepath), "%s/file_write-%d", path, i);
        retval = unlink(filepath);
        VERIFY(retval == 0, "unlink failed");
    }

    return PERFINDEX_SUCCESS;
}
