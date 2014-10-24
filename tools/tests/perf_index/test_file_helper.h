#ifndef __TEST_FILE_HELPER_H_
#define __TEST_FILE_HELPER_H_

#define MAXFILESIZE 8589934592L

char* setup_tempdir();
int cleanup_tempdir();
int test_file_create(char* path, int thread_id, int num_threads, long long length);
int test_file_read_setup(char* path, int num_threads, long long length, long long max_file_size);
int test_file_read(char* path, int thread_id, int num_threads, long long length, long long max_file_size);
int test_file_read_cleanup(char* path, int num_threads, long long length);
int test_file_write_setup(char* path, int num_threads, long long length);
int test_file_write(char* path, int thread_id, int num_threads, long long length, long long max_file_size);
int test_file_write_cleanup(char* path, int num_threads, long long length);

#endif
