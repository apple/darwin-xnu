#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/time.h>
#include <pthread.h>
#include <assert.h>
#include <mach-o/dyld.h>
#include <string.h>
#include <libgen.h>
#include <unistd.h>
#include "fail.h"

typedef struct parsed_args_struct {
    char* my_name;
    char* test_name;
    int num_threads;
    long long length;
    int test_argc;
    void** test_argv;
} parsed_args_t;

typedef struct test_struct {
    int (*setup)(int, long long, int, void**);
    int (*execute)(int, int, long long, int, void**);
    int (*cleanup)(int, long long);
    char** error_str_ptr;
} test_t;

parsed_args_t args;
test_t test;
int ready_thread_count;
pthread_mutex_t ready_thread_count_lock;
pthread_cond_t start_cvar;
pthread_cond_t threads_ready_cvar;

int parse_args(int argc, char** argv, parsed_args_t* parsed_args) {
    if(argc != 4) {
        return -1;
    }

    parsed_args->my_name = argv[0];
    parsed_args->test_name = argv[1];
    parsed_args->num_threads = atoi(argv[2]);
    parsed_args->length = strtoll(argv[3], NULL, 10);
    parsed_args->test_argc = 0;
    parsed_args->test_argv = NULL;
    return 0;
}

void print_usage(char** argv) {
    printf("Usage: %s test_name threads length\n", argv[0]);
}

int find_test(char* test_name, char* test_path) {
    char binpath[MAXPATHLEN];
    char* dirpath;
    uint32_t size = sizeof(binpath);
    int retval;

    retval = _NSGetExecutablePath(binpath, &size);
    assert(retval == 0);
    dirpath = dirname(binpath);

    snprintf(test_path, MAXPATHLEN, "%s/perfindex-%s.dylib", dirpath, test_name);
    if(access(test_path, F_OK) == 0)
        return 0;
    else
        return -1;
}

int load_test(char* path, test_t* test) {
    void* handle;
    void* p;

    handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if(!handle) {
        return -1;
    }


    p = dlsym(handle, "setup");
    test->setup = (int (*)(int, long long, int, void **))p;

    p = dlsym(handle, "execute");
    test->execute = (int (*)(int, int, long long, int, void **))p;
    if(p == NULL)
        return -1;

    p = dlsym(handle, "cleanup");
    test->cleanup = (int (*)(int, long long))p;

    p = dlsym(handle, "error_str");
    test->error_str_ptr = (char**)p;

    return 0;
}

void start_timer(struct timeval *tp) {
  gettimeofday(tp, NULL);
}

void end_timer(struct timeval *tp) {
  struct timeval tend;
  gettimeofday(&tend, NULL);
  if(tend.tv_usec >= tp->tv_usec) {
    tp->tv_sec = tend.tv_sec - tp->tv_sec;
    tp->tv_usec = tend.tv_usec - tp->tv_usec;
  }
  else {
    tp->tv_sec = tend.tv_sec - tp->tv_sec - 1;
    tp->tv_usec = tend.tv_usec - tp->tv_usec + 1000000;
  }
}

void print_timer(struct timeval *tp) {
  printf("%ld.%06d\n", tp->tv_sec, tp->tv_usec);
}

static void* thread_setup(void *arg) {
  int my_index = (int)arg;
  long long work_size = args.length / args.num_threads;
  int work_remainder = args.length % args.num_threads;

  if(work_remainder > my_index) {
    work_size++;
  }

  pthread_mutex_lock(&ready_thread_count_lock);
  ready_thread_count++;
  if(ready_thread_count == args.num_threads)
    pthread_cond_signal(&threads_ready_cvar);
  pthread_cond_wait(&start_cvar, &ready_thread_count_lock);
  pthread_mutex_unlock(&ready_thread_count_lock);
  test.execute(my_index, args.num_threads, work_size, args.test_argc, args.test_argv);
  return NULL;
}

int main(int argc, char** argv) {
    int retval;
    int thread_index;
    struct timeval timer;
    pthread_t* threads;
    int thread_retval;
    void* thread_retval_ptr = &thread_retval;
    char test_path[MAXPATHLEN];

    retval = parse_args(argc, argv, &args);
    if(retval) {
        print_usage(argv);
        return -1;
    }

    retval = find_test(args.test_name, test_path);
    if(retval) {
        printf("Unable to find test %s\n", args.test_name);
        return -1;
    }

    load_test(test_path, &test);
    if(retval) {
        printf("Unable to load test %s\n", args.test_name);
        return -1;
    }

    pthread_cond_init(&threads_ready_cvar, NULL);
    pthread_cond_init(&start_cvar, NULL);
    pthread_mutex_init(&ready_thread_count_lock, NULL);
    ready_thread_count = 0;

    if(test.setup) {
        retval = test.setup(args.num_threads, args.length, 0, NULL);
        if(retval == PERFINDEX_FAILURE) {
            fprintf(stderr, "Test setup failed: %s\n", *test.error_str_ptr);
            return -1;
        }
    }

    threads = (pthread_t*)malloc(sizeof(pthread_t)*args.num_threads);
    for(thread_index = 0; thread_index < args.num_threads; thread_index++) {
        retval = pthread_create(&threads[thread_index], NULL, thread_setup, (void*)(long)thread_index);
        assert(retval == 0);
    }

    pthread_mutex_lock(&ready_thread_count_lock);
    if(ready_thread_count != args.num_threads) {
        pthread_cond_wait(&threads_ready_cvar, &ready_thread_count_lock);
    }
    pthread_mutex_unlock(&ready_thread_count_lock);

    start_timer(&timer);
    pthread_cond_broadcast(&start_cvar);
    for(thread_index = 0; thread_index < args.num_threads; thread_index++) {
        pthread_join(threads[thread_index], &thread_retval_ptr);
        if(**test.error_str_ptr) {
            printf("Test failed: %s\n", *test.error_str_ptr);
        }
    }
    end_timer(&timer);

    if(test.cleanup)
        retval = test.cleanup(args.num_threads, args.length);
        if(retval == PERFINDEX_FAILURE) {
            fprintf(stderr, "Test cleanup failed: %s\n", *test.error_str_ptr);
            free(threads);
            return -1;
        }

    print_timer(&timer);

    free(threads);

    return 0;
}
