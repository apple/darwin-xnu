#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <pthread.h>
#include "perf_index.h"
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>

#define CONTROL_PORT 17694

static const stress_test_t *stress_tests[] = 
{&cpu_test, &memory_test, &syscall_test, &fault_test, &zfod_test,
  &file_local_create_test, &file_local_write_test, &file_local_read_test,
  &file_ram_create_test, &file_ram_read_test, &file_ram_write_test, &iperf_test,
  &compile_test
};

static int num_threads;
static long long all_len;
static int test_type;
static const char *control_host = NULL;
static const char **test_argv;
static int test_argc;
struct in_addr control_host_addr;
int control_sock;
const char remote_str[] = "remote";
const char ready_msg[] = "Ready";
const char done_msg[] = "Done";

static pthread_cond_t threads_running_cvar;
static pthread_cond_t start_cvar;
static int thread_count;
static pthread_mutex_t count_lock;

static void usage() {
  int i;
  fprintf(stderr, "usage: perf_index remote server\n"
    "or\n"
    "usage: pref_index type threads size [args]\n\n"
    "where type is one of:\n");
  for(i=0; i<sizeof(stress_tests)/sizeof(stress_test_t*); i++) {
    fprintf(stderr, "%s ", stress_tests[i]->name);
  }
  fprintf(stderr, "\n");
  exit(1);
}

static int validate_args(int argc, const char **argv) {
  int i;
  int ret;
  int found = 0;

  if(argc < 3) {
    return -1;
  }
  if(argc==3 && strcmp(argv[1], remote_str) == 0)
    return 0;
  

  if(argc < 4)
    return -1;

  ret = -1;
  for(i=0; i<sizeof(stress_tests)/sizeof(stress_test_t*); i++) {
    if(strcmp(argv[1], stress_tests[i]->name) == 0) {
      ret = i;
      found = 1;
      break;
    }
  }

  if(!found)
    return -1;

  if(stress_tests[i]->validate(argc-4, argv+4))
    return ret;
  else
    return -1;
}

int host_to_addr(const char *hostname, struct in_addr *addr) {
  struct addrinfo *info;
  int err;
  if((err = getaddrinfo(hostname, NULL, NULL, &info)) != 0) {
    return -1;
  }
  *addr = ((struct sockaddr_in*)info->ai_addr)->sin_addr;
  freeaddrinfo(info);
  return 0;
}

static void parse_args(int argc, const char **argv);

static void read_params_from_server(void) {
  struct sockaddr_in addr;
  char readbuff[1024];
  int zerocount = 0;
  ssize_t offset = 0;
  ssize_t recv_count;
  ssize_t i;
  const char **newargv = malloc(sizeof(char*) * 4);
  assert(newargv != NULL);

  if(host_to_addr(control_host, &control_host_addr)<0) {
    fprintf(stderr, "Could not resolve: %s\n", control_host);
    exit(2);
  }
  
  control_sock  = socket(PF_INET, SOCK_STREAM, 0);
  assert(control_sock != -1);
  addr.sin_family = AF_INET;
  addr.sin_port = htons(CONTROL_PORT);
  addr.sin_addr = control_host_addr;
  bzero(addr.sin_zero, sizeof addr.sin_zero);
  if(connect(control_sock, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1) {
    fprintf(stderr, "Failed to connect to host: %s\n", control_host);
    exit(3);
  }

  while(offset<sizeof(readbuff)) {
    recv_count = recv(control_sock, readbuff+offset, sizeof(readbuff) - offset, 0);
    if(recv_count<0) {
      fprintf(stderr, "Failed to receive parameters\n");
      exit(3);
    }

    /* Guard against bad input */
    readbuff[sizeof(readbuff)-1] = '\0';
    newargv[1] = strdup(readbuff);
    for(i=offset; i<offset+recv_count; i++) {
      if(readbuff[i] == '\0') {
        zerocount++;
        newargv[zerocount+1] = strdup(&readbuff[i+1]);
      }
    }
    offset += recv_count;
    if(offset>=2 && readbuff[offset-1] == '\0' && readbuff[offset-2] == '\0')
      break;
  }
  if(zerocount < 3) {
    fprintf(stderr, "Received invalid parameters");
    exit(4);
  }

  parse_args(zerocount+1, newargv);
}

static void parse_args(int argc, const char **argv) {
  test_type = validate_args(argc, argv);
  if(test_type < 0)
    usage();
  if(strcmp(argv[1], remote_str) == 0) {
    control_host = argv[2];
    read_params_from_server();
  }
  else {
    num_threads = strtoimax(argv[2], NULL, 10);
    all_len = strtoll(argv[3], NULL, 10);
    test_argc = argc - 4;
    test_argv = argv + 4;
  }
}

static void *stress_loop(void *data) {
  int my_index = (int)data;
  long long work_size = all_len / num_threads;
  int work_remainder = all_len % num_threads;

  if(work_remainder > my_index) {
    work_size++;
  }

  pthread_mutex_lock(&count_lock);
  thread_count++;
  if(thread_count == num_threads)
    pthread_cond_signal(&threads_running_cvar);
  pthread_cond_wait(&start_cvar, &count_lock);
  pthread_mutex_unlock(&count_lock);
  stress_tests[test_type]->stress(my_index, num_threads, work_size, test_argc, test_argv);
  return NULL;
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
  printf("%ld.%06d", tp->tv_sec, tp->tv_usec);
}

void wait_start(void) {
  char readbuff[1024];
  if(control_host != NULL) {
    send(control_sock, ready_msg, strlen(ready_msg), 0);
    while(recv(control_sock, readbuff, sizeof(readbuff), 0)>0);
  }
}

void done(void) {
  send(control_sock, done_msg, strlen(done_msg), 0);
}

int main(int argc, const char **argv) {
  int thread_index;
  pthread_t *threads;
  parse_args(argc, argv);
  struct timeval timer;

  stress_tests[test_type]->init(num_threads, all_len, test_argc, test_argv);
  pthread_cond_init(&threads_running_cvar, NULL);
  pthread_cond_init(&start_cvar, NULL);
  pthread_mutex_init(&count_lock, NULL);
  thread_count = 0;

  threads = (pthread_t*)malloc(sizeof(pthread_t)*num_threads);
  for(thread_index = 0; thread_index < num_threads; thread_index++) {
    assert(pthread_create(&threads[thread_index], NULL, stress_loop, (void*)thread_index) == 0);
  }

  pthread_mutex_lock(&count_lock);
  if(thread_count != num_threads)
    pthread_cond_wait(&threads_running_cvar, &count_lock);
  pthread_mutex_unlock(&count_lock);

  wait_start();

  start_timer(&timer);
  pthread_cond_broadcast(&start_cvar);
  for(thread_index = 0; thread_index < num_threads; thread_index++) {
    pthread_join(threads[thread_index], NULL);
  }
  end_timer(&timer);
  done();

  pthread_mutex_destroy(&count_lock);
  pthread_cond_destroy(&start_cvar);
  pthread_cond_destroy(&threads_running_cvar);

  stress_tests[test_type]->cleanup(num_threads, all_len);

  print_timer(&timer);
  printf("\n");

  return 0;
}
