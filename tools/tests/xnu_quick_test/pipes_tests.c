/* Mach virtual memory unit tests
 *
 * The main goal of this code is to facilitate the construction,
 * running, result logging and clean up of a test suite, taking care
 * of all the scaffolding. A test suite is a sequence of very targeted
 * unit tests, each running as a separate process to isolate its
 * address space.
 * A unit test is abstracted as a unit_test_t structure, consisting of
 * a test function and a logging identifier. A test suite is a suite_t
 * structure, consisting of an unit_test_t array, a logging identifier,
 * and fixture set up and tear down functions.
 * Test suites are created dynamically. Each of its unit test runs in
 * its own fork()d process, with the fixture set up and tear down
 * running before and after each test. The parent process will log a
 * pass result if the child exits normally, and a fail result in any
 * other case (non-zero exit status, abnormal signal). The suite
 * results are then aggregated and logged, and finally the test suite
 * is destroyed.
 * Everything is logged to stdout in the standard Testbot format, which
 * can be easily converted to Munin or SimonSays logging
 * format. Logging is factored out as much as possible for future
 * flexibility. In our particular case, a unit test is logged as a
 * Testbot Test Case ([BEGIN]/[PASS]/[FAIL], and a test suite is
 * logged as a Testbot Test ([TEST]). This is confusing but
 * unfortunately cannot be avoided for compatibility. Suite results
 * are aggregated after the [SUMMARY] keyword.
 * The included test suites cover the various pipe buffer operations 
 * with dynamic expansion.
 *
 * Vishal Patel (vishal_patel@apple.com)
 */

#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <math.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <sys/sysctl.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <dispatch/dispatch.h>

/**************************/
/**************************/
/* Unit Testing Framework */
/**************************/
/**************************/					

/*********************/
/* Private interface */
/*********************/

static const char frameworkname[] = "pipes_unitester";

/* Type for test, fixture set up and fixture tear down functions. */
typedef void (*test_fn_t)();

/* Unit test structure. */
typedef struct {
     const char *name;
     test_fn_t test;
} unit_test_t;

/* Test suite structure. */
typedef struct {
     const char *name;
     int numoftests;
     test_fn_t set_up;
     unit_test_t *tests;
     test_fn_t tear_down;
} suite_t;

int _quietness = 0;
unsigned int _timeout = 0;
int _expected_signal = 0;

struct {
     uintmax_t numoftests;
     uintmax_t passed_tests;
} results = { 0, 0 };

void logr(char *format, ...) __printflike(1, 2);

static void die(int condition, const char *culprit)
{
     if (condition) {
	  printf("%s: %s error: %s.\n", frameworkname, culprit,
		 strerror(errno));
	  exit(1);
     }
}

static void die_on_stdout_error()
{
     die(ferror(stdout), "stdout");
}

/* Individual test result logging. */
void logr(char *format, ...)
{
     if (_quietness <= 1) {
	  va_list ap;
	  
	  va_start(ap, format);
	  vprintf(format, ap);
	  va_end(ap);
	  die_on_stdout_error();
     }
}

static suite_t *create_suite(const char *name, int numoftests,
			     test_fn_t set_up, unit_test_t *tests,
			     test_fn_t tear_down)
{
     suite_t *suite =  (suite_t *)malloc(sizeof(suite_t));
     die(suite == NULL, "malloc()");

     suite->name = name;
     suite->numoftests = numoftests;
     suite->set_up = set_up;
     suite->tests = tests;
     suite->tear_down = tear_down;
     return suite;
}

static void destroy_suite(suite_t *suite)
{
     free(suite);
}

static void log_suite_info(suite_t *suite)
{
     logr("[TEST] %s\n", suite->name);
     logr("Number of tests: %d\n\n", suite->numoftests);
}

static void log_suite_results(suite_t *suite, int passed_tests)
{
     results.numoftests += (uintmax_t)suite->numoftests;
     results.passed_tests += (uintmax_t)passed_tests;
}

static void log_test_info(unit_test_t *unit_test)
{
     logr("[BEGIN] %s\n", unit_test->name);
}

static void log_test_result(unit_test_t *unit_test,
			    boolean_t test_passed)
{
     logr("[%s] %s\n\n", test_passed ? "PASS" : "FAIL",
	  unit_test->name);
}

/* Handler for test time out. */
static void alarm_handler(int signo)
{
     write(1,"Child process timed out.\n",
	   strlen("Child process timed out.\n"));
     _Exit(6);
}

/* Run a test with fixture set up and teardown, while enforcing the
 * time out constraint. */
static void run_test(suite_t *suite, unit_test_t *unit_test)
{
     struct sigaction alarm_act;

     log_test_info(unit_test);
     alarm_act.sa_handler = alarm_handler;
     sigemptyset(&alarm_act.sa_mask);
     alarm_act.sa_flags = 0;
     die(sigaction(SIGALRM, &alarm_act, NULL) != 0, "sigaction()");
     alarm(_timeout);
     
     suite->set_up();
     unit_test->test();
     suite->tear_down();
}

/* Check a child return status. */
static boolean_t child_terminated_normally(int child_status)
{
     boolean_t normal_exit = FALSE;
     
     if (WIFEXITED(child_status)) {
	  int exit_status = WEXITSTATUS(child_status);
	  if (exit_status) {
	       printf("Child process unexpectedly exited with code "
		      "%d.\n", exit_status);
	  } else if (!_expected_signal) {
	       normal_exit = TRUE;
	  }
     } else if (WIFSIGNALED(child_status)) {
	  int signal = WTERMSIG(child_status);
	  if (signal == _expected_signal) {
	       if (_quietness <= 0) {
		    printf("Child process died with expected signal "
			   "%d.\n", signal);
	       }
	       normal_exit = TRUE;
	  } else {
	       printf("Child process unexpectedly died with signal "
		      "%d.\n", signal);
	  }	       
     } else {
	  printf("Child process unexpectedly did not exit nor "
		 "die.\n");
     }
     die_on_stdout_error();
     return normal_exit;
}

/* Run a test in its own process, and report the result. */
static boolean_t child_test_passed(suite_t *suite,
				   unit_test_t *unit_test)
{
     int test_status;

     pid_t test_pid = fork();
     die(test_pid == -1, "fork()");
     if (!test_pid) {
	  run_test(suite, unit_test);
	  exit(0);
     }
     while (waitpid(test_pid, &test_status, 0) != test_pid) {
	  continue;
     }
     boolean_t test_result = child_terminated_normally(test_status);
     log_test_result(unit_test, test_result);
     return test_result;
}

/* Run each test in a suite, and report the results. */
static int count_passed_suite_tests(suite_t *suite)
{
     int passed_tests = 0;
     int i;
     
     for (i = 0; i < suite->numoftests; i++) {
	  passed_tests += child_test_passed(suite,
					    &(suite->tests[i]));
     }
     return passed_tests;
}

/********************/
/* Public interface */
/********************/

#define DEFAULT_TIMEOUT 5U
#define DEFAULT_QUIETNESS 1

#define assert(condition, exit_status, ...)	\
     if (!(condition)) {			\
	  _fatal(__FILE__, __LINE__, __func__,	\
		 (exit_status),  __VA_ARGS__);	\
     }

/* Include in tests whose expected outcome is a specific signal. */
#define expect_signal(signal)				\
     struct sigaction _act;				\
     _act.sa_handler = expected_signal_handler;		\
     sigemptyset(&_act.sa_mask);			\
     _act.sa_flags = 0;					\
     assert(sigaction((signal), &_act, NULL) == 0, 1,	\
	    "sigaction() error: %s.", strerror(errno));

#define run_suite(set_up, tests, tear_down, ...)		\
     _run_suite((sizeof(tests)/sizeof(tests[0])),		\
		(set_up), (tests), (tear_down),	__VA_ARGS__)	

typedef unit_test_t UnitTests[];

void _fatal(const char *file, int line, const char *function,
	    int exit_status, const char *format, ...)
     __printflike(5, 6);
void _run_suite(int numoftests, test_fn_t set_up, UnitTests tests,
		test_fn_t tear_down, const char *format, ...)
     __printflike(5, 6);
void logv(char *format, ...) __printflike(1, 2);

void _fatal(const char *file, int line, const char *function,
	    int exit_status, const char *format, ...)
{
     va_list ap;
     
     va_start(ap, format);
     vprintf(format, ap);
     printf("\n");
     printf("Assert failed in file %s, function %s(), line %d.\n",
	    file, function, line);
     va_end(ap);
     exit(exit_status);
}
 
void _run_suite(int numoftests, test_fn_t set_up, UnitTests tests,
		test_fn_t tear_down, const char *format, ...)
{
     va_list ap;
     char *name;
     
     va_start(ap, format);
     die(vasprintf(&name, format, ap) == -1, "vasprintf()");
     va_end(ap);
     suite_t *suite = create_suite(name, numoftests, set_up, tests,
				   tear_down);
     log_suite_info(suite);
     log_suite_results(suite, count_passed_suite_tests(suite));
     free(name);
     destroy_suite(suite);
}

/* Signal handler for tests expected to terminate with a specific
 * signal. */
void expected_signal_handler(int signo)
{
     write(1,"Child process received expected signal.\n",
	   strlen("Child process received expected signal.\n"));
     _Exit(0);
}

/* Setters and getters for various test framework global
 * variables. Should only be used outside of the test, set up and tear
 * down functions. */

/* Time out constraint for running a single test. */
void set_timeout(unsigned int time)
{
     _timeout = time;
}

unsigned int get_timeout()
{
     return _timeout;
}

/* Expected signal for a test, default is 0. */
void set_expected_signal(int signal)
{
     _expected_signal = signal;
}

int get_expected_signal()
{
     return _expected_signal;
}

/* Logging verbosity. */
void set_quietness(int value)
{
     _quietness = value;
}

int get_quietness()
{
     return _quietness;
}

/* For fixture set up and tear down functions, and units tests. */
void do_nothing() {
}

/* Verbose (default) logging. */
void logv(char *format, ...)
{
     if (get_quietness() <= 0) {
	  va_list ap;
	  
	  va_start(ap, format);
	  vprintf(format, ap);
	  va_end(ap);
	  die_on_stdout_error();
     }
}

void log_aggregated_results()
{
     printf("[SUMMARY] Aggregated Test Results\n");
     printf("Total: %ju\n", results.numoftests);
     printf("Passed: %ju\n", results.passed_tests);
     printf("Failed: %ju\n\n", results.numoftests
	    - results.passed_tests);
     die_on_stdout_error();
}

/*******************************/
/*******************************/
/* pipes buffer  unit  testing */
/*******************************/
/*******************************/

static const char progname[] = "pipes_unitester";

static void die_on_error(int condition, const char *culprit)
{
     assert(!condition, 1, "%s: %s error: %s.", progname, culprit,
	    strerror(errno));
}

  
/*******************************/
/* Usage and option processing */
/*******************************/

static void usage(int exit_status)
{
     printf("Usage : %s\n", progname);
     exit(exit_status);
} 

static void die_on_invalid_value(int condition,
				 const char *value_string)
{
     if (condition) {
	  printf("%s: invalid value: %s.\n", progname, value_string);
	  usage(1);
     }
}

/* Convert a storage unit suffix into an exponent. */
static int strtoexp(const char *string)
{
     if (string[0] == '\0') {
	  return 0;
     }
     
     char first_letter =  toupper(string[0]);
     char prefixes[] = "BKMGTPE";
     const int numofprefixes = strlen(prefixes);
     prefixes[numofprefixes] = first_letter;
     int i = 0;

     while (prefixes[i] != first_letter) {
	  i++;
     }
     die_on_invalid_value(i >= numofprefixes || (string[1] != '\0' &&
						 (toupper(string[1])
						  != 'B' || string[2]
						  != '\0')), string);
     return 10 * i;
}

static void process_options(int argc, char *argv[])
{
     int opt;
     char *endptr;
  
     setvbuf(stdout, NULL, _IONBF, 0);

     set_timeout(DEFAULT_TIMEOUT);
     set_quietness(DEFAULT_QUIETNESS);
     
     while ((opt = getopt(argc, argv, "t:vqh")) != -1) {
	  switch (opt) {
	  case 't': 
	       errno = 0;
	       set_timeout(strtoul(optarg, &endptr, 0));
	       die_on_invalid_value(errno == ERANGE || *endptr != '\0'
				    || endptr == optarg, optarg);
	       break;
	  case 'q':
	       set_quietness(get_quietness() + 1);
	       break;
	  case 'v':
	       set_quietness(0);
	       break;
	  case 'h':
	       usage(0);
	       break;
	  default:
	       usage(1);
	       break;
	  }
     }
}

/*********************************/
/* Various function declarations */
/*********************************/

void initialize_data(int *ptr, int len);

int verify_data(int *base, int *target, int len);

void clear_data(int *ptr, int len);

/*******************************/
/* Arrays for test suite loops */
/*******************************/

#define BUFMAX 20000
#define BUFMAXLEN (BUFMAX * sizeof(int))

const unsigned int pipesize_blocks[] = {128,256,1024,2048,PAGE_SIZE,PAGE_SIZE*2,PAGE_SIZE*4};
static const int bufsizes[] = { 128, 512, 1024, 2048, 4096, 16384  };

int data[BUFMAX],readbuf[BUFMAX];
int pipefd[2] = {0,0};

typedef int * pipe_t;

struct thread_work_data {
	pipe_t p;
	unsigned int total_bytes;
	unsigned int chunk_size;
};

void * reader_thread(void *ptr);
void * writer_thread(void *ptr);

dispatch_semaphore_t r_sem, w_sem;

unsigned long current_buf_size=0;

/*************************************/
/* Global variables set up functions */
/*************************************/


void initialize_data(int *ptr, int len)
{
        int i;
        if (!ptr || len <=0 )
                return;

        for (i = 0; i < len; i ++)
                ptr[i] = i;
}

void clear_data(int *ptr, int len)
{

        int i;
        if (!ptr)
                return;
        for (i = 0; i < len; i++)
                ptr[i]=0;
}

int verify_data(int *base, int *target, int len)
{
        int i = 0;
        
        if (!base || !target)
                return 0;
        
        for (i = 0; i < len; i++){
                if (base[i] != target[i])
                        return 0;
        }

        return 1;
}

void initialize_data_buffer()
{
	initialize_data(data, BUFMAX);
	initialize_data(readbuf, BUFMAX);
}

/*******************************/
/* core read write helper funtions */
/*******************************/

ssize_t read_whole_buffer(pipe_t p, void *scratch_buf, int size);
ssize_t pipe_read_data(pipe_t p, void *dest_buf, int size);
ssize_t pipe_write_data(pipe_t p, void *src_buf, int size);

ssize_t read_whole_buffer(pipe_t p, void *scratch_buf, int size)
{
	int fd = p[0];
	logv("reading whole buffer from fd %d, size %d", fd, size);
	int retval = pread(fd, scratch_buf, size, 0);
	if (retval == -1 ){
		logv("Error reading whole buffer. (%d) %s\n",errno, strerror(errno));
	}
	return retval;

}

ssize_t pipe_read_data(pipe_t p, void *dest_buf, int size)
{
	int fd = p[0];
	//logv("reading from pipe %d, for size %d", fd, size);
	int retval = read(fd, dest_buf, size);
	if (retval == -1) {
		logv("Error reading from buffer. (%d)",errno);	
	}
	return retval;
}

ssize_t pipe_write_data(pipe_t p, void *src_buf, int size)
{
	int fd = p[1];
	//logv("writing to pipe %d, for size %d", fd, size);
	int retval = write(fd, src_buf, size);
	if (retval == -1) {
		logv("Error writing to buffer. (%d) %s",errno, strerror(errno));	
	}
	return retval;
}


void * reader_thread(void *ptr)
{
     	struct thread_work_data *m;
     	m = (struct thread_work_data *) ptr;
    	int i = m->total_bytes/m->chunk_size;
	int retval, data_idx=0;
 	while (i > 0){
     		dispatch_semaphore_wait(r_sem, 8000);
     		retval = pipe_read_data(m->p, &readbuf[data_idx], m->chunk_size);
		assert(retval == m->chunk_size, 1, "Pipe read returned different amount of numbe");
		data_idx +=m->chunk_size;
		//logv("RD %d \n", m->chunk_size);
     		dispatch_semaphore_signal(w_sem);
		i--;
	}
     	return 0;
}

void * writer_thread(void *ptr)
{
	struct thread_work_data *m;
	m = (struct thread_work_data *)ptr;
	int i = m->total_bytes/m->chunk_size;
	int retval, data_idx=0;
	while ( i > 0 ){

		dispatch_semaphore_wait(w_sem, 8000);
		//logv("WR %d \n", m->chunk_size);
		retval=pipe_write_data(m->p, &data[data_idx], m->chunk_size);
                assert(retval == m->chunk_size, 1, "Pipe write failed");
		data_idx +=m->chunk_size;
		dispatch_semaphore_signal(r_sem);
		i--;
	}
	return 0;
}


void create_threads(struct thread_work_data *rdata, struct thread_work_data *wdata){

	pthread_t thread1, thread2;
	r_sem = dispatch_semaphore_create(0);
	w_sem = dispatch_semaphore_create(1);
	int iret1, iret2;
	void * thread_ret1 =0;
	void * thread_ret2 =0;
	/* Create independent threads each of which will execute function */

	iret1 = pthread_create( &thread1, NULL, reader_thread, (void*) rdata);
	iret2 = pthread_create( &thread2, NULL, writer_thread, (void*) wdata);

	pthread_join( thread2, &thread_ret1);
	pthread_join( thread1, &thread_ret1);
	assert(thread_ret1 == 0, 1, "Reader Thread Failed");
	assert(thread_ret2 == 0, 1, "Writer Thread Failed");
}


/*******************************/
/* Pipes unit test functions   */
/*******************************/
void test_pipebuffer_setup ()
{

	logv("Setting up buffers data and readbuf\n");
	clear_data(data, BUFMAX);
	clear_data(readbuf, BUFMAX);
	logv("Initializing buffers data and readbuf\n");
	initialize_data(data, BUFMAX);
	initialize_data(readbuf, BUFMAX);
	logv("verifying data for correctness\n");
	die_on_error(!verify_data(data, readbuf, BUFMAX), "data initialization");
	clear_data(readbuf, BUFMAX);
}

void test_pipe_create(){
	int pipefds[2] = {0,0};
	pipe_t p = pipefds;
	int err = pipe(p);
	if ( err ){
		logv("error opening pipes (%d) %s", errno, strerror(errno));
		return;
	}

	die_on_error(0 != close(pipefds[0]), "close()");
	die_on_error(0 != close(pipefds[1]), "close()");
}

void test_pipe_write_single_byte(){
	int pipefds[2] = { 0 , 0 };
	pipe_t p = pipefds;
	die_on_error( 0 != pipe(p), "pipe()");
	initialize_data_buffer();
	int i = 0,retval;
	for ( ; i < current_buf_size; i++){
		if ( i > 16384){
			logv("cannot fill continuously beyond 16K.");
			break;
		}
		retval=pipe_write_data(p, &data[i], 1);
		assert(retval == 1, 1, "Pipe write failed");
	}

	close(p[0]);
	close(p[1]);
}

void test_pipe_single_read_write(){
	int pipefds[2] = { 0 , 0 };
        pipe_t p = pipefds;
        die_on_error( 0 != pipe(p), "pipe()");
        initialize_data_buffer();
	struct thread_work_data d = { p, current_buf_size, 1};
	create_threads(&d, &d);
        verify_data(data, readbuf, current_buf_size);
        close(p[0]);
        close(p[1]);

}

void test_pipe_single_read_2write(){
	int pipefds[2] = { 0 , 0 };
        pipe_t p = pipefds;
        die_on_error( 0 != pipe(p), "pipe()");
        initialize_data_buffer();
	struct thread_work_data rd = { p, current_buf_size, 1};
	struct thread_work_data wd = { p, current_buf_size, 2};
	create_threads(&rd, &wd);
        verify_data(data, readbuf, current_buf_size);
        close(p[0]);
        close(p[1]);

}

void test_pipe_expansion_buffer(){
	int pipefds[2] = { 0 , 0 };
	int iter = 0;
        pipe_t p = pipefds;
        die_on_error( 0 != pipe(p), "pipe()");
        initialize_data_buffer();
	for ( iter=0; iter < sizeof(pipesize_blocks)/sizeof(unsigned int); iter++){
		assert(pipesize_blocks[iter] == pipe_write_data(p, &data[0], pipesize_blocks[iter] ), 1, "expansion write failed");
		assert(pipesize_blocks[iter] == pipe_read_data(p, &readbuf[0], pipesize_blocks[iter]+200), 1, "reading from expanded data failed");
	/*	logv("finished round for size %u \n", pipesize_blocks[iter]); */
	}
        verify_data(data, readbuf, current_buf_size);
        close(p[0]);
        close(p[1]);

}

void test_pipe_initial_big_allocation(){
        int pipefds[2] = { 0 , 0 };
        int iter = 0;
        pipe_t p = pipefds;
        die_on_error( 0 != pipe(p), "pipe()");
        initialize_data_buffer();
        assert(current_buf_size == pipe_write_data(p, &data[0], current_buf_size ), 1, "initial big allocation failed");
        assert(current_buf_size == pipe_read_data(p, &readbuf[0], current_buf_size+200), 1, "reading from initial big write failed");
        assert(verify_data(data, readbuf, current_buf_size), 1, "big pipe initial allocation -not able to verify data");
        close(p[0]);
        close(p[1]);

}

void test_pipe_cycle_small_writes(){
        int pipefds[2] = { 0 , 0 };
        int iter = 0;
        pipe_t p = pipefds;
        die_on_error( 0 != pipe(p), "pipe()");
        initialize_data_buffer();
	int buf_size = current_buf_size / 2;
        
	assert(buf_size == pipe_write_data(p, &data[0], buf_size ), 1, "cycle  write failed");
        assert(buf_size == pipe_read_data(p, &readbuf[0], buf_size+200), 1, "reading from cycle read failed");
        assert(verify_data(data, readbuf, buf_size), 1, "data verification failed");
        
	assert(buf_size == pipe_write_data(p, &data[0], buf_size ), 1, "cycle  write failed");
        assert(buf_size == pipe_read_data(p, &readbuf[0], buf_size+200), 1, "reading from cycle read failed");
        assert(verify_data(data, readbuf, buf_size), 1, "data verification failed");
        
	assert(buf_size == pipe_write_data(p, &data[0], buf_size ), 1, "cycle  write failed");
        assert(buf_size == pipe_read_data(p, &readbuf[0], buf_size+200), 1, "reading from cycle read failed");
        assert(verify_data(data, readbuf, buf_size), 1, "data verification failed");
        
	close(p[0]);
        close(p[1]);

}
 
void test_pipe_moving_data(){
        int pipefds[2] = { 0 , 0 };
        int iter = 0;
        pipe_t p = pipefds;
        die_on_error( 0 != pipe(p), "pipe()");
        initialize_data_buffer();
	int buf_size = current_buf_size / 2;
	if (buf_size > PAGE_SIZE)
		buf_size = PAGE_SIZE;
        
	assert(buf_size == pipe_write_data(p, &data[0], buf_size ), 1, "cycle  write failed");
        logv("write of size =%d\n", buf_size);
	assert(buf_size == pipe_write_data(p, &data[buf_size/sizeof(int)], buf_size ), 1, "cycle  write failed");
        logv("write of size =%d\n", buf_size*2);
	assert(buf_size == pipe_write_data(p, &data[(buf_size*2)/sizeof(int)], buf_size ), 1, "cycle  write failed");
        logv("write of size =%d\n", buf_size*3);
        assert((3*buf_size) == pipe_read_data(p, &readbuf[0], (3*buf_size)+200), 1, "reading from cycle read failed");
        assert(verify_data(data, readbuf, (3*buf_size)/sizeof(int)), 1, "data verification failed");
        
	close(p[0]);
        close(p[1]);

}
    

/*************/
/* pipe Suites */
/*************/

void run_pipe_basic_tests()
{
     int sizes_idx;
     int numofsizes = sizeof(bufsizes)/sizeof(int);

     logv("running tests for %d different sizes \n", numofsizes);

     UnitTests pipe_basic_tests = {
	  { "1. create buffer and verify both reads/writes are valid",
	    test_pipebuffer_setup },
	  { "2. open and close pipes", test_pipe_create },
	  { "3. single byte write to full", test_pipe_write_single_byte},
	  { "4. single byte read/write in sync", test_pipe_single_read_write},
	  { "5. single byte read/2write in sync", test_pipe_single_read_2write},
	  { "6. expansion from existing size", test_pipe_expansion_buffer},
	  { "7. initial big allocation " , test_pipe_initial_big_allocation},
	  { "8. cycle_small_writes " ,test_pipe_cycle_small_writes },
	  { "9. test moving data " ,test_pipe_moving_data }
     };
  for (sizes_idx = 0; sizes_idx < numofsizes; sizes_idx++) {
       current_buf_size = bufsizes[sizes_idx];
       run_suite(do_nothing,
		 pipe_basic_tests,
		 do_nothing, "pipe create base test "
		 "Size: 0x%jx (%ju)",
		 (uintmax_t)bufsizes[sizes_idx],
		 (uintmax_t)bufsizes[sizes_idx]);
  }
}


int pipes_test(void *the_argp)
{
     set_quietness(2);
     run_pipe_basic_tests();
     //log_aggregated_results();
     return results.numoftests - results.passed_tests;
}

/*
 * retaining the old main function to debug issues with the tests and not the xnu_quick_test framework
 * or the system
 */
int main_nonuse(int argc, char *argv[])
{
     process_options(argc, argv);
     
     run_pipe_basic_tests();
     
     log_aggregated_results();
     return 0;
}
