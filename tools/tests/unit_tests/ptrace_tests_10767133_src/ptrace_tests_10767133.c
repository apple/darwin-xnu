/*
 * File: ptrace_tests_10767133.c
 * Test Description: Testing different functions of the ptrace call.
 * Radar: <rdar://problem/10767133>
 * compile command: cc -o ../BUILD/ptrace_tests_10767133 ptrace_tests_10767133.c 
 */
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <sys/wait.h>

#define assert_condition(condition, exit_status, cause)     \
     if (!(condition)) {                        \
          printf("[FAILED] %s:%s at %d error: %s \n", "test_10767133", __func__ , __LINE__, cause ); \
	  if (errno) \
		perror(cause); \
          exit(exit_status);  \
     }  \

#define log_message(msg)	\
	printf("%s:%d -> %s \n", __func__, __LINE__, msg); 


typedef int * pipe_t;

ssize_t pipe_read_data(pipe_t p, void *dest_buf, int size)
{
        int fd = p[0];
        int retval = read(fd, dest_buf, size);
        if (retval == -1) {
                printf("Error reading from buffer. ");
		perror("pipe_read");
        }
        return retval;
}

ssize_t pipe_write_data(pipe_t p, void *src_buf, int size)
{
        int fd = p[1];
        int retval = write(fd, src_buf, size);
        if (retval == -1) {
                printf("Error writing to buffer. ");
		perror("pipe_write");
        }
        return retval;
}



void test_ptrace_deny_tace_sigexc();
void test_ptrace_attach_detach();
void test_ptrace_step_kill();

int main(){
	int retval =0;
        log_message(" Testing for PT_FORCEQUOTA. it should return EPERM for non root program. ");
	errno=0;
	retval = ptrace(PT_FORCEQUOTA, getpid(), NULL, 0);
	assert_condition( (retval == -1 && errno == EPERM), -1, "PT_FORCEQUOTA");
	
	log_message(" Testing to PT_DENY_ATTACH. should return successfully as nobody is tracing me.")
	retval = ptrace(PT_DENY_ATTACH, getpid(), NULL, 0);	
	assert_condition (retval == 0 , -2, "PR_DENY_ATTACH");
	test_ptrace_deny_tace_sigexc();
	test_ptrace_attach_detach();
	test_ptrace_step_kill();
    success: 
        printf("[PASSED] Test test_10767133 passed. \n");
        return 0;
    fail:
        printf("[FAILED] Test test_10767133 failed. \n");
        return -1;
}

void test_ptrace_step_kill(){
	int retval = 0, status=1;
	int parentpipe[2], childpipe[2], data;
	enum data_state  { begin, finished_child_loop, finished_parent_detach };
	retval = pipe(childpipe);
	assert_condition(retval == 0, -1, "Pipe create");
	retval = pipe(parentpipe);
	assert_condition(retval == 0, -1, "Pipe create");
	int childpid = fork();
	assert_condition(childpid >=0, -1, "fork failed");

	if (childpid == 0){ /* child */
		pipe_read_data(parentpipe, &data, sizeof(data));
		assert_condition(data == begin, -1, "child: parent not setting begin");
		pipe_write_data(childpipe, &data, sizeof(data));
		log_message("child: running the sleep loop");
		int i = 5;
		log_message("child: sleep loop");
		while (i-- > 0){
			sleep(1);
			printf(".z.\n");
		}
		data = finished_child_loop;
		log_message("child: finished sleep loop");
		pipe_write_data(childpipe, &data, sizeof(data));
		pipe_read_data(parentpipe, &data, sizeof(data));
		assert_condition(data == finished_parent_detach, -1, "child: parent not done with detach");
		i = 5;
		log_message("child: sleep loop 2");
		while (i-- > 0){
			sleep(1);
			printf(".Z.\n");
		}
		exit(57);
	}else{  /* parent */
		data = begin;
		pipe_write_data(parentpipe, &data, sizeof(data));
		data = getpid();
		pipe_read_data(childpipe, &data, sizeof(data));
		assert_condition(data == begin, -1, "child is not ready with TRACE_ME setup");
		printf("parent: attaching to child with pid %d \n", childpid);
		retval = ptrace(PT_ATTACH, childpid, NULL, 0);
		assert_condition(retval == 0,  -1, "parent: failed to attach to child");
		sleep(2);
		log_message("parent: attached to child. Now PT_STEP through it");
		retval = ptrace(PT_STEP, childpid, (caddr_t)1, 0);
		assert_condition(retval == 0, -1, "parent: failed to continue the child");
		sleep(2);
		retval = ptrace(PT_STEP, childpid, (caddr_t)1, 0);
		assert_condition(retval == 0, -1, "parent: failed to continue the child");
		log_message("parent: issuing PT_KILL to child ");
		sleep(2);
		retval = ptrace(PT_KILL, childpid, NULL, 0);
		assert_condition(retval == 0, -1, "parent: failed to PT_KILL the child");
		data = finished_parent_detach;
		pipe_write_data(parentpipe, &data, sizeof(data));
		waitpid(childpid,&status,0);
		assert_condition(status != 57, -1, "child has exited successfully. It should have died with signal 9");
		assert_condition(status == 9, -1, "child has exited unexpectedly. Should have died with signal 9");
	}

}

void test_ptrace_attach_detach(){
	int retval = 0, status=1;
	int parentpipe[2], childpipe[2], data;
	enum data_state  { begin, finished_child_loop, finished_parent_detach };
	retval = pipe(childpipe);
	assert_condition(retval == 0, -1, "Pipe create");
	retval = pipe(parentpipe);
	assert_condition(retval == 0, -1, "Pipe create");
	int childpid = fork();
	assert_condition(childpid >=0, -1, "fork failed");

	if (childpid == 0){ /* child */
		//retval = ptrace(PT_TRACE_ME, getpid(), NULL, 0);
		//assert_condition(retval == 0, -1, "PT_TRACE_ME failed");
		pipe_read_data(parentpipe, &data, sizeof(data));
		assert_condition(data == begin, -1, "child: parent not setting begin");
		pipe_write_data(childpipe, &data, sizeof(data));
		log_message("child: running the sleep loop");
		int i = 5;
		log_message("child: sleep looping");
		while (i-- > 0){
			sleep(1);
			printf(".z.\n");
		}
		data = finished_child_loop;
		log_message("child: finished sleep loop");
		pipe_write_data(childpipe, &data, sizeof(data));
		pipe_read_data(parentpipe, &data, sizeof(data));
		assert_condition(data == finished_parent_detach, -1, "child: parent not done with detach");
		i = 5;
		log_message("child sleep looping too");
		while (i-- > 0){
			sleep(1);
			printf(".Z.\n");
		}
		exit(0);
	}else{  /* parent */
		data = begin;
		pipe_write_data(parentpipe, &data, sizeof(data));
		data = getpid();
		pipe_read_data(childpipe, &data, sizeof(data));
		assert_condition(data == begin, -1, "child is not ready with TRACE_ME setup");
		printf("parent: attaching to child with pid %d \n", childpid);
		retval = ptrace(PT_ATTACH, childpid, NULL, 0);
		assert_condition(retval == 0,  -1, "parent: failed to attach to child");
		sleep(2);
		log_message("parent: attached to child. Now continuing it");
		retval = ptrace(PT_CONTINUE, childpid, (caddr_t)1, 0);
		assert_condition(retval == 0, -1, "parent: failed to continue the child");

		pipe_read_data(childpipe, &data, sizeof(data));
		assert_condition(data == finished_child_loop, -1, "parent: child has not finished while loop");
		
		retval = kill(childpid, SIGSTOP);
		assert_condition(retval == 0, -1, "parent: failed to SIGSTOP child");
		sleep(2);

		log_message("parent: child has finished loop. Now detaching the child");
		retval = ptrace(PT_DETACH, childpid, NULL, 0);
		assert_condition(retval == 0, -1, "parent: failed to detach");

		data = finished_parent_detach;
		pipe_write_data(parentpipe, &data, sizeof(data));
		waitpid(childpid,&status,0);
		assert_condition(status == 0, -1, "child has exited unexpectedly");
	}
}


void test_ptrace_deny_tace_sigexc(){
	enum ptrace_state { begin,denied_attach, sigexc_tested,trace_me_set,  attached, stepped, continued, killed };
	int retval =0;
	int childpipe[2],parentpipe[2], data[2];
	retval = pipe(childpipe);
	assert_condition( retval == 0, -3, "Pipe create");
	retval = pipe(parentpipe);
	assert_condition( retval == 0, -3, "Pipe create");

	data[0] = begin; // parent
	data[1] = begin; //child

	int childpid = fork();
	int status = 0;
	assert_condition(childpid >=0, -4, "fork failed");

	if (childpid == 0){
		/* child */
		retval = ptrace(PT_DENY_ATTACH, getpid(), NULL,0);
		data[1] = denied_attach;
		pipe_write_data(childpipe, &data[1], sizeof(int));
		log_message("child: waiting for parent to write something");
		pipe_read_data(parentpipe, &data[0], sizeof(int));
		assert_condition(data[0] == begin , -5, "child: parent didnt begin with right state");

		/* waiting for parent to verify that PT_SIGEXC fails since child is not yet traced. */

		pipe_read_data(parentpipe, &data[0], sizeof(int));
		assert_condition(data[0] == sigexc_tested, -5, " child: parent didnt test for sigexc failure");
		log_message("child: setting myself to be traced");
		retval = ptrace(PT_TRACE_ME, getpid(), NULL ,0);
		assert_condition(retval == 0, -6, "child: failed to setmyself for tracing");
		data[1]=trace_me_set;
		pipe_write_data(childpipe, &data[1], sizeof(int));
		log_message("child: setting signals to be exceptions. PT_SIGEXC");
		retval = ptrace(PT_SIGEXC, getpid(), NULL, 0);
		assert_condition(retval == 0, -7, "child: failed to set PT_SIGEXC");
		
		exit(0);
		
	}else {
		/* parent */
		// get status of child
		pipe_read_data(childpipe, &data[1], sizeof(int));
		assert_condition(data[1] == denied_attach, -5, "parent: deny_attach_check");
		pipe_write_data(parentpipe, &data[0], sizeof(int));
		
		log_message("parent: testing for failure fo PT_SIGEXC ");
		retval = ptrace(PT_SIGEXC, childpid, NULL, 0);
		assert_condition(retval < 0 , -5, "PT_SIGEXC did not fail for untraced child");
		data[0] = sigexc_tested;
		pipe_write_data(parentpipe, &data[0], sizeof(int));

		pipe_read_data(childpipe, &data[1], sizeof(int));
		assert_condition(data[1] == trace_me_set , -7, "parent: child has not set PT_TRACE_ME");

		waitpid(childpid, &status, 0); 
		if ( status != 0){
			log_message("Child exited with non zero status");
		}
	}

	close(childpipe[0]);
	close(childpipe[1]);

	close(parentpipe[0]);
	close(parentpipe[1]);

}
