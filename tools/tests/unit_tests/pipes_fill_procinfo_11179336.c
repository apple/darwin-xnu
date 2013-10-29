#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <libproc.h>

int main(){
	int pipe_fds[2];
	if (pipe(&pipe_fds[0]) < 0) {
		perror("pipe");
		goto fail;
	}
	struct pipe_fdinfo pdinfo; 
	/* from the headers
	  int proc_pidfdinfo(int pid, int fd, int flavor, void * buffer, int buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);
	*/	
	int mypid = getpid();
	int flavor = PROC_PIDFDPIPEINFO;
	int nv = proc_pidfdinfo(mypid, pipe_fds[0], flavor, (void *) &pdinfo, sizeof(pdinfo));
	if (nv < 0) {
		perror("proc_pidinfo");
		goto fail;
	}
	printf("handle value = %p \n", (void *)pdinfo.pipeinfo.pipe_handle);
	struct stat mystat;
	fstat(pipe_fds[0], &mystat);
	printf("ino value = %p \n", (void *)mystat.st_ino);

	if ( (uintptr_t)mystat.st_ino == (uintptr_t)pdinfo.pipeinfo.pipe_handle)
		goto success;
	fail:
		printf("[FAILED] fill_pipeinfo returned wrong values. (i.e. pipeinfo->pipe_handle != fstat->st_ino ) \n");
		return -1;
	success: 
		printf("[PASSED] fill_pipeinfo returned correct values. (i.e. pipeinfo->pipe_handle ==  fstat->st_ino ) \n");
		return 0;
}

