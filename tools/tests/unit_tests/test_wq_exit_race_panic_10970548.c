#include <stdio.h>
#include <stdlib.h>
#include <dispatch/dispatch.h>

int main(int argc, char *argv[])
{
	char **envp = { NULL };
	char *mycount = "1";
	char *nargvp[] = { argv[0], mycount , NULL};
	char *progpath = argv[0];
	char buf[50];
	char oldcount[30];
	int envcount=0;
	if (argc >= 2){
		envcount = atoi(argv[1]);
		printf("count = %d \n", envcount);
		sprintf(buf, "%d", envcount+1);
		nargvp[1] = buf;
	}
	char **nargvpp = nargvp;
	if (envcount < 8 )
		fork();
	if (envcount > 320)
		exit(0);
	dispatch_apply(32,
		       dispatch_get_global_queue(0,0),
		       ^(size_t i __attribute__((unused))) {
		execve(progpath,nargvpp,envp);
	});

	return 0;
}
