#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/errno.h>

int main(int argc, char **argv)
{
	int fd[2], pid, r;
	char *args[3], buf[32];
	struct pollfd pfd;
	extern char **environ;

	if (pipe(fd) < 0) {
		perror("pipe");
		return 1;
	}

	snprintf(buf, sizeof buf, "%d", fd[0]);

	args[0] = "./child";
	args[1] = buf;
	args[2] = 0;

	switch (pid = fork()) {
	case -1:
		perror("fork");
		return 1;
	case 0:		/* child */
		close(fd[1]);
		execve(args[0], args, environ);
		perror(args[0]);
		_exit(1);
	default:	/* parent */
		close(fd[0]);
		pfd.fd = fd[1];
		pfd.events = POLLOUT;
		pfd.revents = 0;
		printf("parent poll(%d)...\n", pfd.fd);
		errno = 0;
		r = poll(&pfd, 1, -1);
		printf("parent poll(%d) returned %d errno %d[%s]\n",
		    pfd.fd, r, errno, strerror(errno));
		write(fd[1], "howdy", 5);
		close(fd[1]);
		printf("parent done\n");
	}

	return 0;
}
