#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/guarded.h>
#include <mach/mach.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include "guarded_test_common.h"

#include <sys/syscall.h>

#if !defined(SYS_guarded_kqueue_np)
#define	guarded_kqueue_np(gp, gf)	syscall(443, gp, gf)
#endif

#if !defined(SYS_change_fdguard_np)
#define	change_fdguard_np(fd, gp, gf, ngp, nfg, flp)	\
	syscall(444, fd, gp, gf, ngp, nfg, flp)
#endif

#define SERVER_NAME "/tmp/fdserver"

typedef union {
	struct cmsghdrcmsghdr;
	u_char msg_control[0];
} cmsghdr_msg_control_t;

/* Test case for closing a guarded fd */
void close_guarded_fd(int);
/* Test case for duping a guarded fd */
void dup_guarded_fd(int);
/* Test case for removing flag from guarded fd */
void remove_flag_guarded_fd(int);
/* Test case for closing guarded fd with bad guard */
void badguard_close_guarded_fd(int, guardid_t);
/* Test case for guarded closing an unguarded fd */
void guard_close_unguarded_fd(guardid_t);
/* Test case for guarded closing a guarded fd correctly */
void guard_close_guarded_fd(int, guardid_t);
/* Test case for creating a file port from a guarded fd */
void fileport_makeport_guarded_fd(int);
/* Test case for sending guarded fd over socket */
void sendmsg_guarded_fd(int);
/* Test case for removing the guard from a guarded fd */
void remove_guard(int, guardid_t, u_int, int);
/* Test case for adding a guard to a tcp socket */
void add_guard_to_socket(guardid_t);
/* Test case for a guarded kqueue */
void create_and_close_guarded_kqueue(guardid_t);

/* Helper routines */
void *client_recv_fd(void *);
int receive_fd_using_sockfd(int *, int);
int send_fd_using_sockfd(int, int);
int setup_server(const char *);

const guardid_t guard = 0x123456789abcdefull;
char *pname;

static void usage(void)
{
        printf("usage: %s [test number]\n", pname);
        printf("test 0: Test case for closing a guarded fd\n");
        printf("test 1: Test case for duping a guarded fd\n");
        printf("test 2: Test case for removing FD_CLOEXEC flag from a guarded fd\n");
	printf("test 3: Test case for closing a guarded fd with a bad guard\n");
	printf("test 4: Test case for closing an unguarded fd using a guarded close\n");
	printf("test 5: Test case for closing a guarded fd with the correct guard\n");
	printf("test 6: Test case for creating a file port from a guarded fd\n");
	printf("test 7: Test case for sending a guarded fd over a socket\n");
	printf("test 8: Test case for removing the guard from a guarded fd\n");
	printf("test 9: Test case for adding a guard to a tcp socket\n");
	printf("test 10: Test case for a guarded kqueue\n");
}

int main(int argc, char *argv[])
{
	int option, fd;
	
	pname = argv[0];
	if (argc != 2) {
		usage();
                exit(1);
	}
	printf("Test Program invoked with option [%s]\n", argv[1]);
	option = atoi(argv[1]);

	close(TEST_FD);
	fd = guarded_open_np(
			"/tmp/try.txt",
			&guard,
			GUARD_CLOSE | GUARD_DUP | GUARD_SOCKET_IPC | GUARD_FILEPORT,
			O_CREAT | O_CLOEXEC | O_RDWR,
			0666);

	if (-1 == fd) {
		perror("guarded_open_np");
		exit(1);
	}

	switch(option) {

		case 0:
			close_guarded_fd(fd);
			break;
		case 1:
			dup_guarded_fd(fd);
			break;
		case 2:
			remove_flag_guarded_fd(fd);
			break;
		case 3:
			badguard_close_guarded_fd(fd, guard);
			break;
		case 4:
			guard_close_unguarded_fd(guard);
			break;
		case 5:
			guard_close_guarded_fd(fd, guard);
			break;
		case 6:
			fileport_makeport_guarded_fd(fd);
			break;
		case 7:
			sendmsg_guarded_fd(fd);
			break;
		case 8:
			remove_guard(fd, guard, GUARD_CLOSE | GUARD_DUP |
			    GUARD_SOCKET_IPC | GUARD_FILEPORT, FD_CLOEXEC);
			break;
		case 9:
			add_guard_to_socket(guard);
			break;
		case 10:
			create_and_close_guarded_kqueue(guard);
			break;	
		default:
			usage();
			exit(1);
	}

	return 0;
}

void close_guarded_fd(int fd)
{
	int ret_val; 
	printf("Performing close on a guarded fd...\n");

	/* Brute force way of ensuring that the child process
	 * uses the TEST_FD which is checked by the parent
	 */
	while(fd != TEST_FD && fd <= TEST_FD) {
		fd = guarded_open_np(
				"/tmp/try.txt",
				&guard,
				GUARD_CLOSE | GUARD_DUP | GUARD_SOCKET_IPC | GUARD_FILEPORT,
				O_CREAT | O_CLOEXEC | O_RDWR,
				0666);

		if (-1 == fd) {
			perror("guarded_open_np");
			exit(1);
		}
	}

	ret_val = close(TEST_FD);
	fprintf(stderr, "close() returned (%d) on a guarded fd?!\n", ret_val);
	exit(1);
}

void dup_guarded_fd(int fd)
{
	int ret_val;
	printf("Performing dup on a guarded fd...\n");
	ret_val = dup(fd);
	fprintf(stderr, "dup() returned (%d) on a guarded fd?!\n", ret_val);
	exit(1);
}

void remove_flag_guarded_fd(int fd)
{
	int ret_val, value;
	printf("Removing FD_CLOEXEC from a guarded fd...\n");
	value = fcntl(fd, F_GETFD);
	if (-1 == value) {
		fprintf(stderr, "fcntl:F_GETFD failed with %s!\n", strerror(errno));
		exit(1);
	}
	ret_val = fcntl(fd, F_SETFD, value & ~FD_CLOEXEC);
	fprintf(stderr, "fcntl:F_SETFD returned (%d) on a guarded fd?!\n", ret_val);
	exit(1);
}

void badguard_close_guarded_fd(int fd, guardid_t guard)
{
	int ret_val;
	printf("Closing guarded fd with a bad guard...\n");
	guardid_t badguard = guard << 1;
	ret_val = guarded_close_np(fd, &badguard);
	if (-1 == ret_val) {
		switch (errno) {
		case EPERM:
			/* Expected */
			perror("guarded_close_np");
			exit(0);
		default:
			perror("guarded_close_np");
			break;
		}
	}
	fprintf(stderr,
	    "Close with bad guard returned (%d) on a guarded fd?!\n", ret_val);
	exit(1);
}

void guard_close_unguarded_fd(guardid_t guard)
{
	printf("Closing Unguarded fd with guarded_close_np...\n");
	int newfd, ret_val;

	if ((newfd = dup(fileno(stderr))) == -1) {
		fprintf(stderr, "Failed to dup stderr!\n");
		exit(1);
	}

	ret_val = guarded_close_np(newfd, &guard);
	if (-1 == ret_val) {
		/* Expected */
		perror("guarded_close_np");
		exit(0);
	}
	else {
		fprintf(stderr, "Closing unguarded fd with guarded_fd succeeded with return value (%d)?!\n", ret_val);
		exit(1);
	}
}

void guard_close_guarded_fd(int fd, guardid_t guard)
{
	printf("Closing a guarded fd with correct guard...\n");
	if (-1 == guarded_close_np(fd, &guard)) {
		fprintf(stderr, "Closing guarded fd with correct guard failed?!\n");
		exit(1);
	}
	/* Expected */
	exit(0);
}

void fileport_makeport_guarded_fd(int fd)
{
	mach_port_name_t fdname = MACH_PORT_NULL;
	int ret_val;
	printf("Creating a file port from a guarded fd...\n");
	ret_val = fileport_makeport(fd, &fdname);
	fprintf(stderr, "Creating a file port from guarded fd returned (%d)?!\n", ret_val);
	exit(1);
}  

void sendmsg_guarded_fd(int fd)
{
	int sockfd, err;
	int csockfd;
	socklen_t len;
	struct sockaddr_un client_unix_addr;
	pthread_t client_thread;
	int ret_val;

	/* Setup fd server */
	if ((sockfd = setup_server(SERVER_NAME)) < 0) {
		exit(1);
	}

	if(-1 == listen(sockfd, 5)) {
		perror("listen");
		exit(1);
	}

	/* Create client thread */
	if ((err = pthread_create(&client_thread, NULL, client_recv_fd, 0)) != 0) {
		fprintf(stderr, "pthread_create server_thread: %s\n", strerror(err));
		exit(1);
	}

	pthread_detach(client_thread);

	for (;;) {
		len = sizeof (client_unix_addr);
		csockfd = accept(sockfd,
				(struct sockaddr *)&client_unix_addr, &len);
		if (csockfd < 0) {
			perror("accept");
			exit(1);
		}

		printf("Sending guarded fd on a socket...\n");
		ret_val = send_fd_using_sockfd(fd, csockfd);
		if(ret_val < 0) {
			/* Expected */
			fprintf(stderr, "sendmsg failed with return value (%d)!\n", ret_val);
		}
		else {
			fprintf(stderr, "Sending guarded fd on socket succeeded with return value (%d)?!\n", ret_val);
		}
	}

	exit(0);
}

void
remove_guard(int fd, guardid_t guard, u_int guardflags, int fdflags)
{
	printf("Remove the guard from a guarded fd, then dup(2) it ...\n");

	int ret_val = change_fdguard_np(fd, &guard, guardflags, NULL, 0, &fdflags);

	if (ret_val == -1) {
		perror("change_fdguard_np");
		exit(1);
	}

	printf("Dup-ing the unguarded fd ...\n");

	/*
	 * Now that the GUARD_DUP has been removed, we should be able
	 * to dup the descriptor with no exception generation.
	 */
	int newfd = dup(fd);

	if (-1 == newfd) {
		perror("dup");
		exit(1);
	}
	exit(0);
}

void
add_guard_to_socket(guardid_t guard)
{
	printf("Add a close guard to an unguarded socket fd, then close it ...\n");

	int s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (-1 == s) {
		perror("socket");
		exit(1);
	}

	int ret_val = change_fdguard_np(s, NULL, 0, &guard, GUARD_CLOSE | GUARD_DUP, NULL);

	if (-1 == ret_val) {
		perror("change_fdguard_np");
		exit(1);
	}

	/*
	 * Now we've added a GUARD_CLOSE successfully, let's try and do a close
	 */
	if (-1 == close(s))
		perror("close");
	/*
	 * This is an error, because we should've received a fatal EXC_GUARD
	 */
	exit(1);
}

void
create_and_close_guarded_kqueue(guardid_t guard)
{
	printf("Create a guarded kqueue, then guarded_close_np() it ...\n");

	int kq = guarded_kqueue_np(&guard, GUARD_CLOSE | GUARD_DUP);

	int ret_val = guarded_close_np(kq, &guard);
	if (-1 == ret_val) {
		perror("guarded_close_np");
		exit(1);
	}

	printf("Create a guarded kqueue, then close() it ...\n");

	kq = guarded_kqueue_np(&guard, GUARD_CLOSE | GUARD_DUP);
	if (-1 == close(kq))
		perror("close");
	/*
	 * This is always an error, because we should've received a fatal EXC_GUARD
	 */
	exit(1);
}

/*
 * Helper Routines
 */

int setup_server(const char *name)
{
	int sockfd, len;
	struct sockaddr_un server_unix_addr;

	if ((sockfd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return (sockfd);
	}

	(void) unlink(name);
	bzero(&server_unix_addr, sizeof (server_unix_addr));
	server_unix_addr.sun_family = AF_LOCAL;
	(void) strcpy(server_unix_addr.sun_path, name);
	len = strlen(name) + 1;
	len += sizeof (server_unix_addr.sun_family);

	if (bind(sockfd, (struct sockaddr *)&server_unix_addr, len) < 0) {
		(void) close(sockfd);
		return (-1);
	}
	return (sockfd);
}

int send_fd_using_sockfd(int fd, int sockfd)
{
	ssize_t ret;
	struct iovec iovec[1];
	struct msghdr msg;
	struct cmsghdr *cmsghdrp;
	cmsghdr_msg_control_t *cmsghdr_msg_control;

	cmsghdr_msg_control = malloc(CMSG_SPACE(sizeof (int)));

	iovec[0].iov_base = "";
	iovec[0].iov_len = 1;

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = iovec;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsghdr_msg_control->msg_control;
	msg.msg_controllen = CMSG_SPACE(sizeof (int));
	msg.msg_flags = 0;

	cmsghdrp = CMSG_FIRSTHDR(&msg);
	cmsghdrp->cmsg_len = CMSG_LEN(sizeof (int));
	cmsghdrp->cmsg_level = SOL_SOCKET;
	cmsghdrp->cmsg_type = SCM_RIGHTS;

	*((int *)CMSG_DATA(cmsghdrp)) = fd;

	if ((ret = sendmsg(sockfd, &msg, 0)) < 0) {
		perror("sendmsg");
		return ret;
	}

	return 0;
}

int receive_fd_using_sockfd(int *fd, int sockfd)
{
	ssize_t ret;
	u_char c;
	int errcount = 0;
	struct iovec iovec[1];
	struct msghdr msg;
	struct cmsghdr *cmsghdrp;
	cmsghdr_msg_control_t *cmsghdr_msg_control;

	cmsghdr_msg_control = malloc(CMSG_SPACE(sizeof (int)));

	iovec[0].iov_base = &c;
	iovec[0].iov_len = 1;

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = iovec;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsghdr_msg_control->msg_control;
	msg.msg_controllen = CMSG_SPACE(sizeof (int));
	msg.msg_flags = 0;

	if ((ret = recvmsg(sockfd, &msg, 0)) < 0) {
		perror("recvmsg");
		return ret;
	}

	cmsghdrp = CMSG_FIRSTHDR(&msg);
	if (cmsghdrp == NULL) {
		*fd = -1;
		return ret;
	}

	if (cmsghdrp->cmsg_len != CMSG_LEN(sizeof (int)))
		errcount++;
	if (cmsghdrp->cmsg_level != SOL_SOCKET)
		errcount++;
	if (cmsghdrp->cmsg_type != SCM_RIGHTS)
		errcount++;
	if (errcount) {
		*fd = -1;
	} else
		*fd = *((int *)CMSG_DATA(cmsghdrp));
	return ret;
}

void *client_recv_fd(void *arg)
{
	char buf[512];
	int fd = -1, sockfd, len, ret;
	struct sockaddr_un server_unix_addr;

	bzero(&server_unix_addr, sizeof (server_unix_addr));
	strcpy(server_unix_addr.sun_path, SERVER_NAME);
	server_unix_addr.sun_family = AF_LOCAL;
	len = strlen(SERVER_NAME) + 1;
	len += sizeof (server_unix_addr.sun_family);

	if ((sockfd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}

	if (connect(sockfd, (struct sockaddr *)&server_unix_addr, len) < 0) {
		perror("connect");
		exit(1);
	}

	ret = receive_fd_using_sockfd(&fd, sockfd);
	return (NULL);
}
