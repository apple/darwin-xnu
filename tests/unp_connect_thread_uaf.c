/* This tests thread_t uaf vulnerability in the XNU kernel due to
 * a race condition in unp_connect
 */

#include <sys/un.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/proc_info.h>
#include <libproc.h>
#include <darwintest.h>
#include <unistd.h>

int g_start = 0;
int g_client = 0;
int g_sever1 = 0;
int g_sever2 = 0;

static void
server_thread1(char* path)
{
	struct sockaddr_un server_sockaddr;
	memset(&server_sockaddr, 0, sizeof(struct sockaddr_un));
	server_sockaddr.sun_family = AF_UNIX;
	strcpy(server_sockaddr.sun_path, path);
	unlink(server_sockaddr.sun_path);

	int server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	g_sever1 = server_sock;
	T_ASSERT_POSIX_SUCCESS(bind(server_sock,
	    (struct sockaddr *) &server_sockaddr, sizeof(server_sockaddr)), NULL);

	/*********************************/
	/* Listen for any client sockets */
	/*********************************/
	T_ASSERT_POSIX_SUCCESS(listen(server_sock, -1), NULL);

	return;
}

static void
server_thread2(char* path)
{
	struct sockaddr_un server_sockaddr;
	memset(&server_sockaddr, 0, sizeof(struct sockaddr_un));
	server_sockaddr.sun_family = AF_UNIX;
	strcpy(server_sockaddr.sun_path, path);
	unlink(server_sockaddr.sun_path);

	int server_sock = socket(AF_UNIX, SOCK_STREAM, 0);
	g_sever2 = server_sock;
	T_ASSERT_POSIX_SUCCESS(bind(server_sock,
	    (struct sockaddr *) &server_sockaddr, sizeof(server_sockaddr)), NULL);

	/*********************************/
	/* Listen for any client sockets */
	/*********************************/
	T_ASSERT_POSIX_SUCCESS(listen(server_sock, -1), NULL);

	return;
}

static void
try_to_connect(char* path)
{
	struct sockaddr_un server_sockaddr;
	memset(&server_sockaddr, 0, sizeof(struct sockaddr_un));
	server_sockaddr.sun_family = AF_UNIX;
	strcpy(server_sockaddr.sun_path, path);
	//unlink(server_sockaddr.sun_path);

	while (g_start == 0) {
		usleep(100);
	}
	int ret = connect(g_client, (struct sockaddr *)&server_sockaddr,
	    sizeof(server_sockaddr));

	T_ASSERT_TRUE(ret == 0 || errno == EALREADY || errno == EISCONN,
	    "connect with ret: %d(%d)", ret, errno);
}


static void
test_unp_connect_multithread()
{
	int client_sock;
	char path[] = "/tmp/";
	char path1[256];
	char path2[256];
	char path3[256];

	strncpy(path1, path, 255);
	strcat(path1, "/1");
	strncpy(path2, path, 255);
	strcat(path2, "/2");
	strncpy(path3, path, 255);
	strcat(path3, "/3");


	for (int i = 0; i < 1024; i++) {
		T_SETUPBEGIN;
		server_thread1(path1);
		server_thread2(path2);
		T_ASSERT_POSIX_SUCCESS(client_sock = socket(AF_UNIX, SOCK_STREAM, 0), NULL);

		unlink(path3);
		struct sockaddr_un client_sockaddr;
		client_sockaddr.sun_family = AF_UNIX;
		strcpy(client_sockaddr.sun_path, path3);
		T_ASSERT_POSIX_SUCCESS(bind(client_sock, (struct sockaddr *)&client_sockaddr,
		    sizeof(client_sockaddr)), NULL);
		T_SETUPEND;
		g_client = client_sock;
		g_start = 0;
		pthread_t runner1;
		pthread_t runner2;
		if (pthread_create(&runner1, 0, (void*)try_to_connect, path1)) {
			T_ASSERT_FAIL("pthread_create failed");
		}

		if (pthread_create(&runner2, 0, (void*)try_to_connect, path2)) {
			T_ASSERT_FAIL("pthread_create failed");
		}
		usleep(300);
		g_start = 1;
		pthread_join(runner1, 0);
		pthread_join(runner2, 0);

		usleep(3000);

		struct socket_fdinfo si_1 = {0};
		proc_pidfdinfo(getpid(), g_sever1, PROC_PIDFDSOCKETINFO, &si_1,
		    sizeof(si_1));
		struct socket_fdinfo si_2 = {0};
		proc_pidfdinfo(getpid(), g_sever2, PROC_PIDFDSOCKETINFO, &si_2,
		    sizeof(si_2));
		if (si_1.psi.soi_incqlen || si_2.psi.soi_incqlen) {
			close(g_sever2);
			close(g_sever1);
		}
		close(client_sock);
		close(g_sever2);
		close(g_sever1);
	}
}

T_DECL(unp_connect_thread_uaf, "Uaf due to multithreaded unp_connect")
{
	test_unp_connect_multithread();
}
