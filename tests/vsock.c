/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <sys/cdefs.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/vsock.h>
#include <errno.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#define COUNT_ELEMS(array) (sizeof (array) / sizeof (array[0]))

T_GLOBAL_META(
	T_META_RUN_CONCURRENTLY(true),
	T_META_NAMESPACE("xnu.vsock")
	);

static int
vsock_new_socket(void)
{
	int sock = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (sock < 0 && errno == ENODEV) {
		T_SKIP("no vsock transport available");
	}
	T_ASSERT_GT(sock, 0, "create new vsock socket");
	return sock;
}

static uint32_t
vsock_get_local_cid(int socket)
{
	uint32_t cid = 0;
	int result = ioctl(socket, IOCTL_VM_SOCKETS_GET_LOCAL_CID, &cid);
	T_ASSERT_POSIX_SUCCESS(result, "vsock ioctl cid successful");
	T_ASSERT_GT(cid, VMADDR_CID_HOST, "cid is set");
	T_ASSERT_NE(cid, VMADDR_CID_ANY, "cid is valid");

	return cid;
}

static int
vsock_bind(uint32_t cid, uint32_t port, struct sockaddr_vm * addr, int *socket)
{
	*socket = vsock_new_socket();

	bzero(addr, sizeof(*addr));
	addr->svm_port = port;
	addr->svm_cid = cid;

	return bind(*socket, (struct sockaddr *) addr, sizeof(*addr));
}

static int
vsock_listen(uint32_t cid, uint32_t port, struct sockaddr_vm * addr, int backlog, int *socket)
{
	int result = vsock_bind(cid, port, addr, socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock bind");
	return listen(*socket, backlog);
}

static int
vsock_connect(uint32_t cid, uint32_t port, int *socket)
{
	*socket = vsock_new_socket();
	struct sockaddr_vm addr = (struct sockaddr_vm) {
		.svm_cid = cid,
		.svm_port = port,
	};
	return connect(*socket, (struct sockaddr *)&addr, sizeof(addr));
}

static struct sockaddr_vm
vsock_getsockname(int socket)
{
	struct sockaddr_vm addr;
	socklen_t length = sizeof(addr);
	int result = getsockname(socket, (struct sockaddr *)&addr, &length);
	T_ASSERT_POSIX_SUCCESS(result, "vsock getsockname");
	T_ASSERT_EQ_INT((int) sizeof(addr), length, "correct address length");
	T_ASSERT_GT(addr.svm_port, 0, "bound to non-zero local port");
	return addr;
}

static void
vsock_close(int socket)
{
	int result = close(socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock close");
}

static void
vsock_connect_peers(uint32_t cid, uint32_t port, int backlog, int *socketA, int *socketB)
{
	// Listen.
	struct sockaddr_vm addr;
	int listen_socket;
	int result = vsock_listen(cid, port, &addr, backlog, &listen_socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock listen");

	const uint32_t connection_cid = vsock_get_local_cid(listen_socket);

	// Connect.
	int connect_socket;
	result = vsock_connect(connection_cid, addr.svm_port, &connect_socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock connect");

	// Accept.
	struct sockaddr_vm accepted_addr;
	socklen_t addrlen = sizeof(accepted_addr);
	int accepted_socket = accept(listen_socket, (struct sockaddr *)&accepted_addr, &addrlen);
	T_ASSERT_GT(accepted_socket, 0, "accepted socket");
	T_ASSERT_EQ_INT((int) sizeof(accepted_addr), addrlen, "correct address length");
	T_ASSERT_EQ_INT(connection_cid, accepted_addr.svm_cid, "same cid");
	T_ASSERT_NE_INT(VMADDR_CID_ANY, accepted_addr.svm_port, "some valid port");
	T_ASSERT_NE_INT(0, accepted_addr.svm_port, "some non-zero port");

	*socketA = connect_socket;
	*socketB = accepted_socket;
}

static void
vsock_send(int socket, char *msg)
{
	T_ASSERT_NOTNULL(msg, "send message is not null");
	ssize_t sent_bytes = send(socket, msg, strlen(msg), 0);
	T_ASSERT_EQ_LONG(strlen(msg), (unsigned long)sent_bytes, "sent all bytes");
}

static void
vsock_disable_sigpipe(int socket)
{
	int on = 1;
	int result = setsockopt(socket, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
	T_ASSERT_POSIX_SUCCESS(result, "vsock disable SIGPIPE");
}

static bool
vsock_address_exists(struct xvsockpgen *buffer, struct sockaddr_vm addr)
{
	struct xvsockpgen *xvg = buffer;
	struct xvsockpgen *oxvg = buffer;

	bool found = false;
	for (xvg = (struct xvsockpgen *)((char *)xvg + xvg->xvg_len);
	    xvg->xvg_len > sizeof(struct xvsockpgen);
	    xvg = (struct xvsockpgen *)((char *)xvg + xvg->xvg_len)) {
		struct xvsockpcb *xpcb = (struct xvsockpcb *)xvg;

		/* Ignore PCBs which were freed during copyout. */
		if (xpcb->xvp_gencnt > oxvg->xvg_gen) {
			continue;
		}

		if (xpcb->xvp_local_cid == addr.svm_cid && xpcb->xvp_remote_cid == VMADDR_CID_ANY &&
		    xpcb->xvp_local_port == addr.svm_port && xpcb->xvp_remote_port == VMADDR_PORT_ANY) {
			found = true;
			break;
		}
	}

	T_ASSERT_NE(xvg, oxvg, "first and last xvsockpgen were returned");

	return found;
}

/* New Socket */

T_DECL(new_socket_getsockname, "vsock new - getsockname")
{
	int socket = vsock_new_socket();

	struct sockaddr_vm addr;
	socklen_t length = sizeof(struct sockaddr_vm);
	int result = getsockname(socket, (struct sockaddr *)&addr, &length);
	T_ASSERT_POSIX_SUCCESS(result, "vsock getsockname");
	T_ASSERT_EQ_INT(addr.svm_port, VMADDR_PORT_ANY, "name is any port");
	T_ASSERT_EQ_INT(addr.svm_cid, VMADDR_CID_ANY, "name is any cid");
}

T_DECL(new_socket_getpeername, "vsock new - getpeername")
{
	int socket = vsock_new_socket();

	struct sockaddr_vm addr;
	socklen_t length = sizeof(struct sockaddr_vm);
	int result = getpeername(socket, (struct sockaddr *)&addr, &length);
	T_ASSERT_POSIX_FAILURE(result, ENOTCONN, "vsock getpeername");
}

/* Ioctl */

T_DECL(ioctl_cid, "vsock ioctl cid")
{
	int socket = vsock_new_socket();
	vsock_get_local_cid(socket);
}

/* Socketpair */

T_DECL(socketpair, "vsock socketpair")
{
	int pair[2];
	int error = socketpair(AF_VSOCK, SOCK_STREAM, 0, pair);
	if (error < 0 && errno == ENODEV) {
		T_SKIP("no vsock transport available");
	}
	T_ASSERT_POSIX_FAILURE(error, EOPNOTSUPP, "vsock socketpair not supported");
}

/* Bind */

T_DECL(bind, "vsock bind to specific port")
{
	int socket;
	struct sockaddr_vm addr;
	int result = vsock_bind(VMADDR_CID_ANY, 8888, &addr, &socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock bind to specific port");
}

T_DECL(bind_any, "vsock bind to any port")
{
	int socket;
	struct sockaddr_vm addr;
	int result = vsock_bind(VMADDR_CID_ANY, VMADDR_PORT_ANY, &addr, &socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock bind to any port");
}

T_DECL(bind_getsockname, "vsock bind - getsockname")
{
	int socket;
	struct sockaddr_vm addr;
	const uint32_t port = VMADDR_PORT_ANY;
	const uint32_t cid = VMADDR_CID_ANY;
	int result = vsock_bind(cid, port, &addr, &socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock bind to any port");

	struct sockaddr_vm bound_addr = vsock_getsockname(socket);
	T_ASSERT_NE_INT(bound_addr.svm_port, port, "bound to unique local port");
	T_ASSERT_EQ_INT(bound_addr.svm_cid, cid, "bound to any cid");
}

T_DECL(bind_hypervisor, "vsock do not bind to hypervisor cid")
{
	int socket;
	struct sockaddr_vm addr;
	int result = vsock_bind(VMADDR_CID_HYPERVISOR, VMADDR_PORT_ANY, &addr, &socket);
	T_ASSERT_POSIX_FAILURE(result, EADDRNOTAVAIL, "vsock do not bind to hypervisor cid");
}

T_DECL(bind_reserved, "vsock do not bind to reserved cid")
{
	int socket;
	struct sockaddr_vm addr;
	int result = vsock_bind(VMADDR_CID_RESERVED, VMADDR_PORT_ANY, &addr, &socket);
	T_ASSERT_POSIX_FAILURE(result, EADDRNOTAVAIL, "vsock do not bind to reserved cid");
}

T_DECL(bind_host, "vsock do not bind to host cid")
{
	int socket;
	struct sockaddr_vm addr;
	int result = vsock_bind(VMADDR_CID_HOST, VMADDR_PORT_ANY, &addr, &socket);
	T_ASSERT_POSIX_FAILURE(result, EADDRNOTAVAIL, "vsock do not bind to host cid");
}

T_DECL(bind_zero, "vsock bind to port zero", T_META_ASROOT(true))
{
	const uint32_t port = 0;

	int socket;
	struct sockaddr_vm addr;
	int result = vsock_bind(VMADDR_CID_ANY, port, &addr, &socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock bind to port zero");

	struct sockaddr_vm bound_addr;
	socklen_t length = sizeof(struct sockaddr_vm);
	result = getsockname(socket, (struct sockaddr *)&bound_addr, &length);
	T_ASSERT_POSIX_SUCCESS(result, "vsock getsockname");
	T_ASSERT_EQ_INT((int) sizeof(bound_addr), length, "correct address length");
	T_ASSERT_EQ_UINT(bound_addr.svm_port, port, "bound to local port zero");
}

T_DECL(bind_double, "vsock double bind")
{
	const uint32_t cid = VMADDR_CID_ANY;
	const uint32_t port = 8899;

	int socket;
	struct sockaddr_vm addr;
	int result = vsock_bind(cid, port, &addr, &socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock bind to a port");

	result = bind(socket, (struct sockaddr *) &addr, sizeof(addr));
	T_ASSERT_POSIX_FAILURE(result, EINVAL, "vsock bind to same port");
}

T_DECL(bind_same, "vsock bind same address and port")
{
	const uint32_t cid = VMADDR_CID_ANY;
	const uint32_t port = 3399;

	int socket;
	struct sockaddr_vm addr;
	int result = vsock_bind(cid, port, &addr, &socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock bind to a port");

	result = vsock_bind(cid, port, &addr, &socket);
	T_ASSERT_POSIX_FAILURE(result, EADDRINUSE, "vsock bind to same address and port");
}

T_DECL(bind_port_reuse, "vsock bind port reuse")
{
	const uint32_t cid = VMADDR_CID_ANY;
	const uint32_t port = 9111;

	int socket;
	struct sockaddr_vm addr;
	int result = vsock_bind(cid, port, &addr, &socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock bind to a port");

	vsock_close(socket);

	result = vsock_bind(cid, port, &addr, &socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock bind to a port");
}

T_DECL(bind_privileged_non_root, "vsock bind on privileged port - non-root", T_META_ASROOT(false))
{
	if (geteuid() == 0) {
		T_SKIP("test requires non-root privileges to run.");
	}
	struct sockaddr_vm addr;
	int socket;
	int result = vsock_bind(VMADDR_CID_ANY, 5, &addr, &socket);
	T_ASSERT_POSIX_FAILURE(result, EACCES, "vsock bind privileged as non-root");
}

T_DECL(bind_privileged_root, "vsock bind on privileged port - root", T_META_ASROOT(true))
{
	if (geteuid() != 0) {
		T_SKIP("test requires root privileges to run.");
	}
	struct sockaddr_vm addr;
	int socket;
	int result = vsock_bind(VMADDR_CID_ANY, 6, &addr, &socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock bind privileged as root");
}

T_DECL(bind_no_family, "vsock bind with unspecified family")
{
	int socket = vsock_new_socket();

	struct sockaddr_vm addr = (struct sockaddr_vm) {
		.svm_family = AF_UNSPEC,
		.svm_cid = VMADDR_CID_ANY,
		.svm_port = 7321,
	};

	int result = bind(socket, (struct sockaddr *) &addr, sizeof(addr));
	T_ASSERT_POSIX_SUCCESS(result, "vsock bind with unspecified family");
}

T_DECL(bind_vsock_family, "vsock bind with vsock family")
{
	int socket = vsock_new_socket();

	struct sockaddr_vm addr = (struct sockaddr_vm) {
		.svm_family = AF_VSOCK,
		.svm_cid = VMADDR_CID_ANY,
		.svm_port = 7322,
	};

	int result = bind(socket, (struct sockaddr *) &addr, sizeof(addr));
	T_ASSERT_POSIX_SUCCESS(result, "vsock bind with vsock family");
}

T_DECL(bind_wrong_family, "vsock bind with wrong family")
{
	int socket = vsock_new_socket();

	struct sockaddr_vm addr = (struct sockaddr_vm) {
		.svm_family = AF_INET,
		.svm_cid = VMADDR_CID_ANY,
		.svm_port = 7323,
	};

	int result = bind(socket, (struct sockaddr *) &addr, sizeof(addr));
	T_ASSERT_POSIX_FAILURE(result, EAFNOSUPPORT, "vsock bind with wrong family");
}

/* Listen */

T_DECL(listen, "vsock listen on specific port")
{
	struct sockaddr_vm addr;
	int socket;
	int result = vsock_listen(VMADDR_CID_ANY, 8889, &addr, 10, &socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock listen");
}

T_DECL(listen_any, "vsock listen on any port")
{
	struct sockaddr_vm addr;
	int socket;
	int result = vsock_listen(VMADDR_CID_ANY, VMADDR_PORT_ANY, &addr, 10, &socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock listen");
}

/* Connect */

T_DECL(connect_non_hypervisor, "vsock connect to remote other than hypervisor")
{
	int socket;
	int result = vsock_connect(5555, 1234, &socket);
	T_ASSERT_POSIX_FAILURE(result, EFAULT, "vsock connect non-hypervisor");
}

T_DECL(connect_non_listening_host, "vsock connect to non-listening host port")
{
	int socket;
	int result = vsock_connect(VMADDR_CID_HOST, 7777, &socket);
	T_ASSERT_POSIX_FAILURE(result, EAGAIN, "vsock connect non-listening host port");
}

T_DECL(connect_non_listening_hypervisor, "vsock connect to non-listening hypervisor port")
{
	int socket;
	int result = vsock_connect(VMADDR_CID_HYPERVISOR, 4444, &socket);
	T_ASSERT_POSIX_FAILURE(result, EAGAIN, "vsock connect non-listening hypervisor port");
}

T_DECL(connect_getsockname, "vsock connect - getsockname")
{
	int socket;
	int result = vsock_connect(VMADDR_CID_HOST, 9999, &socket);
	T_ASSERT_POSIX_FAILURE(result, EAGAIN, "vsock connect non-listening");

	vsock_getsockname(socket);
}

T_DECL(connect_timeout, "vsock connect with timeout")
{
	int socket = vsock_new_socket();

	struct timeval timeout = (struct timeval) {
		.tv_sec = 0,
		.tv_usec = 1,
	};
	int result = setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	T_ASSERT_POSIX_SUCCESS(result, "vsock set socket timeout");

	struct sockaddr_vm addr = (struct sockaddr_vm) {
		.svm_cid = VMADDR_CID_HOST,
		.svm_port = 4321,
	};
	result = connect(socket, (struct sockaddr *)&addr, sizeof(addr));
	T_ASSERT_POSIX_FAILURE(result, ETIMEDOUT, "vsock connect timeout");
}

T_DECL(connect_non_blocking, "vsock connect non-blocking")
{
	int socket = vsock_new_socket();

	const uint32_t port = 4321;
	const uint32_t cid = vsock_get_local_cid(socket);

	// Listen.
	struct sockaddr_vm listen_addr;
	int listen_socket;
	long result = vsock_listen(cid, port, &listen_addr, 10, &listen_socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock listen");

	// Set non-blocking.
	long arg = fcntl(socket, F_GETFL, NULL);
	T_ASSERT_GT(arg, -1L, "vsock get args");
	arg |= O_NONBLOCK;
	result = fcntl(socket, F_SETFL, arg);
	T_ASSERT_GT(arg, -1L, "vsock set args");

	// Connect.
	struct sockaddr_vm addr = (struct sockaddr_vm) {
		.svm_cid = cid,
		.svm_port = port,
	};
	result = connect(socket, (struct sockaddr *)&addr, sizeof(addr));
	if (result != 0 && errno != EINPROGRESS) {
		T_ASSERT_FAIL("vsock connect should succeed or return EINPROGRESS. errno: %u", errno);
	}

	vsock_close(socket);
	vsock_close(listen_socket);
}

/* Shutdown */

T_DECL(shutdown_not_connected, "vsock shutdown - not connected")
{
	int how[] = {SHUT_RD, SHUT_WR, SHUT_RDWR};
	for (unsigned long i = 0; i < COUNT_ELEMS(how); i++) {
		int socket = vsock_new_socket();
		int result = shutdown(socket, how[i]);
		T_ASSERT_POSIX_FAILURE(result, ENOTCONN, "vsock cannot shutdown");
	}
}

T_DECL(shutdown_reads, "vsock shutdown - reads")
{
	int socketA, socketB;
	vsock_connect_peers(VMADDR_CID_ANY, 8989, 10, &socketA, &socketB);

	char *msg = "This is test message.\n";

	// 'A' sends a message.
	vsock_send(socketA, msg);

	// 'B' shutsdown reads.
	int result = shutdown(socketB, SHUT_RD);
	T_ASSERT_POSIX_SUCCESS(result, "vsock shutdown reads");

	// 'B' reads nothing.
	char buffer[1024] = {0};
	ssize_t read_bytes = read(socketB, buffer, 1024);
	T_ASSERT_EQ_LONG(0L, read_bytes, "read zero bytes");

	// 'B' can still send.
	vsock_send(socketB, msg);

	vsock_close(socketA);
	vsock_close(socketB);
}

T_DECL(shutdown_writes, "vsock shutdown - writes")
{
	int socketA, socketB;
	vsock_connect_peers(VMADDR_CID_ANY, 8787, 10, &socketA, &socketB);

	char *msg = "This is test message.\n";

	// 'A' sends a message.
	vsock_send(socketA, msg);

	// 'B' sends a message.
	vsock_send(socketB, msg);

	// send() hits us with a SIGPIPE if peer closes. ignore this and catch the error code.
	vsock_disable_sigpipe(socketB);

	// 'B' shutsdown writes.
	int result = shutdown(socketB, SHUT_WR);
	T_ASSERT_POSIX_SUCCESS(result, "vsock shutdown writes");

	// 'B' fails to write.
	ssize_t sent_bytes = send(socketB, msg, strlen(msg), 0);
	T_ASSERT_POSIX_FAILURE(sent_bytes, EPIPE, "vsock cannot write");

	// 'B' can still read.
	char buffer[1024] = {0};
	ssize_t read_bytes = read(socketB, buffer, 1024);
	T_ASSERT_EQ_LONG(strlen(msg), (unsigned long)read_bytes, "read all bytes");

	vsock_close(socketA);
	vsock_close(socketB);
}

T_DECL(shutdown_both, "vsock shutdown - both")
{
	int socketA, socketB;
	vsock_connect_peers(VMADDR_CID_ANY, 8686, 10, &socketA, &socketB);

	char *msg = "This is test message.\n";
	char buffer[1024] = {0};

	// 'A' sends a message.
	vsock_send(socketA, msg);

	// 'B' sends a message.
	vsock_send(socketB, msg);

	// 'B' reads a message.
	ssize_t read_bytes = read(socketB, buffer, 1024);
	T_ASSERT_EQ_LONG(strlen(msg), (unsigned long)read_bytes, "read all bytes");
	T_ASSERT_EQ_STR(msg, buffer, "same message");

	// 'A' sends a message.
	vsock_send(socketA, msg);

	// send() hits us with a SIGPIPE if peer closes. ignore this and catch the error code.
	vsock_disable_sigpipe(socketB);

	// 'B' shutsdown reads and writes.
	int result = shutdown(socketB, SHUT_RDWR);
	T_ASSERT_POSIX_SUCCESS(result, "vsock shutdown reads and writes");

	// 'B' fails to write.
	ssize_t sent_bytes = send(socketB, msg, strlen(msg), 0);
	T_ASSERT_POSIX_FAILURE(sent_bytes, EPIPE, "vsock cannot write");

	// 'B' reads nothing.
	read_bytes = read(socketB, buffer, 1024);
	T_ASSERT_EQ_LONG(0L, read_bytes, "read zero bytes");

	vsock_close(socketA);
	vsock_close(socketB);
}

/* Communication */

T_DECL(talk_self, "vsock talk to self")
{
	int socketA, socketB;
	vsock_connect_peers(VMADDR_CID_ANY, 4545, 10, &socketA, &socketB);

	char buffer[1024] = {0};

	for (int i = 0; i < 64; i++) {
		// Send a message.
		char *msg = (char*)malloc(64 * sizeof(char));
		sprintf(msg, "This is test message %d\n", i);
		vsock_send(socketA, msg);

		// Receive a message.
		ssize_t read_bytes = read(socketB, buffer, 1024);
		T_ASSERT_EQ_LONG(strlen(msg), (unsigned long)read_bytes, "read all bytes");
		T_ASSERT_EQ_STR(msg, buffer, "same message");
		free(msg);
	}

	vsock_close(socketA);
	vsock_close(socketB);
}

T_DECL(talk_self_double, "vsock talk to self - double sends")
{
	int socketA, socketB;
	vsock_connect_peers(VMADDR_CID_ANY, 4646, 10, &socketA, &socketB);

	char buffer[1024] = {0};

	for (int i = 0; i < 64; i++) {
		// Send a message.
		char *msg = (char*)malloc(64 * sizeof(char));
		sprintf(msg, "This is test message %d\n", i);
		vsock_send(socketA, msg);

		// Send the same message.
		vsock_send(socketA, msg);

		// Receive a message.
		ssize_t read_bytes = read(socketB, buffer, 1024);
		T_ASSERT_EQ_LONG(strlen(msg) * 2, (unsigned long)read_bytes, "read all bytes");
		char *expected_msg = (char*)malloc(64 * sizeof(char));
		sprintf(expected_msg, "%s%s", msg, msg);
		T_ASSERT_EQ_STR(expected_msg, buffer, "same message");
		free(msg);
		free(expected_msg);
	}

	vsock_close(socketA);
	vsock_close(socketB);
}

T_DECL(talk_self_early_close, "vsock talk to self - peer closes early")
{
	int socketA, socketB;
	vsock_connect_peers(VMADDR_CID_ANY, 4646, 10, &socketA, &socketB);

	char *msg = "This is a message.";
	vsock_send(socketA, msg);

	// send() hits us with a SIGPIPE if peer closes. ignore this and catch the error code.
	vsock_disable_sigpipe(socketA);

	vsock_close(socketB);

	ssize_t result = send(socketA, msg, strlen(msg), 0);
	T_ASSERT_POSIX_FAILURE(result, EPIPE, "vsock peer closed");

	vsock_close(socketA);
}

T_DECL(talk_self_connections, "vsock talk to self - too many connections")
{
	const uint32_t port = 4747;
	const int backlog = 1;

	struct sockaddr_vm listen_addr;
	int listen_socket;
	int result = vsock_listen(VMADDR_CID_ANY, port, &listen_addr, backlog, &listen_socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock listen");

	const uint32_t connection_cid = vsock_get_local_cid(listen_socket);

	// One backlog.
	int connected_socket = vsock_new_socket();
	struct sockaddr_vm addr = (struct sockaddr_vm) {
		.svm_cid = connection_cid,
		.svm_port = port,
	};
	result = connect(connected_socket, (struct sockaddr *)&addr, sizeof(addr));
	T_ASSERT_POSIX_SUCCESS(result, "vsock connection successful");

	int bad_socket = vsock_new_socket();
	result = connect(bad_socket, (struct sockaddr *)&addr, sizeof(addr));
	T_ASSERT_POSIX_FAILURE(result, ECONNREFUSED, "vsock connection refused");

	vsock_close(connected_socket);
	vsock_close(listen_socket);
}

/* Sysctl */

static const char* pcblist = "net.vsock.pcblist";

T_DECL(vsock_pcblist_simple, "vsock pcblist sysctl - simple")
{
	// Create some socket to discover in the pcblist.
	struct sockaddr_vm addr;
	int socket;
	int result = vsock_listen(VMADDR_CID_ANY, 88899, &addr, 10, &socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock listen on a port");

	// Get the buffer length for the pcblist.
	size_t length = 0;
	result = sysctlbyname(pcblist, 0, &length, 0, 0);
	if (result == ENOENT) {
		T_SKIP("%s missing", pcblist);
	}
	T_ASSERT_POSIX_SUCCESS(result, "vsock pcblist get buffer size (result %d)", result);

	// Allocate the buffer.
	struct xvsockpgen *buffer = malloc(length);
	T_ASSERT_NOTNULL(buffer, "allocated buffer is not null");

	// Populate the buffer with the pcblist.
	result = sysctlbyname(pcblist, buffer, &length, 0, 0);
	T_ASSERT_POSIX_SUCCESS(result, "vsock pcblist populate buffer");

	// The socket should exist in the list.
	bool exists = vsock_address_exists(buffer, addr);
	T_ASSERT_TRUE(exists, "vsock pcblist contains the specified socket");

	vsock_close(socket);
	free(buffer);
}

T_DECL(vsock_pcblist_added, "vsock pcblist sysctl - socket added")
{
	// Get the buffer length for the pcblist.
	size_t length = 0;
	int result = sysctlbyname(pcblist, 0, &length, 0, 0);
	if (result == ENOENT) {
		T_SKIP("%s missing", pcblist);
	}
	T_ASSERT_POSIX_SUCCESS(result, "vsock pcblist get buffer size (result %d)", result);

	// Create some socket to discover in the pcblist after making the first sysctl.
	struct sockaddr_vm addr;
	int socket;
	result = vsock_listen(VMADDR_CID_ANY, 77799, &addr, 10, &socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock listen on a port");

	// Allocate the buffer.
	struct xvsockpgen *buffer = malloc(length);
	T_ASSERT_NOTNULL(buffer, "allocated buffer is not null");

	// Populate the buffer with the pcblist.
	result = sysctlbyname(pcblist, buffer, &length, 0, 0);
	T_ASSERT_POSIX_SUCCESS(result, "vsock pcblist populate buffer");

	// The socket was created after the buffer and cannot fit.
	bool exists = vsock_address_exists(buffer, addr);
	T_ASSERT_FALSE(exists, "vsock pcblist should not contain the new socket");

	vsock_close(socket);
	free(buffer);
}

T_DECL(vsock_pcblist_removed, "vsock pcblist sysctl - socket removed")
{
	// Create some socket to be removed after making the first sysctl.
	struct sockaddr_vm addr;
	int socket;
	int result = vsock_listen(VMADDR_CID_ANY, 66699, &addr, 10, &socket);
	T_ASSERT_POSIX_SUCCESS(result, "vsock listen on a port");

	// Get the buffer length for the pcblist.
	size_t length = 0;
	result = sysctlbyname(pcblist, 0, &length, 0, 0);
	if (result == ENOENT) {
		T_SKIP("%s missing", pcblist);
	}
	T_ASSERT_POSIX_SUCCESS(result, "vsock pcblist get buffer size (result %d)", result);

	// Close the socket early.
	vsock_close(socket);

	// Allocate the buffer.
	struct xvsockpgen *buffer = malloc(length);
	T_ASSERT_NOTNULL(buffer, "allocated buffer is not null");

	// Populate the buffer with the pcblist.
	result = sysctlbyname(pcblist, buffer, &length, 0, 0);
	T_ASSERT_POSIX_SUCCESS(result, "vsock pcblist populate buffer");

	// The socket was destroyed before populating the list and should not exist.
	bool exists = vsock_address_exists(buffer, addr);
	T_ASSERT_FALSE(exists, "vsock pcblist should not contain the deleted socket");

	free(buffer);
}
