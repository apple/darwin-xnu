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

/* -*- compile-command: "xcrun --sdk iphoneos.internal make recvmsg_x_test" -*- */


#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#define NMSGS       5
#define BUFFERLEN   1000

T_GLOBAL_META(T_META_NAMESPACE("xnu.net"));

static void
sendPackets(int s, struct sockaddr *dst, unsigned int numMsg, size_t bufferLen)
{
	ssize_t count = 0;
	struct msghdr msg = {};
	struct iovec vec = {};
	char *bytes = calloc(1, bufferLen);
	if (bytes == NULL) {
		err(EX_OSERR, "calloc()");
	}

	vec.iov_base = bytes;
	vec.iov_len = bufferLen;

	msg.msg_name = (void *)dst;
	msg.msg_namelen = dst->sa_len;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	for (unsigned int i = 0; i < numMsg; i++) {
		ssize_t n;
		T_QUIET; T_EXPECT_POSIX_SUCCESS(n = sendmsg(s, &msg, 0), "sendmsg()");
		T_LOG("Sent %ld bytes\n", n);
		count += 1;
	}

	// Wait a bit to make sure the packets reach the receiver
	usleep(100000);

	T_LOG("Sent %ld packet\n", count);

	free(bytes);
}

static void
recvPackets_x(int s, unsigned int numMsg, size_t buflen, socklen_t cmsgLen)
{
	struct msghdr_x *msgList;
	struct sockaddr_in *srcAddrs;
	struct iovec *vec;
	char *buffers;
	char *cmsgBuf;

	T_QUIET; T_ASSERT_NOTNULL(msgList = calloc(numMsg, sizeof(struct msghdr_x)), "msgList calloc()");
	T_QUIET; T_ASSERT_NOTNULL(srcAddrs = calloc(numMsg, sizeof(struct sockaddr_in)), "srcAddrs calloc()");
	T_QUIET; T_ASSERT_NOTNULL(vec = calloc(numMsg, sizeof(struct iovec)), "vec calloc()");
	T_QUIET; T_ASSERT_NOTNULL(buffers = calloc(numMsg, buflen), "buffers calloc()");
	T_QUIET; T_ASSERT_NOTNULL(cmsgBuf = calloc(numMsg, ALIGN(cmsgLen)), "cmsgBuf calloc()");

	u_int count = 0;
	while (true) {
		/*
		 * Wrap around when we've exhausted the list
		 */
		if ((count % numMsg) == 0) {
			for (unsigned int i = 0; i < numMsg; i++) {
				struct msghdr_x *msg = &msgList[i];
				msg->msg_name = &srcAddrs[i];
				msg->msg_namelen = sizeof(srcAddrs[i]);
				vec[i].iov_base = buffers + (i * buflen);
				vec[i].iov_len = buflen;
				msg->msg_iov = &vec[i];
				msg->msg_iovlen = 1;
				msg->msg_control = cmsgBuf + (i * ALIGN(cmsgLen));
				msg->msg_controllen = cmsgLen;
				msg->msg_flags = 0;

				T_QUIET; T_EXPECT_TRUE((uintptr_t)msg->msg_control % sizeof(uint32_t) == 0, NULL);
			}
		}

		ssize_t n = recvmsg_x(s, msgList + (count % numMsg), numMsg - (count % numMsg), 0);
		if (n < 0) {
			if (errno == EINTR) {
				T_LOG("recvmsg_x(): %s", strerror(errno));
				continue;
			}
			if (errno == EWOULDBLOCK) {
				T_LOG("recvmsg_x(): %s", strerror(errno));
				break;
			}
			T_FAIL("recvmsg_x() failed: %s", strerror(errno));
		}
		T_LOG("recvmsg_x returned %ld packets\n", n);

		for (unsigned int i = count; i < count + (u_int)n; i++) {
			struct msghdr_x *msg = &msgList[i % numMsg];

			T_LOG("Received packet #%d %lu bytes with recvmsg_x(), msg_namelen = %u, msg_controllen = %d -> %d, msg_flags = 0x%x\n",
			    i + 1, msg->msg_datalen, msg->msg_namelen, cmsgLen, msg->msg_controllen, msg->msg_flags);

			struct cmsghdr *cmsg;

			for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
				T_QUIET; T_EXPECT_TRUE((uintptr_t)cmsg % sizeof(uint32_t) == 0, NULL);

				T_LOG("level = %d, type = %d, length = %d\n", cmsg->cmsg_level, cmsg->cmsg_type, cmsg->cmsg_len);
			}
		}

		count += (u_int)n;
	}

	free(msgList);
	free(srcAddrs);
	free(vec);
	free(buffers);
	free(cmsgBuf);
}

T_DECL(recvmsg_x_test, "exercise revcmsg_x() with various parameter")
{
	struct sockaddr_in addr = {
		.sin_len = sizeof(addr),
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(0x7f000001),
		.sin_port = 0
	};

	int recvSocket;
	T_QUIET; T_EXPECT_POSIX_SUCCESS(recvSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP), "socket()");
	T_QUIET; T_EXPECT_POSIX_SUCCESS(bind(recvSocket, (const struct sockaddr *)&addr, sizeof(addr)), "bind()");

	socklen_t addrLen = sizeof(addr);
	T_QUIET; T_EXPECT_POSIX_SUCCESS(getsockname(recvSocket, (struct sockaddr *)&addr, &addrLen), "getsockname()");

	int one = 1;
	T_QUIET; T_EXPECT_POSIX_SUCCESS(setsockopt(recvSocket, IPPROTO_IP, IP_RECVPKTINFO, (void *)&one, sizeof(one)), "setsockopt(IP_RECVPKTINFO)");

	int flags = fcntl(recvSocket, F_GETFL, 0);
	T_QUIET; T_EXPECT_POSIX_SUCCESS(fcntl(recvSocket, F_SETFL, flags | O_NONBLOCK), "fcntl()");

	int sendSocket;
	T_QUIET; T_EXPECT_POSIX_SUCCESS(sendSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP), "sendSocket socket()");

	for (int dontTrunc = 0; dontTrunc <= 1; dontTrunc++) {
		T_QUIET; T_EXPECT_POSIX_SUCCESS(setsockopt(recvSocket, SOL_SOCKET, SO_DONTTRUNC, (void *)&dontTrunc, sizeof(dontTrunc)), "setsockopt(SO_DONTTRUNC)");

		T_LOG("\n================= recvmsg_x() test =================\n");
		sendPackets(sendSocket, (struct sockaddr *)&addr, NMSGS, BUFFERLEN);
		recvPackets_x(recvSocket, NMSGS, BUFFERLEN, 50);

		T_LOG("\n================= recvmsg_x() test =================\n");
		sendPackets(sendSocket, (struct sockaddr *)&addr, NMSGS, BUFFERLEN);
		recvPackets_x(recvSocket, NMSGS, BUFFERLEN * 2, 50);

		T_LOG("\n================= recvmsg_x() test =================\n");
		sendPackets(sendSocket, (struct sockaddr *)&addr, NMSGS, BUFFERLEN);
		recvPackets_x(recvSocket, NMSGS, BUFFERLEN / 2, 50);

		T_LOG("\n================= recvmsg_x() test =================\n");
		sendPackets(sendSocket, (struct sockaddr *)&addr, NMSGS, BUFFERLEN);
		recvPackets_x(recvSocket, NMSGS, BUFFERLEN, 10);

		T_LOG("\n================= recvmsg_x() test =================\n");
		sendPackets(sendSocket, (struct sockaddr *)&addr, NMSGS, BUFFERLEN);
		recvPackets_x(recvSocket, NMSGS, BUFFERLEN / 2, 10);
	}

	close(sendSocket);
	close(recvSocket);

	T_LOG("\n================= PASS =================\n");
}
