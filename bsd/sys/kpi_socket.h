/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*!
	@header kpi_socket.h
	This header defines an API for creating and interacting with sockets
	in the kernel. It is possible to create sockets in the kernel
	without an associated file descriptor. In some cases, a reference to
	the socket may be known while the file descriptor is not. These
	functions can be used for interacting with sockets in the kernel.
	The API is similar to the user space socket API.
 */
#ifndef __KPI_SOCKET__
#define __KPI_SOCKET__

#include <sys/types.h>
#include <sys/kernel_types.h>

struct timeval;

/*!
	@typedef sock_upcall
	
	@discussion sock_upcall is used by a socket to notify an in kernel
		client that data is waiting. Instead of making blocking calls in
		the kernel, a client can specify an upcall which will be called
		when data is available or the socket is ready for sending.
		
		Calls to your upcall function are not serialized and may be
		called concurrently from multiple threads in the kernel.
		
		Your upcall function will be called when:
		
	@param so A reference to the socket that's ready.
	@param cookie The cookie passed in when the socket was created.
	@param waitf Indicates whether or not it's safe to block.
*/
typedef void (*sock_upcall)(socket_t so, void* cookie, int waitf);

/*!
	@function sock_accept
	@discussion Accepts an incoming connection on a socket. See 'man 2
		accept' for more information. Allocating a socket in this manner
		creates a socket with no associated file descriptor.
	@param so The listening socket you'd like to accept a connection on.
	@param from A pointer to a socket address that will be filled in
		with the address the connection is from.
	@param fromlen Maximum length of from.
	@param flags Supports MSG_DONTWAIT and MSG_USEUPCALL. If
		MSG_DONTWAIT is set, accept will return EWOULDBLOCK if there are
		no connections ready to be accepted. If MSG_USEUPCALL is set,
		the created socket will use the same upcall function attached to
		the original socket.
	@param callback A notifier function to be called when an event
		occurs on the socket. This may be NULL.
	@param cookie A cookie passed directly to the callback.
	@param new_so Upon success, *new_so will be a reference to a new
		socket for tracking the connection.
	@result 0 on success otherwise the errno error.
 */
errno_t sock_accept(socket_t so, struct sockaddr *from, int fromlen,
					int flags, sock_upcall callback, void* cookie,
					socket_t *new_so);

/*!
	@function sock_bind
	@discussion Binds a socket to a specific address. See 'man 2 bind'
		for more information.
	@param so The socket to be bound.
	@param to The local address the socket should be bound to.
	@result 0 on success otherwise the errno error.
 */
errno_t sock_bind(socket_t so, const struct sockaddr *to);

/*!
	@function sock_connect
	@discussion Initiates a connection on the socket. See 'man 2
		connect' for more information.
	@param so The socket to be connect.
	@param to The remote address the socket should connect to.
	@param flags Flags for connecting. The only flag supported so far is
		MSG_DONTWAIT. MSG_DONTWAIT will perform a non-blocking connect.
		sock_connect will return immediately with EINPROGRESS. The
		upcall, if supplied, will be called when the connection is
		completed.
	@result 0 on success, EINPROGRESS for a non-blocking connect that
		has not completed, otherwise the errno error.
 */
errno_t sock_connect(socket_t so, const struct sockaddr *to, int flags);

#ifdef KERNEL_PRIVATE
/*!
	This function was added to support NFS. NFS does something funny,
	setting a short timeout and checking to see if it should abort the
	connect every two seconds. Ideally, NFS would use the upcall to be
	notified when the connect is complete.
	
	If you feel you need to use this function, please contact us to
	explain why.
	
	@function sock_connectwait
	@discussion Allows a caller to wait on a socket connect.
	@param so The socket being connected.
	@param tv The amount of time to wait.
	@result 0 on success otherwise the errno error. EINPROGRESS will be
		returned if the connection did not complete in the timeout
		specified.
 */
errno_t sock_connectwait(socket_t so, const struct timeval *tv);
#endif KERNEL_PRIVATE

/*!
	@function sock_getpeername
	@discussion Retrieves the remote address of a connected socket. See
		'man 2 getpeername'.
	@param so The socket.
	@param peername Storage for the peer name.
	@param peernamelen Length of storage for the peer name.
	@result 0 on success otherwise the errno error.
 */
errno_t sock_getpeername(socket_t so, struct sockaddr *peername, int peernamelen);

/*!
	@function sock_getsockname
	@discussion Retrieves the local address of a socket. See 'man 2
		getsockname'.
	@param so The socket.
	@param sockname Storage for the local name.
	@param socknamelen Length of storage for the socket name.
	@result 0 on success otherwise the errno error.
 */
errno_t sock_getsockname(socket_t so, struct sockaddr *sockname, int socknamelen);

/*!
	@function sock_getsockopt
	@discussion Retrieves a socket option. See 'man 2 getsockopt'.
	@param so The socket.
	@param level Level of the socket option.
	@param optname The option name.
	@param optval The option value.
	@param optlen The length of optval, returns the actual length.
	@result 0 on success otherwise the errno error.
 */
errno_t sock_getsockopt(socket_t so, int level, int optname, void *optval, int *optlen);

/*!
	@function sock_ioctl
	@discussion Performs an ioctl operation on a socket. See 'man 2 ioctl'.
	@param so The socket.
	@param request The ioctl name.
	@param argp The argument.
	@result 0 on success otherwise the errno error.
 */
errno_t sock_ioctl(socket_t so, unsigned long request, void *argp);

/*!
	@function sock_setsockopt
	@discussion Sets a socket option. See 'man 2 setsockopt'.
	@param so The socket.
	@param level Level of the socket option.
	@param optname The option name.
	@param optval The option value.
	@param optlen The length of optval.
	@result 0 on success otherwise the errno error.
 */
errno_t sock_setsockopt(socket_t so, int level, int optname, const void *optval, int optlen);

/*!
	@function sock_listen
	@discussion Indicate that the socket should start accepting incoming
		connections. See 'man 2 listen'.
	@param so The socket.
	@param backlog The maximum length of the queue of pending connections.
	@result 0 on success otherwise the errno error.
 */
errno_t sock_listen(socket_t so, int backlog);

/*!
	@function sock_receive
	@discussion Receive data from a socket. Similar to recvmsg. See 'man
		2 recvmsg' for more information about receiving data.
	@param so The socket.
	@param msg The msg describing how the data should be received.
	@param flags See 'man 2 recvmsg'.
	@param recvdlen Number of bytes received, same as return value of
		userland recvmsg.
	@result 0 on success, EWOULDBLOCK if non-blocking and operation
		would cause the thread to block, otherwise the errno error.
 */
errno_t sock_receive(socket_t so, struct msghdr *msg, int flags, size_t *recvdlen);

/*!
	@function sock_receivembuf
	@discussion Receive data from a socket. Similar to sock_receive
		though data is returned as a chain of mbufs. See 'man 2 recvmsg'
		for more information about receiving data.
	@param so The socket.
	@param msg The msg describing how the data should be received. May
		be NULL. The msg_iov is ignored.
	@param data Upon return *data will be a reference to an mbuf chain
		containing the data received. This eliminates copying the data
		out of the mbufs. Caller is responsible for freeing the mbufs.
	@param flags See 'man 2 recvmsg'.
	@param recvlen Maximum number of bytes to receive in the mbuf chain.
		Upon return, this value will be set to the number of bytes
		received, same as return value of userland recvmsg.
	@result 0 on success, EWOULDBLOCK if non-blocking and operation
		would cause the thread to block, otherwise the errno error.
 */
errno_t sock_receivembuf(socket_t so, struct msghdr *msg, mbuf_t *data, int flags, size_t *recvlen);

/*!
	@function sock_send
	@discussion Send data on a socket. Similar to sendmsg. See 'man 2
		sendmsg' for more information about sending data.
	@param so The socket.
	@param msg The msg describing how the data should be sent. Any
		pointers must point to data in the kernel.
	@param flags See 'man 2 sendmsg'.
	@param sentlen The number of bytes sent.
	@result 0 on success, EWOULDBLOCK if non-blocking and operation
		would cause the thread to block, otherwise the errno error.
 */
errno_t sock_send(socket_t so, const struct msghdr *msg, int flags, size_t *sentlen);

/*!
	@function sock_sendmbuf
	@discussion Send data in an mbuf on a socket. Similar to sock_send
		only the data to be sent is taken from the mbuf chain.
	@param so The socket.
	@param msg The msg describing how the data should be sent. The
		msg_iov is ignored. msg may be NULL.
	@param data The mbuf chain of data to send.
	@param flags See 'man 2 sendmsg'.
	@param sentlen The number of bytes sent.
	@result 0 on success, EWOULDBLOCK if non-blocking and operation
		would cause the thread to block, otherwise the errno error.
		Regardless of return value, the mbuf chain 'data' will be freed.
 */
errno_t sock_sendmbuf(socket_t so, const struct msghdr *msg, mbuf_t data, int flags, size_t *sentlen);

/*!
	@function sock_shutdown
	@discussion Shutdown one or both directions of a connection. See
		'man 2 shutdown' for more information.
	@param so The socket.
	@param how SHUT_RD - shutdown receive. SHUT_WR - shutdown send. SHUT_RDWR - shutdown both.
	@result 0 on success otherwise the errno error.
 */
errno_t sock_shutdown(socket_t so, int how);

/*!
	@function sock_socket
	@discussion Allocate a socket. Allocating a socket in this manner
		creates a socket with no associated file descriptor. For more
		information, see 'man 2 socket'.
	@param domain The socket domain (PF_INET, etc...).
	@param type The socket type (SOCK_STREAM, SOCK_DGRAM, etc...).
	@param protocol The socket protocol.
	@param callback A notifier function to be called when an event
		occurs on the socket. This may be NULL.
	@param cookie A cookie passed directly to the callback.
	@param new_so Upon success, a reference to the new socket.
	@result 0 on success otherwise the errno error.
 */
errno_t sock_socket(int domain, int type, int protocol, sock_upcall callback,
			   void* cookie, socket_t *new_so);

/*!
	@function sock_close
	@discussion Close the socket.
	@param so The socket to close. This should only ever be a socket
		created with sock_socket. Closing a socket created in user space
		using sock_close may leave a file descriptor pointing to the closed
		socket, resulting in undefined behavior.
 */
void	sock_close(socket_t so);

/*!
	@function sock_retain
	@discussion Prevents the socket from closing
	@param so The socket to close.  Increment a retain count on the
		socket, preventing it from being closed when sock_close is
		called. This is used when a File Descriptor is passed (and
		closed) from userland and the kext wants to keep ownership of
		that socket. It is used in conjunction with
		sock_release(socket_t so).
 */
void	sock_retain(socket_t so);

/*!
	@function sock_release
	@discussion Decrement the retain count and close the socket if the
		retain count reaches zero.
	@param so The socket to release. This is used to release ownership
		on a socket acquired with sock_retain. When the last retain
		count is reached, this will call sock_close to close the socket.
 */
void	sock_release(socket_t so);

/*!
	@function sock_setpriv
	@discussion Set the privileged bit in the socket. Allows for
		operations that require root privileges.
	@param so The socket on which to modify the SS_PRIV flag.
	@param on Indicate whether or not the SS_PRIV flag should be set.
	@result 0 on success otherwise the errno error.
 */
errno_t sock_setpriv(socket_t so, int on);

/*!
	@function sock_isconnected
	@discussion Returns whether or not the socket is connected.
	@param so The socket to check.
	@result 0 - socket is not connected. 1 - socket is connected.
 */
int sock_isconnected(socket_t so);

/*!
	@function sock_isnonblocking
	@discussion Returns whether or not the socket is non-blocking. In
		the context of this KPI, non-blocking means that functions to
		perform operations on a socket will not wait for completion.
		
		To enable or disable blocking, use the FIONBIO ioctl. The
		parameter is an int. If the int is zero, the socket will block.
		If the parameter is non-zero, the socket will not block.
	@result 0 - socket will block. 1 - socket will not block.
 */
int sock_isnonblocking(socket_t so);

/*!
	@function sock_gettype
	@discussion Retrieves information about the socket. This is the same
		information that was used to create the socket. If any of the
		parameters following so are NULL, that information is not
		retrieved.
	@param so The socket to check.
	@param domain The domain of the socket (PF_INET, etc...). May be NULL.
	@param type The socket type (SOCK_STREAM, SOCK_DGRAM, etc...). May be NULL.
	@param protocol The socket protocol. May be NULL.
	@result 0 on success otherwise the errno error.
 */
errno_t sock_gettype(socket_t so, int *domain, int *type, int *protocol);

#ifdef KERNEL_PRIVATE
/*!
	@function sock_nointerrupt
	@discussion Disables interrupt on socket buffers (sets SB_NOINTR on
		send and receive socket buffers).
	@param so The socket to modify.
	@param on Indicate whether or not the SB_NOINTR flag should be set.
	@result 0 on success otherwise the errno error.
 */
errno_t sock_nointerrupt(socket_t so, int on);
#endif KERNEL_PRIVATE
#endif __KPI_SOCKET__
