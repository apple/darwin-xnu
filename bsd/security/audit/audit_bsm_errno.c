/*-
 * Copyright (c) 2008-2019 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <sys/param.h>

#include <security/audit/audit.h>

#include <bsm/audit_errno.h>
#include <bsm/audit_record.h>

#include <sys/errno.h>

#if CONFIG_AUDIT
/*
 * Different operating systems use different numeric constants for different
 * error numbers, and sometimes error numbers don't exist in more than one
 * operating system.  These routines convert between BSM and local error
 * number spaces, subject to the above realities.  BSM error numbers are
 * stored in a single 8-bit character, so don't have a byte order.
 *
 * Don't include string definitions when this code is compiled into a kernel.
 */
struct bsm_errno {
	int              be_bsm_errno;
	int              be_local_errno;
#if !defined(KERNEL) && !defined(_KERNEL)
	const char      *be_strerror;
#endif
};

#define ERRNO_NO_LOCAL_MAPPING  -600

#if !defined(KERNEL) && !defined(_KERNEL)
#define ES(x)   .be_strerror = x
#else
#define ES(x)
#endif

/*
 * Mapping table -- please maintain in numeric sorted order with respect to
 * the BSM constant.  Today we do a linear lookup, but could switch to a
 * binary search if it makes sense.  We only ifdef errors that aren't
 * generally available, but it does make the table a lot more ugly.
 *
 * XXXRW: It would be nice to have a similar ordered table mapping to BSM
 * constant from local constant, but the order of local constants varies by
 * OS.  Really we need to build that table at compile-time but don't do that
 * yet.
 *
 * XXXRW: We currently embed English-language error strings here, but should
 * support catalogues; these are only used if the OS doesn't have an error
 * string using strerror(3).
 */
static const struct bsm_errno bsm_errnos[] = {
	{ .be_bsm_errno = BSM_ERRNO_ESUCCESS, .be_local_errno = 0, ES("Success") },
	{ .be_bsm_errno = BSM_ERRNO_EPERM, .be_local_errno = EPERM, ES("Operation not permitted") },
	{ .be_bsm_errno = BSM_ERRNO_ENOENT, .be_local_errno = ENOENT, ES("No such file or directory") },
	{ .be_bsm_errno = BSM_ERRNO_ESRCH, .be_local_errno = ESRCH, ES("No such process") },
	{ .be_bsm_errno = BSM_ERRNO_EINTR, .be_local_errno = EINTR, ES("Interrupted system call") },
	{ .be_bsm_errno = BSM_ERRNO_EIO, .be_local_errno = EIO, ES("Input/output error") },
	{ .be_bsm_errno = BSM_ERRNO_ENXIO, .be_local_errno = ENXIO, ES("Device not configured") },
	{ .be_bsm_errno = BSM_ERRNO_E2BIG, .be_local_errno = E2BIG, ES("Argument list too long") },
	{ .be_bsm_errno = BSM_ERRNO_ENOEXEC, .be_local_errno = ENOEXEC, ES("Exec format error") },
	{ .be_bsm_errno = BSM_ERRNO_EBADF, .be_local_errno = EBADF, ES("Bad file descriptor") },
	{ .be_bsm_errno = BSM_ERRNO_ECHILD, .be_local_errno = ECHILD, ES("No child processes") },
	{ .be_bsm_errno = BSM_ERRNO_EAGAIN, .be_local_errno = EAGAIN, ES("Resource temporarily unavailable") },
	{ .be_bsm_errno = BSM_ERRNO_ENOMEM, .be_local_errno = ENOMEM, ES("Cannot allocate memory") },
	{ .be_bsm_errno = BSM_ERRNO_EACCES, .be_local_errno = EACCES, ES("Permission denied") },
	{ .be_bsm_errno = BSM_ERRNO_EFAULT, .be_local_errno = EFAULT, ES("Bad address") },
	{ .be_bsm_errno = BSM_ERRNO_ENOTBLK, .be_local_errno = ENOTBLK, ES("Block device required") },
	{ .be_bsm_errno = BSM_ERRNO_EBUSY, .be_local_errno = EBUSY, ES("Device busy") },
	{ .be_bsm_errno = BSM_ERRNO_EEXIST, .be_local_errno = EEXIST, ES("File exists") },
	{ .be_bsm_errno = BSM_ERRNO_EXDEV, .be_local_errno = EXDEV, ES("Cross-device link") },
	{ .be_bsm_errno = BSM_ERRNO_ENODEV, .be_local_errno = ENODEV, ES("Operation not supported by device") },
	{ .be_bsm_errno = BSM_ERRNO_ENOTDIR, .be_local_errno = ENOTDIR, ES("Not a directory") },
	{ .be_bsm_errno = BSM_ERRNO_EISDIR, .be_local_errno = EISDIR, ES("Is a directory") },
	{ .be_bsm_errno = BSM_ERRNO_EINVAL, .be_local_errno = EINVAL, ES("Invalid argument") },
	{ .be_bsm_errno = BSM_ERRNO_ENFILE, .be_local_errno = ENFILE, ES("Too many open files in system") },
	{ .be_bsm_errno = BSM_ERRNO_EMFILE, .be_local_errno = EMFILE, ES("Too many open files") },
	{ .be_bsm_errno = BSM_ERRNO_ENOTTY, .be_local_errno = ENOTTY, ES("Inappropriate ioctl for device") },
	{ .be_bsm_errno = BSM_ERRNO_ETXTBSY, .be_local_errno = ETXTBSY, ES("Text file busy") },
	{ .be_bsm_errno = BSM_ERRNO_EFBIG, .be_local_errno = EFBIG, ES("File too large") },
	{ .be_bsm_errno = BSM_ERRNO_ENOSPC, .be_local_errno = ENOSPC, ES("No space left on device") },
	{ .be_bsm_errno = BSM_ERRNO_ESPIPE, .be_local_errno = ESPIPE, ES("Illegal seek") },
	{ .be_bsm_errno = BSM_ERRNO_EROFS, .be_local_errno = EROFS, ES("Read-only file system") },
	{ .be_bsm_errno = BSM_ERRNO_EMLINK, .be_local_errno = EMLINK, ES("Too many links") },
	{ .be_bsm_errno = BSM_ERRNO_EPIPE, .be_local_errno = EPIPE, ES("Broken pipe") },
	{ .be_bsm_errno = BSM_ERRNO_EDOM, .be_local_errno = EDOM, ES("Numerical argument out of domain") },
	{ .be_bsm_errno = BSM_ERRNO_ERANGE, .be_local_errno = ERANGE, ES("Result too large") },
	{ .be_bsm_errno = BSM_ERRNO_ENOMSG, .be_local_errno = ENOMSG, ES("No message of desired type") },
	{ .be_bsm_errno = BSM_ERRNO_EIDRM, .be_local_errno = EIDRM, ES("Identifier removed") },
	{ .be_bsm_errno = BSM_ERRNO_ECHRNG,
#ifdef ECHRNG
	  .be_local_errno = ECHRNG,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Channel number out of range") },
	{ .be_bsm_errno = BSM_ERRNO_EL2NSYNC,
#ifdef EL2NSYNC
	  .be_local_errno = EL2NSYNC,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Level 2 not synchronized") },
	{ .be_bsm_errno = BSM_ERRNO_EL3HLT,
#ifdef EL3HLT
	  .be_local_errno = EL3HLT,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Level 3 halted") },
	{ .be_bsm_errno = BSM_ERRNO_EL3RST,
#ifdef EL3RST
	  .be_local_errno = EL3RST,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Level 3 reset") },
	{ .be_bsm_errno = BSM_ERRNO_ELNRNG,
#ifdef ELNRNG
	  .be_local_errno = ELNRNG,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Link number out of range") },
	{ .be_bsm_errno = BSM_ERRNO_EUNATCH,
#ifdef EUNATCH
	  .be_local_errno = EUNATCH,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Protocol driver not attached") },
	{ .be_bsm_errno = BSM_ERRNO_ENOCSI,
#ifdef ENOCSI
	  .be_local_errno = ENOCSI,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("No CSI structure available") },
	{ .be_bsm_errno = BSM_ERRNO_EL2HLT,
#ifdef EL2HLT
	  .be_local_errno = EL2HLT,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Level 2 halted") },
	{ .be_bsm_errno = BSM_ERRNO_EDEADLK, .be_local_errno = EDEADLK, ES("Resource deadlock avoided") },
	{ .be_bsm_errno = BSM_ERRNO_ENOLCK, .be_local_errno = ENOLCK, ES("No locks available") },
	{ .be_bsm_errno = BSM_ERRNO_ECANCELED, .be_local_errno = ECANCELED, ES("Operation canceled") },
	{ .be_bsm_errno = BSM_ERRNO_ENOTSUP, .be_local_errno = ENOTSUP, ES("Operation not supported") },
	{ .be_bsm_errno = BSM_ERRNO_EDQUOT, .be_local_errno = EDQUOT, ES("Disc quota exceeded") },
	{ .be_bsm_errno = BSM_ERRNO_EBADE,
#ifdef EBADE
	  .be_local_errno = EBADE,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Invalid exchange") },
	{ .be_bsm_errno = BSM_ERRNO_EBADR,
#ifdef EBADR
	  .be_local_errno = EBADR,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Invalid request descriptor") },
	{ .be_bsm_errno = BSM_ERRNO_EXFULL,
#ifdef EXFULL
	  .be_local_errno = EXFULL,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Exchange full") },
	{ .be_bsm_errno = BSM_ERRNO_ENOANO,
#ifdef ENOANO
	  .be_local_errno = ENOANO,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("No anode") },
	{ .be_bsm_errno = BSM_ERRNO_EBADRQC,
#ifdef EBADRQC
	  .be_local_errno = EBADRQC,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Invalid request descriptor") },
	{ .be_bsm_errno = BSM_ERRNO_EBADSLT,
#ifdef EBADSLT
	  .be_local_errno = EBADSLT,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Invalid slot") },
	{ .be_bsm_errno = BSM_ERRNO_EDEADLOCK,
#ifdef EDEADLOCK
	  .be_local_errno = EDEADLOCK,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Resource deadlock avoided") },
	{ .be_bsm_errno = BSM_ERRNO_EBFONT,
#ifdef EBFONT
	  .be_local_errno = EBFONT,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Bad font file format") },
	{ .be_bsm_errno = BSM_ERRNO_EOWNERDEAD,
#ifdef EOWNERDEAD
	  .be_local_errno = EOWNERDEAD,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Process died with the lock") },
	{ .be_bsm_errno = BSM_ERRNO_ENOTRECOVERABLE,
#ifdef ENOTRECOVERABLE
	  .be_local_errno = ENOTRECOVERABLE,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Lock is not recoverable") },
	{ .be_bsm_errno = BSM_ERRNO_ENOSTR,
#ifdef ENOSTR
	  .be_local_errno = ENOSTR,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Device not a stream") },
	{ .be_bsm_errno = BSM_ERRNO_ENONET,
#ifdef ENONET
	  .be_local_errno = ENONET,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Machine is not on the network") },
	{ .be_bsm_errno = BSM_ERRNO_ENOPKG,
#ifdef ENOPKG
	  .be_local_errno = ENOPKG,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Package not installed") },
	{ .be_bsm_errno = BSM_ERRNO_EREMOTE, .be_local_errno = EREMOTE,
	  ES("Too many levels of remote in path") },
	{ .be_bsm_errno = BSM_ERRNO_ENOLINK,
#ifdef ENOLINK
	  .be_local_errno = ENOLINK,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Link has been severed") },
	{ .be_bsm_errno = BSM_ERRNO_EADV,
#ifdef EADV
	  .be_local_errno = EADV,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Advertise error") },
	{ .be_bsm_errno = BSM_ERRNO_ESRMNT,
#ifdef ESRMNT
	  .be_local_errno = ESRMNT,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("srmount error") },
	{ .be_bsm_errno = BSM_ERRNO_ECOMM,
#ifdef ECOMM
	  .be_local_errno = ECOMM,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Communication error on send") },
	{ .be_bsm_errno = BSM_ERRNO_EPROTO,
#ifdef EPROTO
	  .be_local_errno = EPROTO,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Protocol error") },
	{ .be_bsm_errno = BSM_ERRNO_ELOCKUNMAPPED,
#ifdef ELOCKUNMAPPED
	  .be_local_errno = ELOCKUNMAPPED,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Locked lock was unmapped") },
	{ .be_bsm_errno = BSM_ERRNO_ENOTACTIVE,
#ifdef ENOTACTIVE
	  .be_local_errno = ENOTACTIVE,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Facility is not active") },
	{ .be_bsm_errno = BSM_ERRNO_EMULTIHOP,
#ifdef EMULTIHOP
	  .be_local_errno = EMULTIHOP,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Multihop attempted") },
	{ .be_bsm_errno = BSM_ERRNO_EBADMSG,
#ifdef EBADMSG
	  .be_local_errno = EBADMSG,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Bad message") },
	{ .be_bsm_errno = BSM_ERRNO_ENAMETOOLONG, .be_local_errno = ENAMETOOLONG, ES("File name too long") },
	{ .be_bsm_errno = BSM_ERRNO_EOVERFLOW, .be_local_errno = EOVERFLOW,
	  ES("Value too large to be stored in data type") },
	{ .be_bsm_errno = BSM_ERRNO_ENOTUNIQ,
#ifdef ENOTUNIQ
	  .be_local_errno = ENOTUNIQ,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Given log name not unique") },
	{ .be_bsm_errno = BSM_ERRNO_EBADFD,
#ifdef EBADFD
	  .be_local_errno = EBADFD,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Given f.d. invalid for this operation") },
	{ .be_bsm_errno = BSM_ERRNO_EREMCHG,
#ifdef EREMCHG
	  .be_local_errno = EREMCHG,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Remote address changed") },
	{ .be_bsm_errno = BSM_ERRNO_ELIBACC,
#ifdef ELIBACC
	  .be_local_errno = ELIBACC,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Can't access a needed shared lib") },
	{ .be_bsm_errno = BSM_ERRNO_ELIBBAD,
#ifdef ELIBBAD
	  .be_local_errno = ELIBBAD,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Accessing a corrupted shared lib") },
	{ .be_bsm_errno = BSM_ERRNO_ELIBSCN,
#ifdef ELIBSCN
	  .be_local_errno = ELIBSCN,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES(".lib section in a.out corrupted") },
	{ .be_bsm_errno = BSM_ERRNO_ELIBMAX,
#ifdef ELIBMAX
	  .be_local_errno = ELIBMAX,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Attempting to link in too many libs") },
	{ .be_bsm_errno = BSM_ERRNO_ELIBEXEC,
#ifdef ELIBEXEC
	  .be_local_errno = ELIBEXEC,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Attempting to exec a shared library") },
	{ .be_bsm_errno = BSM_ERRNO_EILSEQ, .be_local_errno = EILSEQ, ES("Illegal byte sequence") },
	{ .be_bsm_errno = BSM_ERRNO_ENOSYS, .be_local_errno = ENOSYS, ES("Function not implemented") },
	{ .be_bsm_errno = BSM_ERRNO_ELOOP, .be_local_errno = ELOOP, ES("Too many levels of symbolic links") },
	{ .be_bsm_errno = BSM_ERRNO_ERESTART,
#ifdef ERESTART
	  .be_local_errno = ERESTART,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Restart syscall") },
	{ .be_bsm_errno = BSM_ERRNO_ESTRPIPE,
#ifdef ESTRPIPE
	  .be_local_errno = ESTRPIPE,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("If pipe/FIFO, don't sleep in stream head") },
	{ .be_bsm_errno = BSM_ERRNO_ENOTEMPTY, .be_local_errno = ENOTEMPTY, ES("Directory not empty") },
	{ .be_bsm_errno = BSM_ERRNO_EUSERS, .be_local_errno = EUSERS, ES("Too many users") },
	{ .be_bsm_errno = BSM_ERRNO_ENOTSOCK, .be_local_errno = ENOTSOCK,
	  ES("Socket operation on non-socket") },
	{ .be_bsm_errno = BSM_ERRNO_EDESTADDRREQ, .be_local_errno = EDESTADDRREQ,
	  ES("Destination address required") },
	{ .be_bsm_errno = BSM_ERRNO_EMSGSIZE, .be_local_errno = EMSGSIZE, ES("Message too long") },
	{ .be_bsm_errno = BSM_ERRNO_EPROTOTYPE, .be_local_errno = EPROTOTYPE,
	  ES("Protocol wrong type for socket") },
	{ .be_bsm_errno = BSM_ERRNO_ENOPROTOOPT, .be_local_errno = ENOPROTOOPT, ES("Protocol not available") },
	{ .be_bsm_errno = BSM_ERRNO_EPROTONOSUPPORT, .be_local_errno = EPROTONOSUPPORT,
	  ES("Protocol not supported") },
	{ .be_bsm_errno = BSM_ERRNO_ESOCKTNOSUPPORT, .be_local_errno = ESOCKTNOSUPPORT,
	  ES("Socket type not supported") },
	{ .be_bsm_errno = BSM_ERRNO_EOPNOTSUPP, .be_local_errno = EOPNOTSUPP, ES("Operation not supported") },
	{ .be_bsm_errno = BSM_ERRNO_EPFNOSUPPORT, .be_local_errno = EPFNOSUPPORT,
	  ES("Protocol family not supported") },
	{ .be_bsm_errno = BSM_ERRNO_EAFNOSUPPORT, .be_local_errno = EAFNOSUPPORT,
	  ES("Address family not supported by protocol family") },
	{ .be_bsm_errno = BSM_ERRNO_EADDRINUSE, .be_local_errno = EADDRINUSE, ES("Address already in use") },
	{ .be_bsm_errno = BSM_ERRNO_EADDRNOTAVAIL, .be_local_errno = EADDRNOTAVAIL,
	  ES("Can't assign requested address") },
	{ .be_bsm_errno = BSM_ERRNO_ENETDOWN, .be_local_errno = ENETDOWN, ES("Network is down") },
	{ .be_bsm_errno = BSM_ERRNO_ENETRESET, .be_local_errno = ENETRESET,
	  ES("Network dropped connection on reset") },
	{ .be_bsm_errno = BSM_ERRNO_ECONNABORTED, .be_local_errno = ECONNABORTED,
	  ES("Software caused connection abort") },
	{ .be_bsm_errno = BSM_ERRNO_ECONNRESET, .be_local_errno = ECONNRESET, ES("Connection reset by peer") },
	{ .be_bsm_errno = BSM_ERRNO_ENOBUFS, .be_local_errno = ENOBUFS, ES("No buffer space available") },
	{ .be_bsm_errno = BSM_ERRNO_EISCONN, .be_local_errno = EISCONN, ES("Socket is already connected") },
	{ .be_bsm_errno = BSM_ERRNO_ENOTCONN, .be_local_errno = ENOTCONN, ES("Socket is not connected") },
	{ .be_bsm_errno = BSM_ERRNO_ESHUTDOWN, .be_local_errno = ESHUTDOWN,
	  ES("Can't send after socket shutdown") },
	{ .be_bsm_errno = BSM_ERRNO_ETOOMANYREFS, .be_local_errno = ETOOMANYREFS,
	  ES("Too many references: can't splice") },
	{ .be_bsm_errno = BSM_ERRNO_ETIMEDOUT, .be_local_errno = ETIMEDOUT, ES("Operation timed out") },
	{ .be_bsm_errno = BSM_ERRNO_ECONNREFUSED, .be_local_errno = ECONNREFUSED, ES("Connection refused") },
	{ .be_bsm_errno = BSM_ERRNO_EHOSTDOWN, .be_local_errno = EHOSTDOWN, ES("Host is down") },
	{ .be_bsm_errno = BSM_ERRNO_EHOSTUNREACH, .be_local_errno = EHOSTUNREACH, ES("No route to host") },
	{ .be_bsm_errno = BSM_ERRNO_EALREADY, .be_local_errno = EALREADY, ES("Operation already in progress") },
	{ .be_bsm_errno = BSM_ERRNO_EINPROGRESS, .be_local_errno = EINPROGRESS,
	  ES("Operation now in progress") },
	{ .be_bsm_errno = BSM_ERRNO_ESTALE, .be_local_errno = ESTALE, ES("Stale NFS file handle") },
	{ .be_bsm_errno = BSM_ERRNO_EQFULL, .be_local_errno = EQFULL, ES("Interface output queue is full") },
	{ .be_bsm_errno = BSM_ERRNO_EPWROFF,
#ifdef EPWROFF
	  .be_local_errno = EPWROFF,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Device power is off") },
	{ .be_bsm_errno = BSM_ERRNO_EDEVERR,
#ifdef EDEVERR
	  .be_local_errno = EDEVERR,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Device error") },
	{ .be_bsm_errno = BSM_ERRNO_EBADEXEC,
#ifdef EBADEXEC
	  .be_local_errno = EBADEXEC,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Bad executable") },
	{ .be_bsm_errno = BSM_ERRNO_EBADARCH,
#ifdef EBADARCH
	  .be_local_errno = EBADARCH,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Bad CPU type in executable") },
	{ .be_bsm_errno = BSM_ERRNO_ESHLIBVERS,
#ifdef ESHLIBVERS
	  .be_local_errno = ESHLIBVERS,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Shared library version mismatch") },
	{ .be_bsm_errno = BSM_ERRNO_EBADMACHO,
#ifdef EBADMACHO
	  .be_local_errno = EBADMACHO,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Malformed Macho file") },
	{ .be_bsm_errno = BSM_ERRNO_EPOLICY,
#ifdef EPOLICY
	  .be_local_errno = EPOLICY,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Operation failed by policy") },
	{ .be_bsm_errno = BSM_ERRNO_EDOTDOT,
#ifdef EDOTDOT
	  .be_local_errno = EDOTDOT,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("RFS specific error") },
	{ .be_bsm_errno = BSM_ERRNO_EUCLEAN,
#ifdef EUCLEAN
	  .be_local_errno = EUCLEAN,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Structure needs cleaning") },
	{ .be_bsm_errno = BSM_ERRNO_ENOTNAM,
#ifdef ENOTNAM
	  .be_local_errno = ENOTNAM,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Not a XENIX named type file") },
	{ .be_bsm_errno = BSM_ERRNO_ENAVAIL,
#ifdef ENAVAIL
	  .be_local_errno = ENAVAIL,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("No XENIX semaphores available") },
	{ .be_bsm_errno = BSM_ERRNO_EISNAM,
#ifdef EISNAM
	  .be_local_errno = EISNAM,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Is a named type file") },
	{ .be_bsm_errno = BSM_ERRNO_EREMOTEIO,
#ifdef EREMOTEIO
	  .be_local_errno = EREMOTEIO,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Remote I/O error") },
	{ .be_bsm_errno = BSM_ERRNO_ENOMEDIUM,
#ifdef ENOMEDIUM
	  .be_local_errno = ENOMEDIUM,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("No medium found") },
	{ .be_bsm_errno = BSM_ERRNO_EMEDIUMTYPE,
#ifdef EMEDIUMTYPE
	  .be_local_errno = EMEDIUMTYPE,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Wrong medium type") },
	{ .be_bsm_errno = BSM_ERRNO_ENOKEY,
#ifdef ENOKEY
	  .be_local_errno = ENOKEY,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Required key not available") },
	{ .be_bsm_errno = BSM_ERRNO_EKEYEXPIRED,
#ifdef EKEEXPIRED
	  .be_local_errno = EKEYEXPIRED,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Key has expired") },
	{ .be_bsm_errno = BSM_ERRNO_EKEYREVOKED,
#ifdef EKEYREVOKED
	  .be_local_errno = EKEYREVOKED,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Key has been revoked") },
	{ .be_bsm_errno = BSM_ERRNO_EKEYREJECTED,
#ifdef EKEREJECTED
	  .be_local_errno = EKEYREJECTED,
#else
	  .be_local_errno = ERRNO_NO_LOCAL_MAPPING,
#endif
	  ES("Key was rejected by service") },
};
static const int bsm_errnos_count = sizeof(bsm_errnos) / sizeof(bsm_errnos[0]);

static const struct bsm_errno *
bsm_lookup_errno_local(int local_errno)
{
	int i;

	for (i = 0; i < bsm_errnos_count; i++) {
		if (bsm_errnos[i].be_local_errno == local_errno) {
			return &bsm_errnos[i];
		}
	}
	return NULL;
}

/*
 * Conversion to the BSM errno space isn't allowed to fail; we simply map to
 * BSM_ERRNO_UNKNOWN and let the remote endpoint deal with it.
 */
u_char
au_errno_to_bsm(int local_errno)
{
	const struct bsm_errno *bsme;

	bsme = bsm_lookup_errno_local(local_errno);
	if (bsme == NULL) {
		return BSM_ERRNO_UNKNOWN;
	}
	return bsme->be_bsm_errno;
}

static const struct bsm_errno *
bsm_lookup_errno_bsm(u_char bsm_errno)
{
	int i;

	for (i = 0; i < bsm_errnos_count; i++) {
		if (bsm_errnos[i].be_bsm_errno == bsm_errno) {
			return &bsm_errnos[i];
		}
	}
	return NULL;
}

/*
 * Converstion from a BSM error to a local error number may fail if either
 * OpenBSM doesn't recognize the error on the wire, or because there is no
 * appropriate local mapping.
 */
int
au_bsm_to_errno(u_char bsm_errno, int *errorp)
{
	const struct bsm_errno *bsme;

	bsme = bsm_lookup_errno_bsm(bsm_errno);
	if (bsme == NULL || bsme->be_local_errno == ERRNO_NO_LOCAL_MAPPING) {
		return -1;
	}
	*errorp = bsme->be_local_errno;
	return 0;
}

#if !defined(KERNEL) && !defined(_KERNEL)
const char *
au_strerror(u_char bsm_errno)
{
	const struct bsm_errno *bsme;

	bsme = bsm_lookup_errno_bsm(bsm_errno);
	if (bsme == NULL) {
		return "Unrecognized BSM error";
	}
	if (bsme->be_local_errno != ERRNO_NO_LOCAL_MAPPING) {
		return strerror(bsme->be_local_errno);
	}
	return bsme->be_strerror;
}
#endif
#endif /* CONFIG_AUDIT */
