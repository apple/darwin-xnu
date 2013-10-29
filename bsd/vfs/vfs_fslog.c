/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/buf.h>
#include <sys/time.h>
#include <sys/kauth.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/syslog.h>
#include <sys/vnode_internal.h>
#include <sys/fslog.h>
#include <sys/mount_internal.h>
#include <sys/kasl.h>

#include <dev/random/randomdev.h>

#include <uuid/uuid.h>

#include <stdarg.h>

/* Log information about external modification of a process,
 * using MessageTracer formatting. Assumes that both the caller
 * and target are appropriately locked.
 * Currently prints following information - 
 * 	1. Caller process name (truncated to 16 characters)
 *	2. Caller process Mach-O UUID
 *  3. Target process name (truncated to 16 characters)
 *  4. Target process Mach-O UUID
 */
void
fslog_extmod_msgtracer(proc_t caller, proc_t target)
{
	if ((caller != PROC_NULL) && (target != PROC_NULL)) {

		/*
		 * Print into buffer large enough for "ThisIsAnApplicat(BC223DD7-B314-42E0-B6B0-C5D2E6638337)",
		 * including space for escaping, and NUL byte included in sizeof(uuid_string_t).
		 */

		uuid_string_t uuidstr;
		char c_name[2*MAXCOMLEN + 2 /* () */ + sizeof(uuid_string_t)];
		char t_name[2*MAXCOMLEN + 2 /* () */ + sizeof(uuid_string_t)];

		strlcpy(c_name, caller->p_comm, sizeof(c_name));
		uuid_unparse_upper(caller->p_uuid, uuidstr);
		strlcat(c_name, "(", sizeof(c_name));
		strlcat(c_name, uuidstr, sizeof(c_name));
		strlcat(c_name, ")", sizeof(c_name));
		if (0 != escape_str(c_name, strlen(c_name), sizeof(c_name))) {
			return;
		}

		strlcpy(t_name, target->p_comm, sizeof(t_name));
		uuid_unparse_upper(target->p_uuid, uuidstr);
		strlcat(t_name, "(", sizeof(t_name));
		strlcat(t_name, uuidstr, sizeof(t_name));
		strlcat(t_name, ")", sizeof(t_name));
		if (0 != escape_str(t_name, strlen(t_name), sizeof(t_name))) {
			return;
		}
#if DEBUG
		printf("EXTMOD: %s(%d) -> %s(%d)\n",
			   c_name,
			   proc_pid(caller),
			   t_name,
			   proc_pid(target));
#endif

		kern_asl_msg(LOG_DEBUG, "messagetracer",
							5,
							"com.apple.message.domain", "com.apple.kernel.external_modification", /* 0 */
							"com.apple.message.signature", c_name, /* 1 */
							"com.apple.message.signature2", t_name, /* 2 */
							"com.apple.message.result", "noop", /* 3 */
							"com.apple.message.summarize", "YES", /* 4 */
							NULL);
	}
}

/* Log file system related error in key-value format identified by Apple 
 * system log (ASL) facility.  The key-value pairs are string pointers 
 * (char *) and are provided as variable arguments list.  A NULL value 
 * indicates end of the list.
 *
 * Keys can not contain '[', ']', space, and newline.  Values can not 
 * contain '[', ']', and newline.  If any key-value contains any of the 
 * reserved characters, the behavior is undefined.  The caller of the 
 * function should escape any occurrences of '[' and ']' by prefixing
 * it with '\'.
 * 
 * The function takes a message ID which can be used to logically group
 * different ASL messages.  Messages in same logical group have same message
 * ID and have information to describe order of the message --- first, 
 * middle, or last.
 *
 * The following message IDs have special meaning - 
 * FSLOG_MSG_FIRST - This message is the first message in its logical
 *	group.  This generates a unique message ID, creates two key-value 
 *	pairs with message ID and order of the message as "First".
 * FSLOG_MSG_LAST - This is really a MASK which should be logically OR'ed 
 *	with message ID to indicate the last message for a logical group.  
 *	This also creates two key-value pairs with message ID and order of 
 *	message as "Last".
 * FSLOG_MSG_SINGLE - This signifies that the message is the only message
 * 	in its logical group.  Therefore no extra key-values are generated 
 *	for this option.
 * For all other values of message IDs, it regards them as intermediate 
 * message and generates two key-value pairs with message ID and order of
 * message as "Middle".
 * 
 * Returns - 
 *	Message ID of the ASL message printed.  The caller should use
 * 	this value to print intermediate messages or end the logical message
 *	group.
 *	For FSLOG_MSG_SINGLE option, it returns FSLOG_MSG_SINGLE. 
 */
unsigned long fslog_err(unsigned long msg_id, ... )
{
	va_list ap;
	int num_pairs;
	char msg_id_str[21]; /* To convert 64-bit number to string with NULL char */
	char *arg;
	const char *msg_order_ptr;

	/* Count number of arguments and key-value pairs provided by user */
	num_pairs = 0;
	va_start(ap, msg_id);
	arg = va_arg(ap, char *);
	while (arg) {
		num_pairs++;
		arg = va_arg(ap, char *);
	}
	num_pairs /= 2;
	va_end(ap);

	va_start(ap, msg_id);
	if (msg_id == FSLOG_MSG_SINGLE) {
		/* Single message, do not print message ID and message order */
		(void) kern_asl_msg_va(FSLOG_VAL_LEVEL, FSLOG_VAL_FACILITY, 
		    num_pairs, ap,
		    FSLOG_KEY_READ_UID, FSLOG_VAL_READ_UID,
		    NULL);
	} else {
		if (msg_id == FSLOG_MSG_FIRST) {
			/* First message, generate random message ID */
			while ((msg_id == FSLOG_MSG_FIRST) ||
			       (msg_id == FSLOG_MSG_LAST) ||
			       (msg_id == FSLOG_MSG_SINGLE)) {
				msg_id = RandomULong();
				/* MSB is reserved for indicating last message 
				 * in sequence.  Clear the MSB while generating
				 * new message ID.
				 */
				msg_id = msg_id >> 1;
			}
			msg_order_ptr = FSLOG_VAL_ORDER_FIRST;
		} else if (msg_id & FSLOG_MSG_LAST) { 
			/* MSB set to indicate last message for this ID */
			msg_order_ptr = FSLOG_VAL_ORDER_LAST;
			/* MSB of message ID is set to indicate last message
			 * in sequence.  Clear the bit to get real message ID.
			 */
			msg_id = msg_id & ~FSLOG_MSG_LAST;
		} else {
			/* Intermediate message for this ID */
			msg_order_ptr = FSLOG_VAL_ORDER_MIDDLE;
		}

		snprintf(msg_id_str, sizeof(msg_id_str), "%lu", msg_id);
		(void) kern_asl_msg_va(FSLOG_VAL_LEVEL, FSLOG_VAL_FACILITY, 
		    num_pairs, ap,
		    FSLOG_KEY_READ_UID, FSLOG_VAL_READ_UID,
		    FSLOG_KEY_MSG_ID, msg_id_str, 
		    FSLOG_KEY_MSG_ORDER, msg_order_ptr, NULL);
	}
	va_end(ap);
	return msg_id;
}

/* Log information about runtime file system corruption detected by
 * the file system.  It takes the VFS mount structure as 
 * parameter which is used to access the mount point of the 
 * corrupt volume.  If no mount structure or mount point string 
 * string exists, nothing is logged to ASL database.
 * 
 * Currently prints following information - 
 * 	1. Mount Point
 */
void fslog_fs_corrupt(struct mount *mnt)
{
	if (mnt != NULL) {
		fslog_err(FSLOG_MSG_SINGLE,
			  FSLOG_KEY_ERR_TYPE, FSLOG_VAL_ERR_TYPE_FS,
			  FSLOG_KEY_MNTPT, mnt->mnt_vfsstat.f_mntonname,
			  NULL);
	}
		
	return;
} 

/* Log information about IO error detected in buf_biodone()
 * Currently prints following information - 
 * 	1. Physical block number
 *	2. Logical block number
 *	3. Device node 
 *	4. Mount point
 *	5. Path for file, if any
 *	6. Error number
 *	7. Type of IO (read/write)
 */
void fslog_io_error(const buf_t bp)
{
	int err;
	unsigned long msg_id;
	char blknum_str[21];
	char lblknum_str[21];
	char errno_str[6];
	const char *iotype;
	unsigned char print_last = 0;
	vnode_t	vp;

	if (buf_error(bp) == 0) {
		return;
	}

	/* Convert error number to string */
	snprintf (errno_str, sizeof(errno_str), "%d", buf_error(bp));

	/* Determine type of IO operation */
	if (buf_flags(bp) & B_READ) {
		iotype = FSLOG_VAL_IOTYPE_READ;
	} else {
		iotype = FSLOG_VAL_IOTYPE_WRITE;
	}

	/* Convert physical block number to string */
	snprintf (blknum_str, sizeof(blknum_str), "%lld", buf_blkno(bp));

	/* Convert logical block number to string */
	snprintf (lblknum_str, sizeof(lblknum_str), "%lld", buf_lblkno(bp));

	msg_id = fslog_err(FSLOG_MSG_FIRST,
				FSLOG_KEY_ERR_TYPE, FSLOG_VAL_ERR_TYPE_IO,
				FSLOG_KEY_ERRNO, errno_str,
				FSLOG_KEY_IOTYPE, iotype,
				FSLOG_KEY_PHYS_BLKNUM, blknum_str,
				FSLOG_KEY_LOG_BLKNUM, lblknum_str,
				NULL);
	
	/* Access the vnode for this buffer */
	vp = buf_vnode(bp);
	if (vp) {
		struct vfsstatfs *sp;
		mount_t	mp;
		char *path;
		int len;
		struct vfs_context context;

		mp = vnode_mount(vp);
		/* mp should be NULL only for bdevvp during boot */
		if (mp == NULL) {
			goto out;
		}
		sp = vfs_statfs(mp);

		/* Access the file path */
		MALLOC(path, char *, MAXPATHLEN, M_TEMP, M_WAITOK);
		if (path) {
			len = MAXPATHLEN;
			context.vc_thread = current_thread();
			context.vc_ucred = kauth_cred_get();
			/* Find path without entering file system */
			err = build_path(vp, path, len, &len, BUILDPATH_NO_FS_ENTER,
					 &context);	
			if (!err) {
				err = escape_str(path, len, MAXPATHLEN);
				if (!err) {
					/* Print device node, mount point, path */
					msg_id = fslog_err(msg_id | FSLOG_MSG_LAST, 
						FSLOG_KEY_DEVNODE, sp->f_mntfromname,
						FSLOG_KEY_MNTPT, sp->f_mntonname, 
						FSLOG_KEY_PATH, path, 
						NULL);
					print_last = 1;
				}
			}
			FREE(path, M_TEMP);
		} 

		if (print_last == 0) {
			/* Print device node and mount point */
			msg_id = fslog_err(msg_id | FSLOG_MSG_LAST, 
					FSLOG_KEY_DEVNODE, sp->f_mntfromname,
					FSLOG_KEY_MNTPT, sp->f_mntonname, 
					NULL);
			print_last = 1;
		} 
	}

out:
	if (print_last == 0) {
		msg_id = fslog_err(msg_id | FSLOG_MSG_LAST, NULL);
	}

	return;
}

