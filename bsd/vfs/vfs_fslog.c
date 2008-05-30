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

#include <stdarg.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/buf.h>
#include <sys/time.h>
#include <sys/kauth.h>
#include <sys/mount.h>
#include <sys/vnode.h>
#include <sys/syslog.h>		/* for vaddlog() */
#include <sys/vnode_internal.h>
#include <dev/random/randomdev.h>

#include <sys/fslog.h>
#include <sys/mount_internal.h>

/* String to append as format modifier for each key-value pair */
#define FSLOG_KEYVAL_FMT	"[%s %s] " 
#define FSLOG_KEYVAL_FMT_LEN	(sizeof(FSLOG_KEYVAL_FMT) - 1)

#define FSLOG_NEWLINE_CHAR	"\n"
#define FSLOG_NEWLINE_CHAR_LEN	(sizeof(FSLOG_NEWLINE_CHAR) - 1)

/* Length of entire ASL message in 10 characters.  Kernel defaults to zero */
#define FSLOG_ASL_MSG_LEN	"         0"

/* Length of default format string to be used by printf */
#define MAX_FMT_LEN		256

/* Internal function to print input values as key-value pairs in format 
 * identifiable by Apple system log (ASL) facility.   All key-value pairs
 * are assumed to be pointer to strings and are provided using two ways - 
 * (a) va_list argument which is a list of varying number of arguments 
 *     created by the caller of this function.
 * (b) variable number of arguments passed to this function. 
 * 
 * Parameters -
 * 	level 	  - Priority level for this ASL message 
 *	facility  - Facility for this ASL message.
 *	num_pairs - Number of key-value pairs provided by vargs argument.
 *	vargs 	  - List of key-value pairs.  
 *	... 	  - Additional key-value pairs (apart from vargs) as variable 
 *	      	    argument list.  A NULL value indicates the end of the 
 *	      	    variable argument list.
 * 
 * Returns - 
 *	zero	- On success, when it prints all key-values pairs provided.
 *	E2BIG	- When it cannot print all key-value pairs provided and had
 *		  to truncate the output.
 */
static int fslog_asl_msg(int level, const char *facility, int num_pairs, va_list vargs, ...)
{
	int err = 0;
	char fmt[MAX_FMT_LEN];	/* Format string to use with vaddlog */
	int calc_pairs = 0;
	size_t len;
	int i;
	va_list ap;
	char *ptr;

	/* Mask extra bits, if any, from priority level */
	level = LOG_PRI(level);

	/* Create the first part of format string consisting of ASL 
	 * message length, level, and facility.
	 */
	if (facility) {
		snprintf(fmt, MAX_FMT_LEN, "%s [%s %d] [%s %d] [%s %s] ",
			FSLOG_ASL_MSG_LEN,
			FSLOG_KEY_LEVEL, level,
			FSLOG_KEY_READ_UID, FSLOG_VAL_READ_UID, 
			FSLOG_KEY_FACILITY, facility);
	} else {
		snprintf(fmt, MAX_FMT_LEN, "%s [%s %d] [%s %d] ", 
			FSLOG_ASL_MSG_LEN,
			FSLOG_KEY_LEVEL, level,
			FSLOG_KEY_READ_UID, FSLOG_VAL_READ_UID);
	}

	/* Determine the number of key-value format string [%s %s] that 
	 * should be added in format string for every key-value pair provided
	 * in va_list.  Calculate maximum number of format string that can be 
	 * accommodated in the remaining format buffer (after saving space
	 * for newline character).  If the caller provided pairs in va_list 
	 * is more than calculated pairs, truncate extra pairs.
	 */
	len = MAX_FMT_LEN - strlen(fmt) - FSLOG_NEWLINE_CHAR_LEN - 1;
	calc_pairs = len / FSLOG_KEYVAL_FMT_LEN;
	if (num_pairs <= calc_pairs) {
		calc_pairs = num_pairs;
	} else {
		err = E2BIG;
	}

	/* Append format strings [%s %s] for the key-value pairs in vargs */
	len = MAX_FMT_LEN - FSLOG_NEWLINE_CHAR_LEN;
	for (i = 0; i < calc_pairs; i++) {
		(void) strlcat(fmt, FSLOG_KEYVAL_FMT, len);
	}

	/* Count number of variable arguments provided to this function 
	 * and determine total number of key-value pairs.
	 */
	calc_pairs = 0;
	va_start(ap, vargs);
	ptr = va_arg(ap, char *);
	while (ptr) {
		calc_pairs++;
		ptr = va_arg(ap, char *);
	}
	calc_pairs /= 2;
	va_end(ap);

	/* If user provided variable number of arguments, append them as
	 * as real key-value "[k v]" into the format string.  If the format 
	 * string is too small, ignore the key-value pair completely.
	 */
	if (calc_pairs) {
		char *key, *val;
		size_t pairlen;
		int offset;

		/* Calculate bytes available for key-value pairs after reserving 
		 * bytes for newline character and NULL terminator
		 */
		len = MAX_FMT_LEN - strlen(fmt) - FSLOG_NEWLINE_CHAR_LEN - 1;
		offset = strlen(fmt);

		va_start(ap, vargs);
		for (i = 0; i < calc_pairs; i++) {
			key = va_arg(ap, char *);
			val = va_arg(ap, char *);

			/* Calculate bytes required to store next key-value pair as
			 * "[key val] " including space for '[', ']', and two spaces.
			 */
			pairlen = strlen(key) + strlen(val) + 4;
			if (pairlen > len) {
				err = E2BIG;
				break;
			} 

			/* len + 1 because one byte has been set aside for NULL 
			 * terminator in calculation of 'len' above
			 */
			snprintf((fmt + offset), len + 1, FSLOG_KEYVAL_FMT, key, val);
			offset += pairlen;
			len -= pairlen;
		}
		va_end(ap);
	}

	/* Append newline */
	(void) strlcat(fmt, FSLOG_NEWLINE_CHAR, MAX_FMT_LEN);

	/* Print the key-value pairs in ASL format */
	vaddlog(fmt, vargs);

	return err;
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
		(void) fslog_asl_msg(FSLOG_VAL_LEVEL, FSLOG_VAL_FACILITY, 
				num_pairs, ap, NULL);
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
		(void) fslog_asl_msg(FSLOG_VAL_LEVEL, FSLOG_VAL_FACILITY, 
			 num_pairs, ap, 
			 FSLOG_KEY_MSG_ID, msg_id_str, 
			 FSLOG_KEY_MSG_ORDER, msg_order_ptr, NULL);
	}
	va_end(ap);
	return msg_id;
}

/* Search if given string contains '[' and ']'.  If any, escape it by 
 * prefixing with a '\'.  If the length of the string is not big enough, 
 * no changes are done and error is returned.
 *
 * Parameters -
 * 	str - string that can contain '[' or ']', should be NULL terminated
 *	len - length, in bytes, of valid data, including NULL character.
 *	buflen - size of buffer that contains the string
 */
static int escape_str(char *str, int len, int buflen)
{
	int count;
	char *src, *dst;

	/* Count number of characters to escape */
	src = str;
	count = 0;
	do {
		if ((*src == '[') || (*src == ']')) {
			count++;
		}
	} while (*src++);

	if (count) {
		/* Check if the buffer has enough space to escape all characters */
		if ((buflen - len) < count) {
			return ENOSPC;	
		}

		src = str + len;
		dst = src + count;
		while (count) {
			*dst-- = *src;
			if ((*src == '[') || (*src == ']')) {
				/* Last char copied needs to be escaped */
				*dst-- = '\\';
				count--;
			}
			src--;
		}
	}

	return 0;
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
		if (mnt->mnt_vfsstat.f_mntonname != NULL) {
			fslog_err(FSLOG_MSG_SINGLE,
				  FSLOG_KEY_ERR_TYPE, FSLOG_VAL_ERR_TYPE_FS,
				  FSLOG_KEY_MNTPT, mnt->mnt_vfsstat.f_mntonname,
				  NULL);
		}
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
