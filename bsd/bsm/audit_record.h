/*
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2004 Apple Computer, Inc.  All Rights Reserved.
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

#ifndef _BSM_AUDIT_RECORD_H_
#define _BSM_AUDIT_RECORD_H_

#include <sys/cdefs.h>
#include <sys/vnode.h>
#include <sys/ipc.h>
#include <sys/un.h>
#include <sys/event.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

/* We could determined the header and trailer sizes by
 * defining appropriate structures. We hold off that approach
 * till we have a consistant way of using structures for all tokens.
 * This is not straightforward since these token structures may
 * contain pointers of whose contents we dont know the size
 * (e.g text tokens)
 */
#define HEADER_SIZE     18
#define TRAILER_SIZE    7
        
#define ADD_U_CHAR(loc, val) \
        do {\
		*loc = val;\
                loc += sizeof(u_char);\
        }while(0)
    

#define ADD_U_INT16(loc, val) \
        do { \
		memcpy(loc, (u_char *)&val, sizeof(u_int16_t));\
                loc += sizeof(u_int16_t); \
        }while(0)

#define ADD_U_INT32(loc, val) \
        do { \
		memcpy(loc, (u_char *)&val, sizeof(u_int32_t));\
                loc += sizeof(u_int32_t); \
        }while(0)

#define ADD_U_INT64(loc, val)\
        do {\
		memcpy(loc, (u_char *)&val, sizeof(u_int64_t));\
                loc += sizeof(u_int64_t); \
        }while(0)

#define ADD_MEM(loc, data, size) \
        do { \
                memcpy(loc, data, size);\
                loc += size;\
        }while(0)

#define ADD_STRING(loc, data, size) ADD_MEM(loc, data, size)


/* Various token id types */

/* 
 * Values inside the comments are not documented in the BSM pages and
 * have been picked up from the header files 
 */  

/*
 * Values marked as XXX do not have a value defined in the BSM header files 
 */   

/*
 * Control token types

#define AUT_OTHER_FILE              ((char)0x11)
#define AUT_OTHER_FILE32            AUT_OTHER_FILE
#define AUT_OHEADER                 ((char)0x12)

 */

#define AUT_INVALID                 0x00
#define AU_FILE_TOKEN               0x11
#define AU_TRAILER_TOKEN            0x13 
#define AU_HEADER_32_TOKEN          0x14	
#define AU_HEADER_EX_32_TOKEN       0x15

/*
 * Data token types
#define AUT_SERVER              ((char)0x25)
#define AUT_SERVER32            AUT_SERVER
 */

#define AU_DATA_TOKEN               0x21
#define AU_ARB_TOKEN                AU_DATA_TOKEN	
#define AU_IPC_TOKEN                0x22
#define AU_PATH_TOKEN               0x23
#define AU_SUBJECT_32_TOKEN         0x24
#define AU_PROCESS_32_TOKEN         0x26
#define AU_RETURN_32_TOKEN          0x27
#define AU_TEXT_TOKEN               0x28
#define AU_OPAQUE_TOKEN             0x29
#define AU_IN_ADDR_TOKEN            0x2A
#define AU_IP_TOKEN                 0x2B
#define AU_IPORT_TOKEN              0x2C
#define AU_ARG32_TOKEN              0x2D	
#define AU_SOCK_TOKEN               0x2E
#define AU_SEQ_TOKEN                0x2F

/*
 * Modifier token types

#define AUT_ACL                 ((char)0x30)
#define AUT_LABEL               ((char)0x33)
#define AUT_GROUPS              ((char)0x34)
#define AUT_ILABEL              ((char)0x35)
#define AUT_SLABEL              ((char)0x36)
#define AUT_CLEAR               ((char)0x37)
#define AUT_PRIV                ((char)0x38)
#define AUT_UPRIV               ((char)0x39)
#define AUT_LIAISON             ((char)0x3A)
 
 */

#define AU_ATTR_TOKEN               0x31
#define AU_IPCPERM_TOKEN            0x32
#define AU_NEWGROUPS_TOKEN          0x3B
#define AU_EXEC_ARG_TOKEN           0x3C
#define AU_EXEC_ENV_TOKEN           0x3D
#define AU_ATTR32_TOKEN             0x3E

/*
 * Command token types
 */
 
#define AU_CMD_TOKEN                0x51
#define AU_EXIT_TOKEN               0x52

/*
 * Miscellaneous token types

#define AUT_HOST                ((char)0x70)

 */

/*
 * 64bit token types

#define AUT_SERVER64            ((char)0x76)
#define AUT_OTHER_FILE64		((char)0x78)

 */

#define AU_ARG64_TOKEN              0x71
#define AU_RETURN_64_TOKEN          0x72
#define AU_ATTR64_TOKEN             0x73
#define AU_HEADER_64_TOKEN          0x74
#define AU_SUBJECT_64_TOKEN         0x75
#define AU_PROCESS_64_TOKEN         0x77

/*
 * Extended network address token types
 */
 
#define AU_HEADER_EX_64_TOKEN       0x79
#define AU_SUBJECT_32_EX_TOKEN      0x7a	
#define AU_PROCESS_32_EX_TOKEN      0x7b
#define AU_SUBJECT_64_EX_TOKEN      0x7c
#define AU_PROCESS_64_EX_TOKEN      0x7d
#define AU_IN_ADDR_EX_TOKEN	    0x7e
#define AU_SOCK_EX32_TOKEN          0x7f
#define AU_SOCK_EX128_TOKEN         AUT_INVALID         /*XXX*/
#define AU_IP_EX_TOKEN              AUT_INVALID         /*XXX*/

/*
 * The values for the following token ids are not
 * defined by BSM
 */
#define AU_SOCK_INET_32_TOKEN       0x80         /*XXX*/ 
#define AU_SOCK_INET_128_TOKEN      0x81         /*XXX*/
#define AU_SOCK_UNIX_TOKEN          0x82         /*XXX*/

/* print values for the arbitrary token */
#define AUP_BINARY      0
#define AUP_OCTAL       1
#define AUP_DECIMAL     2
#define AUP_HEX         3
#define AUP_STRING      4

/* data-types for the arbitrary token */
#define AUR_BYTE        0
#define AUR_SHORT       1
#define AUR_LONG        2

/* ... and their sizes */
#define AUR_BYTE_SIZE       sizeof(u_char)	
#define AUR_SHORT_SIZE      sizeof(u_int16_t)
#define AUR_LONG_SIZE       sizeof(u_int32_t)

/* Modifiers for the header token */
#define PAD_NOTATTR  0x4000   /* nonattributable event */
#define PAD_FAILURE  0x8000   /* fail audit event */


#define MAX_GROUPS          16
#define HEADER_VERSION      1
#define TRAILER_PAD_MAGIC   0xB105

/* BSM library calls */

__BEGIN_DECLS

int			au_open(void);
int			au_write(int d, token_t *m);
int			au_close(int d, int keep, short event);
token_t			*au_to_file(char *file);
token_t			*au_to_header(int rec_size, au_event_t e_type, 
					au_emod_t e_mod);
token_t			*au_to_header32(int rec_size, au_event_t e_type, 
					au_emod_t e_mod);
token_t			*au_to_header64(int rec_size, au_event_t e_type, 
					au_emod_t e_mod);
token_t			*au_to_me(void);
                               
token_t			*au_to_arg(char n, char *text, u_int32_t v);
token_t			*au_to_arg32(char n, char *text, u_int32_t v);
token_t			*au_to_arg64(char n, char *text, u_int64_t v);
token_t			*au_to_attr(struct vattr *attr);
token_t			*au_to_attr32(struct vattr *attr);
token_t			*au_to_attr64(struct vattr *attr);
token_t			*au_to_data(char unit_print, char unit_type,
				char unit_count, char *p);
token_t			*au_to_exit(int retval, int err);
token_t			*au_to_groups(int *groups);
token_t			*au_to_newgroups(u_int16_t n, gid_t *groups);
token_t			*au_to_in_addr(struct in_addr *internet_addr);
token_t			*au_to_in_addr_ex(struct in6_addr *internet_addr);
token_t			*au_to_ip(struct ip *ip);
token_t			*au_to_ipc(char type, int id);
token_t			*au_to_ipc_perm(struct ipc_perm *perm);
token_t			*au_to_iport(u_int16_t iport);
token_t			*au_to_opaque(char *data, u_int16_t bytes);
token_t			*au_to_path(char *path);
token_t			*au_to_process(au_id_t auid, uid_t euid, gid_t egid,
				uid_t ruid, gid_t rgid, pid_t pid,
				au_asid_t sid, au_tid_t *tid);
token_t			*au_to_process32(au_id_t auid, uid_t euid, gid_t egid,
				uid_t ruid, gid_t rgid, pid_t pid,
				au_asid_t sid, au_tid_t *tid);
token_t			*au_to_process64(au_id_t auid, uid_t euid, gid_t egid,
				uid_t ruid, gid_t rgid, pid_t pid,
				au_asid_t sid, au_tid_t *tid);
token_t			*au_to_process_ex(au_id_t auid, uid_t euid,
				gid_t egid, uid_t ruid, gid_t rgid, pid_t pid,
				au_asid_t sid, au_tid_addr_t *tid);
token_t			*au_to_process32_ex(au_id_t auid, uid_t euid,
				gid_t egid, uid_t ruid, gid_t rgid, pid_t pid,
				au_asid_t sid, au_tid_addr_t *tid);
token_t			*au_to_process64_ex(au_id_t auid, uid_t euid,
				gid_t egid, uid_t ruid, gid_t rgid, pid_t pid,
				au_asid_t sid, au_tid_addr_t *tid);
token_t			*au_to_return(char status, u_int32_t ret);
token_t			*au_to_return32(char status, u_int32_t ret);
token_t			*au_to_return64(char status, u_int64_t ret);
token_t			*au_to_seq(long audit_count);
token_t			*au_to_socket(struct socket *so);
token_t			*au_to_socket_ex_32(u_int16_t lp, u_int16_t rp, 
				struct sockaddr *la, struct sockaddr *ta);
token_t			*au_to_socket_ex_128(u_int16_t lp, u_int16_t rp, 
				struct sockaddr *la, struct sockaddr *ta);
token_t			*au_to_sock_inet(struct sockaddr_in *so);
token_t			*au_to_sock_inet32(struct sockaddr_in *so);
token_t			*au_to_sock_inet128(struct sockaddr_in6 *so);
token_t			*au_to_sock_unix(struct sockaddr_un *so);
token_t			*au_to_subject(au_id_t auid, uid_t euid, gid_t egid,
				uid_t ruid, gid_t rgid, pid_t pid,
				au_asid_t sid, au_tid_t *tid);
token_t			*au_to_subject32(au_id_t auid, uid_t euid, gid_t egid,
				uid_t ruid, gid_t rgid, pid_t pid,
				au_asid_t sid, au_tid_t *tid);
token_t			*au_to_subject64(au_id_t auid, uid_t euid, gid_t egid,
				uid_t ruid, gid_t rgid, pid_t pid,
				au_asid_t sid, au_tid_t *tid);
token_t			*au_to_subject_ex(au_id_t auid, uid_t euid,
				gid_t egid, uid_t ruid, gid_t rgid, pid_t pid,
				au_asid_t sid, au_tid_addr_t *tid);
token_t			*au_to_subject32_ex(au_id_t auid, uid_t euid,
				gid_t egid, uid_t ruid, gid_t rgid, pid_t pid,
				au_asid_t sid, au_tid_addr_t *tid);
token_t			*au_to_subject64_ex(au_id_t auid, uid_t euid,
				gid_t egid, uid_t ruid, gid_t rgid, pid_t pid,
				au_asid_t sid, au_tid_addr_t *tid);
token_t			*au_to_exec_args(const char **);
token_t			*au_to_exec_env(const char **);
token_t			*au_to_text(char *text);
token_t			*au_to_kevent(struct kevent *kev);
token_t			*au_to_trailer(int rec_size);

__END_DECLS

#endif /* ! _BSM_AUDIT_RECORD_H_ */
