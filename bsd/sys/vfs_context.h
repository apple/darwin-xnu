#ifndef _BSD_SYS_VFS_CONTEXT_H_
#define _BSD_SYS_VFS_CONTEXT_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/kernel_types.h>
#include <stdint.h>

struct vfs_context {
	proc_t   vc_proc;
	ucred_t  vc_ucred;
};

#endif /* !_BSD_SYS_VFS_CONTEXT_H_ */
