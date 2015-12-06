/*
 * TODO: remove this file
 */
#ifndef _SYS_LCTX_H_
#define _SYS_LCTX_H_

#ifndef KERNEL
static __inline pid_t
getlcid(pid_t pid)
{
	errno = ENOSYS;
	return -1;
}

static __inline int
setlcid(pid_t pid, pid_t lcid)
{
	errno = ENOSYS;
	return -1;
}
#endif

#define LCID_PROC_SELF  (0)
#define LCID_REMOVE     (-1)
#define LCID_CREATE     (0)

#endif	/* !_SYS_LCTX_H_ */
