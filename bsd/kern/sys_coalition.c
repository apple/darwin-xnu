#include <kern/kern_types.h>
#include <mach/mach_types.h>
#include <mach/boolean.h>

#include <kern/coalition.h>

#include <sys/coalition.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

/* Coalitions syscalls */

/*
 * Create a new, empty coalition and return its ID.
 *
 * Returns:
 * EINVAL	Flags parameter was invalid
 * ENOMEM	Unable to allocate kernel resources for a new coalition
 * EFAULT	cidp parameter pointed to invalid memory.
 *
 * Returns with reference held for userspace caller.
 */
static
int
coalition_create_syscall(user_addr_t cidp, uint32_t flags)
{
	int error = 0;
	kern_return_t kr;
	uint64_t cid;
	coalition_t coal;

	if ((flags & (~COALITION_CREATE_FLAG_MASK)) != 0) {
		return EINVAL;
	}

	boolean_t privileged = flags & COALITION_CREATE_FLAG_PRIVILEGED;

	kr = coalition_create_internal(&coal, privileged);
	if (kr != KERN_SUCCESS) {
		/* for now, the only kr is KERN_RESOURCE_SHORTAGE */
		error = ENOMEM;
		goto out;
	}

	cid = coalition_id(coal);

#if COALITION_DEBUG
	printf("%s(addr, %u) -> %llu\n", __func__, flags, cid);
#endif
	error = copyout(&cid, cidp, sizeof(cid));
out:
	return error;
}

/*
 * Request to terminate the coalition identified by ID.
 * Attempts to spawn into this coalition using the posix_spawnattr will begin
 * failing. Processes already within the coalition may still fork.
 * Arms the 'coalition is empty' notification when the coalition's active
 * count reaches zero.
 *
 * Returns:
 * ESRCH	No coalition with that ID could be found.
 * EALREADY	The coalition with that ID has already been terminated.
 * EFAULT	cidp parameter pointed to invalid memory.
 * EPERM	Caller doesn't have permission to terminate that coalition.
 */
static
int
coalition_request_terminate_syscall(user_addr_t cidp, uint32_t flags)
{
	kern_return_t kr;
	int error = 0;
	uint64_t cid;
	coalition_t coal;

	if (flags != 0) {
		return EINVAL;
	}

	error = copyin(cidp, &cid, sizeof(cid));
	if (error) {
		return error;
	}

	coal = coalition_find_by_id(cid);
	if (coal == COALITION_NULL) {
		return ESRCH;
	}

	kr = coalition_request_terminate_internal(coal);
	coalition_release(coal);

	switch (kr) {
	case KERN_SUCCESS:
		break;
	case KERN_DEFAULT_SET:
		error = EPERM;
	case KERN_TERMINATED:
		error = EALREADY;
	case KERN_INVALID_NAME:
		error = ESRCH;
	default:
		error = EIO;
	}

#if COALITION_DEBUG
	printf("%s(%llu, %u) -> %d\n", __func__, cid, flags, error);
#endif

	return error;
}

/*
 * Request the kernel to deallocate the coalition identified by ID, which
 * must be both terminated and empty. This balances the reference taken
 * in coalition_create.
 * The memory containig the coalition object may not be freed just yet, if
 * other kernel operations still hold references to it.
 *
 * Returns:
 * EINVAL	Flags parameter was invalid
 * ESRCH	Coalition ID refers to a coalition that doesn't exist.
 * EBUSY	Coalition has not yet been terminated.
 * EBUSY	Coalition is still active.
 * EFAULT	cidp parameter pointed to invalid memory.
 * EPERM	Caller doesn't have permission to terminate that coalition.
 * Consumes one reference, "held" by caller since coalition_create
 */
static
int
coalition_reap_syscall(user_addr_t cidp, uint32_t flags)
{
	kern_return_t kr;
	int error = 0;
	uint64_t cid;
	coalition_t coal;

	if (flags != 0) {
		return EINVAL;
	}

	error = copyin(cidp, &cid, sizeof(cid));
	if (error) {
		return error;
	}

	coal = coalition_find_by_id(cid);
	if (coal == COALITION_NULL) {
		return ESRCH;
	}

	kr = coalition_reap_internal(coal);
	coalition_release(coal);

	switch (kr) {
	case KERN_SUCCESS:
		break;
	case KERN_DEFAULT_SET:
		error = EPERM;
	case KERN_TERMINATED:
		error = ESRCH;
	case KERN_FAILURE:
		error = EBUSY;
	default:
		error = EIO;
	}

#if COALITION_DEBUG
	printf("%s(%llu, %u) -> %d\n", __func__, cid, flags, error);
#endif

	return error;
}

/* Syscall demux.
 * Returns EPERM if the calling process is not privileged to make this call.
 */
int coalition(proc_t p, struct coalition_args *cap, __unused int32_t *retval)
{
	uint32_t operation = cap->operation;
	user_addr_t cidp = cap->cid;
	uint32_t flags = cap->flags;
	int error = 0;

	if (!task_is_in_privileged_coalition(p->task)) {
		return EPERM;
	}

	switch (operation) {
	case COALITION_OP_CREATE:
		error = coalition_create_syscall(cidp, flags);
		break;
	case COALITION_OP_REAP:
		error = coalition_reap_syscall(cidp, flags);
		break;
	case COALITION_OP_TERMINATE:
		error = coalition_request_terminate_syscall(cidp, flags);
		break;
	default:
		error = ENOSYS;
	}
	return error;
}

/* This is a temporary interface, likely to be changed by 15385642. */
static int __attribute__ ((noinline))
coalition_info_resource_usage(coalition_t coal, user_addr_t buffer, user_size_t bufsize)
{
	kern_return_t kr;
	struct coalition_resource_usage cru;

	if (bufsize != sizeof(cru)) {
		return EINVAL;
	}

	kr = coalition_resource_usage_internal(coal, &cru);

	switch (kr) {
	case KERN_INVALID_ARGUMENT:
		return EINVAL;
	case KERN_RESOURCE_SHORTAGE:
		return ENOMEM;
	case KERN_SUCCESS:
		break;
	default:
		return EIO; /* shrug */
	}

	return copyout(&cru, buffer, bufsize);
}

int coalition_info(proc_t p, struct coalition_info_args *uap, __unused int32_t *retval)
{
	user_addr_t cidp = uap->cid;
	user_addr_t buffer = uap->buffer;
	user_addr_t bufsizep = uap->bufsize;
	user_size_t bufsize;
	uint32_t flavor = uap->flavor;
	int error;
	uint64_t cid;
	coalition_t coal;

	error = copyin(cidp, &cid, sizeof(cid));
	if (error) {
		return error;
	}

	coal = coalition_find_by_id(cid);
	if (coal == COALITION_NULL) {
		return ESRCH;
	}
	/* TODO: priv check? EPERM or ESRCH? */

	if (IS_64BIT_PROCESS(p)) {
		user64_size_t size64;
		error = copyin(bufsizep, &size64, sizeof(size64));
		bufsize = (user_size_t)size64;
	} else {
		user32_size_t size32;
		error = copyin(bufsizep, &size32, sizeof(size32));
		bufsize = (user_size_t)size32;
	}
	if (error) {
		goto bad;
	}

	switch (flavor) {
	case COALITION_INFO_RESOURCE_USAGE:
		error = coalition_info_resource_usage(coal, buffer, bufsize);
		break;
	default:
		error = EINVAL;
	}

bad:
	coalition_release(coal);
	return error;
}
