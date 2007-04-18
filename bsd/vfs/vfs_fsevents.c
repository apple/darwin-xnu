/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/file_internal.h>
#include <sys/stat.h>
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/attr.h>
#include <sys/sysctl.h>
#include <sys/ubc.h>
#include <machine/cons.h>
#include <miscfs/specfs/specdev.h>
#include <miscfs/devfs/devfs.h>
#include <sys/filio.h>
#include <architecture/byte_order.h>
#include <kern/locks.h>
#include <libkern/OSAtomic.h>

#include <bsm/audit_kernel.h>
#include <bsm/audit_kevents.h>

// where all our structs and defines come from
#include <sys/fsevents.h>


typedef struct kfs_event_arg {
    u_int16_t  type;
    u_int16_t  len;
    union {
	struct vnode *vp;
	char         *str;
	void         *ptr;
	int32_t       int32;
	dev_t         dev;
	ino_t         ino;
	int32_t       mode;
	uid_t         uid;
	gid_t         gid;
    } data;
}kfs_event_arg;

#define KFS_NUM_ARGS  FSE_MAX_ARGS
typedef struct kfs_event {
    int32_t        type;          // type code of this event
    u_int32_t      refcount;      // number of clients referencing this
    pid_t          pid;           // pid of the process that did the op
    kfs_event_arg  args[KFS_NUM_ARGS];
} kfs_event;


typedef struct fs_event_watcher {
    SLIST_ENTRY(fs_event_watcher) link;
    int8_t      *event_list;             // the events we're interested in
    int32_t      num_events;
    dev_t       *devices_to_watch;       // only report events from these devices
    uint32_t     num_devices;
    int32_t      flags;
    kfs_event  **event_queue;
    int32_t      eventq_size;            // number of event pointers in queue
    int32_t      rd, wr;                 // indices to the event_queue
    int32_t      blockers;
} fs_event_watcher;

// fs_event_watcher flags
#define WATCHER_DROPPED_EVENTS  0x0001
#define WATCHER_CLOSING         0x0002

static SLIST_HEAD(watch_list, fs_event_watcher) watch_list_head = { NULL };


#define MAX_KFS_EVENTS   2048

// this array holds each pending event 
static kfs_event  fs_event_buf[MAX_KFS_EVENTS];
static int        free_event_idx = 0;
static int        fs_event_init = 0;

//
// this array records whether anyone is interested in a
// particular type of event.  if no one is, we bail out
// early from the event delivery
//
static int16_t     fs_event_type_watchers[FSE_MAX_EVENTS];

static int  watcher_add_event(fs_event_watcher *watcher, kfs_event *kfse);

//
// Locks
//
static lck_grp_attr_t *  fsevent_group_attr;
static lck_attr_t *      fsevent_lock_attr;
static lck_grp_t *       fsevent_mutex_group;

static lck_grp_t *       fsevent_rw_group;

static lck_rw_t  fsevent_big_lock;    // always grab this first
static lck_mtx_t watch_list_lock;
static lck_mtx_t event_buf_lock;


static void init_pathbuff(void);


static void
fsevents_internal_init(void)
{
    int i;
    
    if (fs_event_init++ != 0) {
	return;
    }

    for(i=0; i < FSE_MAX_EVENTS; i++) {
	fs_event_type_watchers[i] = 0;
    }

    for(i=0; i < MAX_KFS_EVENTS; i++) {
	fs_event_buf[i].type      = FSE_INVALID;
	fs_event_buf[i].refcount  = 0;
    }

    SLIST_INIT(&watch_list_head);

    fsevent_lock_attr    = lck_attr_alloc_init();
    fsevent_group_attr   = lck_grp_attr_alloc_init();
    fsevent_mutex_group  = lck_grp_alloc_init("fsevent-mutex", fsevent_group_attr);
    fsevent_rw_group     = lck_grp_alloc_init("fsevent-rw", fsevent_group_attr);

    lck_mtx_init(&watch_list_lock, fsevent_mutex_group, fsevent_lock_attr);
    lck_mtx_init(&event_buf_lock, fsevent_mutex_group, fsevent_lock_attr);

    lck_rw_init(&fsevent_big_lock, fsevent_rw_group, fsevent_lock_attr);

    init_pathbuff();
}

static void
lock_watch_list(void)
{
    lck_mtx_lock(&watch_list_lock);
}

static void
unlock_watch_list(void)
{
    lck_mtx_unlock(&watch_list_lock);
}

static void
lock_fs_event_buf(void)
{
    lck_mtx_lock(&event_buf_lock);
}

static void
unlock_fs_event_buf(void)
{
    lck_mtx_unlock(&event_buf_lock);
}

// forward prototype
static void do_free_event(kfs_event *kfse);

static int
watcher_cares_about_dev(fs_event_watcher *watcher, dev_t dev)
{
    unsigned int i;
    
    // if there is not list of devices to watch, then always
    // say we're interested so we'll report all events from
    // all devices
    if (watcher->devices_to_watch == NULL) {
	return 1;
    }

    for(i=0; i < watcher->num_devices; i++) {
	if (dev == watcher->devices_to_watch[i]) {
	    // found a match! that means we want events
	    // from this device.
	    return 1;
	}
    }

    // if we're here it's not in the devices_to_watch[] 
    // list so that means we do not care about it
    return 0;
}


int
need_fsevent(int type, vnode_t vp)
{
        fs_event_watcher *watcher;
        dev_t dev;

	if (fs_event_type_watchers[type] == 0)
	        return (0);
	dev = (dev_t)(vp->v_mount->mnt_vfsstat.f_fsid.val[0]);

	lock_watch_list();
    
	SLIST_FOREACH(watcher, &watch_list_head, link) {
	        if (watcher->event_list[type] == FSE_REPORT && watcher_cares_about_dev(watcher, dev)) {
		        unlock_watch_list();
		        return (1);
		}
	}
	unlock_watch_list();
    
	return (0);
}


int
add_fsevent(int type, vfs_context_t ctx, ...) 
{
    struct proc	     *p = vfs_context_proc(ctx);
    int               i, arg_idx, num_deliveries=0;
    kfs_event_arg    *kea;
    kfs_event        *kfse;
    fs_event_watcher *watcher;
    va_list           ap;
    int 	      error = 0;
    dev_t             dev = 0;

    va_start(ap, ctx);

    // if no one cares about this type of event, bail out
    if (fs_event_type_watchers[type] == 0) {
	va_end(ap);
	return 0;
    }

    lck_rw_lock_shared(&fsevent_big_lock);

    // find a free event and snag it for our use
    // NOTE: do not do anything that would block until
    //       the lock is dropped.
    lock_fs_event_buf();
    
    for(i=0; i < MAX_KFS_EVENTS; i++) {
	if (fs_event_buf[(free_event_idx + i) % MAX_KFS_EVENTS].type == FSE_INVALID) {
	    break;
	}
    }

    if (i >= MAX_KFS_EVENTS) {
	// yikes! no free slots
	unlock_fs_event_buf();
	va_end(ap);

	lock_watch_list();
	SLIST_FOREACH(watcher, &watch_list_head, link) {
	    watcher->flags |= WATCHER_DROPPED_EVENTS;
	    wakeup((caddr_t)watcher);
	}
	unlock_watch_list();
	lck_rw_done(&fsevent_big_lock);

	printf("fs_events: add_event: event queue is full! dropping events.\n");
	return ENOSPC;
    }

    kfse = &fs_event_buf[(free_event_idx + i) % MAX_KFS_EVENTS];

    free_event_idx++;
    
    kfse->type     = type;
    kfse->refcount = 0;
    kfse->pid      = p->p_pid;

    unlock_fs_event_buf();  // at this point it's safe to unlock

    //
    // now process the arguments passed in and copy them into
    // the kfse
    //
    arg_idx = 0;
    while(arg_idx < KFS_NUM_ARGS) {
	kea = &kfse->args[arg_idx++];
	kea->type = va_arg(ap, int32_t);

	if (kea->type == FSE_ARG_DONE) {
	    break;
	}

	switch(kea->type) {
	    case FSE_ARG_VNODE: {
		// this expands out into multiple arguments to the client
		struct vnode *vp;
		struct vnode_attr va;

		kea->data.vp = vp = va_arg(ap, struct vnode *);
		if (kea->data.vp == NULL) {
		    panic("add_fsevent: you can't pass me a NULL vnode ptr (type %d)!\n",
			  kfse->type);
		}

		if (vnode_ref_ext(kea->data.vp, O_EVTONLY) != 0) {
		    kea->type = FSE_ARG_DONE;
		    
		    error = EINVAL;
		    goto clean_up;
		}
		VATTR_INIT(&va);
		VATTR_WANTED(&va, va_fsid);
		VATTR_WANTED(&va, va_fileid);
		VATTR_WANTED(&va, va_mode);
		VATTR_WANTED(&va, va_uid);
		VATTR_WANTED(&va, va_gid);
		if (vnode_getattr(kea->data.vp, &va, ctx) != 0) {
		    vnode_rele_ext(kea->data.vp, O_EVTONLY, 0);
		    kea->type = FSE_ARG_DONE;

		    error = EINVAL;
		    goto clean_up;
		}

		kea++;
		kea->type = FSE_ARG_DEV;
		kea->data.dev = dev = (dev_t)va.va_fsid;

		kea++;
		kea->type = FSE_ARG_INO;
		kea->data.ino = (ino_t)va.va_fileid;

		kea++;
		kea->type = FSE_ARG_MODE;
		kea->data.mode = (int32_t)vnode_vttoif(vnode_vtype(vp)) | va.va_mode;

		kea++;
		kea->type = FSE_ARG_UID;
		kea->data.uid = va.va_uid;

		kea++;
		kea->type = FSE_ARG_GID;
		kea->data.gid = va.va_gid;
		arg_idx += 5;
		break;
	    }

	    case FSE_ARG_FINFO: {
		fse_info *fse;
		
		fse = va_arg(ap, fse_info *);
		
		kea->type = FSE_ARG_DEV;
		kea->data.dev = dev = (dev_t)fse->dev;

		kea++;
		kea->type = FSE_ARG_INO;
		kea->data.ino = (ino_t)fse->ino;

		kea++;
		kea->type = FSE_ARG_MODE;
		kea->data.mode = (int32_t)fse->mode;

		kea++;
		kea->type = FSE_ARG_UID;
		kea->data.uid = (uid_t)fse->uid;

		kea++;
		kea->type = FSE_ARG_GID;
		kea->data.gid = (uid_t)fse->gid;
		arg_idx += 4;
		break;
	    }

	    case FSE_ARG_STRING:
		kea->len      = (int16_t)(va_arg(ap, int32_t) & 0xffff);
		kea->data.str = vfs_addname(va_arg(ap, char *), kea->len, 0, 0);
		break;

	    case FSE_ARG_INT32:
		kea->data.int32 = va_arg(ap, int32_t);
		break;

	    case FSE_ARG_INT64:
		printf("fs_events: 64-bit args not implemented.\n");
//		kea->data.int64 = va_arg(ap, int64_t);
		break;

	    case FSE_ARG_RAW:
		kea->len = (int16_t)(va_arg(ap, int32_t) & 0xffff);
		MALLOC(kea->data.ptr, void *, kea->len, M_TEMP, M_WAITOK);
		memcpy(kea->data.ptr, va_arg(ap, void *), kea->len);
		break;

	    case FSE_ARG_DEV:
		kea->data.dev = dev = va_arg(ap, dev_t);
		break;
		
	    case FSE_ARG_MODE:
		kea->data.mode = va_arg(ap, int32_t);
		break;
		
	    case FSE_ARG_INO:
		kea->data.ino = va_arg(ap, ino_t);
		break;
		
	    case FSE_ARG_UID:
		kea->data.uid = va_arg(ap, uid_t);
		break;
		
	    case FSE_ARG_GID:
		kea->data.gid = va_arg(ap, gid_t);
		break;
		
	    default:
		printf("add_fsevent: unknown type %d\n", kea->type);
		// just skip one 32-bit word and hope we sync up...
		(void)va_arg(ap, int32_t);
	}
    }

    va_end(ap);

    //
    // now we have to go and let everyone know that
    // is interested in this type of event...
    //
    lock_watch_list();
    
    SLIST_FOREACH(watcher, &watch_list_head, link) {
	if (watcher->event_list[type] == FSE_REPORT && watcher_cares_about_dev(watcher, dev)) {
	    if (watcher_add_event(watcher, kfse) == 0) {
		num_deliveries++;
	    }
	}
    }

    unlock_watch_list();
    
  clean_up:
    // just in case no one was interested after all...
    if (num_deliveries == 0) {
	do_free_event(kfse);
	free_event_idx = (int)(kfse - &fs_event_buf[0]);
    }	

    lck_rw_done(&fsevent_big_lock);
    return error;
}

static void
do_free_event(kfs_event *kfse)
{
    int i;
    kfs_event_arg *kea, all_args[KFS_NUM_ARGS];
    
    lock_fs_event_buf();
    
    // mark this fsevent as invalid
    kfse->type = FSE_INVALID;

    // make a copy of this so we can free things without
    // holding the fs_event_buf lock
    //
    memcpy(&all_args[0], &kfse->args[0], sizeof(all_args));

    // and just to be anal, set this so that there are no args
    kfse->args[0].type = FSE_ARG_DONE;
    
    free_event_idx = (kfse - fs_event_buf);

    unlock_fs_event_buf();
    
    for(i=0; i < KFS_NUM_ARGS; i++) {
	kea = &all_args[i];
	if (kea->type == FSE_ARG_DONE) {
	    break;
	}

	switch(kea->type) {
	    case FSE_ARG_VNODE:
		vnode_rele_ext(kea->data.vp, O_EVTONLY, 0);
		break;
	    case FSE_ARG_STRING:
		vfs_removename(kea->data.str);
		break;
	    case FSE_ARG_RAW:
		FREE(kea->data.ptr, M_TEMP);
		break;
	}
    }
}


static int
add_watcher(int8_t *event_list, int32_t num_events, int32_t eventq_size, fs_event_watcher **watcher_out)
{
    int               i;
    fs_event_watcher *watcher;

    if (eventq_size < 0 || eventq_size > MAX_KFS_EVENTS) {
	eventq_size = MAX_KFS_EVENTS;
    }

    // Note: the event_queue follows the fs_event_watcher struct
    //       in memory so we only have to do one allocation
    MALLOC(watcher,
	   fs_event_watcher *,
	   sizeof(fs_event_watcher) + eventq_size * sizeof(kfs_event *),
	   M_TEMP, M_WAITOK);

    watcher->event_list   = event_list;
    watcher->num_events   = num_events;
    watcher->devices_to_watch = NULL;
    watcher->num_devices  = 0;
    watcher->flags        = 0;
    watcher->event_queue  = (kfs_event **)&watcher[1];
    watcher->eventq_size  = eventq_size;
    watcher->rd           = 0;
    watcher->wr           = 0;
    watcher->blockers     = 0;

    lock_watch_list();

    // now update the global list of who's interested in
    // events of a particular type...
    for(i=0; i < num_events; i++) {
	if (event_list[i] != FSE_IGNORE && i < FSE_MAX_EVENTS) {
	    fs_event_type_watchers[i]++;
	}
    }

    SLIST_INSERT_HEAD(&watch_list_head, watcher, link);

    unlock_watch_list();

    *watcher_out = watcher;

    return 0;
}

static void
remove_watcher(fs_event_watcher *target)
{
    int i;
    fs_event_watcher *watcher;
    kfs_event *kfse;
    
    lck_rw_lock_shared(&fsevent_big_lock);

    lock_watch_list();
    
    SLIST_FOREACH(watcher, &watch_list_head, link) {
	if (watcher == target) {
	    SLIST_REMOVE(&watch_list_head, watcher, fs_event_watcher, link);

	    for(i=0; i < watcher->num_events; i++) {
		if (watcher->event_list[i] != FSE_IGNORE && i < FSE_MAX_EVENTS) {
		    fs_event_type_watchers[i]--;
		}
	    }

	    unlock_watch_list();
	    
	    // drain the event_queue 
	    for(i=watcher->rd; i != watcher->wr; i=(i+1) % watcher->eventq_size) {
		kfse = watcher->event_queue[i];
		
		if (OSAddAtomic(-1, (SInt32 *)&kfse->refcount) == 1) {
		    do_free_event(kfse);
		}
	    }
	    
	    if (watcher->event_list) {
		FREE(watcher->event_list, M_TEMP);
		watcher->event_list = NULL;
	    }
	    if (watcher->devices_to_watch) {
		FREE(watcher->devices_to_watch, M_TEMP);
		watcher->devices_to_watch = NULL;
	    }
	    FREE(watcher, M_TEMP);

	    lck_rw_done(&fsevent_big_lock);
	    return;
	}
    }

    unlock_watch_list();
    lck_rw_done(&fsevent_big_lock);
}


static int
watcher_add_event(fs_event_watcher *watcher, kfs_event *kfse)
{
    if (((watcher->wr + 1) % watcher->eventq_size) == watcher->rd) {
	watcher->flags |= WATCHER_DROPPED_EVENTS;
	wakeup((caddr_t)watcher);
	return ENOSPC;
    }

    watcher->event_queue[watcher->wr] = kfse;
    OSAddAtomic(1, (SInt32 *)&kfse->refcount);
    watcher->wr = (watcher->wr + 1) % watcher->eventq_size;
    
    // wake up the watcher if he's waiting!
    wakeup((caddr_t)watcher);

    return 0;
}


static int
fmod_watch(fs_event_watcher *watcher, struct uio *uio)
{
    int               i, error=0, last_full_event_resid;
    kfs_event        *kfse;
    kfs_event_arg    *kea;
    uint16_t          tmp16;

    // LP64todo - fix this
    last_full_event_resid = uio_resid(uio);

    // need at least 2048 bytes of space (maxpathlen + 1 event buf)
    if  (uio_resid(uio) < 2048 || watcher == NULL) {
	return EINVAL;
    }


    if (watcher->rd == watcher->wr) {
	if (watcher->flags & WATCHER_CLOSING) {
	    return 0;
	}
	OSAddAtomic(1, (SInt32 *)&watcher->blockers);
    
	// there's nothing to do, go to sleep
	error = tsleep((caddr_t)watcher, PUSER|PCATCH, "fsevents_empty", 0);

	OSAddAtomic(-1, (SInt32 *)&watcher->blockers);

	if (error != 0 || (watcher->flags & WATCHER_CLOSING)) {
	    return error;
	}
    }

    // if we dropped events, return that as an event first
    if (watcher->flags & WATCHER_DROPPED_EVENTS) {
	int32_t val = FSE_EVENTS_DROPPED;

	error = uiomove((caddr_t)&val, sizeof(int32_t), uio);
	if (error == 0) {
	    val = 0;             // a fake pid
	    error = uiomove((caddr_t)&val, sizeof(int32_t), uio);
	    
	    tmp16 = FSE_ARG_DONE;  // makes it a consistent msg
	    error = uiomove((caddr_t)&tmp16, sizeof(int16_t), uio);
	} 

	if (error) {
	    return error;
	}
	
	watcher->flags &= ~WATCHER_DROPPED_EVENTS;
    }

// check if the next chunk of data will fit in the user's
// buffer.  if not, just goto get_out which will return
// the number of bytes worth of events that we did read.
// this leaves the event that didn't fit in the queue.
//    
	// LP64todo - fix this
#define CHECK_UPTR(size) if (size > (unsigned)uio_resid(uio)) { \
                            uio_setresid(uio, last_full_event_resid); \
                            goto get_out; \
                         }

    for (; uio_resid(uio) > 0 && watcher->rd != watcher->wr; ) {
	kfse = watcher->event_queue[watcher->rd];

	// copy out the type of the event
	CHECK_UPTR(sizeof(int32_t));
	if ((error = uiomove((caddr_t)&kfse->type, sizeof(int32_t), uio)) != 0) {
	    goto get_out;
	}

	// now copy out the pid of the person that changed the file
	CHECK_UPTR(sizeof(pid_t));
	if ((error = uiomove((caddr_t)&kfse->pid, sizeof(pid_t), uio)) != 0) {
	    goto get_out;
	}

	error = 0;
	for(i=0; i < KFS_NUM_ARGS && error == 0; i++) {
	    char    *pathbuff;
	    int      pathbuff_len;

	    kea = &kfse->args[i];

	    tmp16 = (uint16_t)kea->type;
	    CHECK_UPTR(sizeof(uint16_t));
	    error = uiomove((caddr_t)&tmp16, sizeof(uint16_t), uio);
	    if (error || kea->type == FSE_ARG_DONE) {
		break;
	    }

	    switch(kea->type) {
		case FSE_ARG_VNODE:
		    pathbuff = get_pathbuff();
		    pathbuff_len = MAXPATHLEN;
		    if (kea->data.vp == NULL) {
			printf("fmod_watch: whoa... vp == NULL (%d)!\n", kfse->type);
			i--;
			release_pathbuff(pathbuff);
			continue;
		    }
		    
		    if (vn_getpath(kea->data.vp, pathbuff, &pathbuff_len) != 0 || pathbuff[0] == '\0') {
//			printf("fmod_watch: vn_getpath failed! vp 0x%x vname 0x%x (%s) vparent 0x%x\n",
//			       kea->data.vp,
//			       VNAME(kea->data.vp),
//			       VNAME(kea->data.vp) ? VNAME(kea->data.vp) : "<null>",
//			       VPARENT(kea->data.vp));
		    }
		    CHECK_UPTR(sizeof(uint16_t));
		    tmp16 = (uint16_t)pathbuff_len;
		    error = uiomove((caddr_t)&tmp16, sizeof(uint16_t), uio);

		    CHECK_UPTR((unsigned)pathbuff_len);
		    error = uiomove((caddr_t)pathbuff, pathbuff_len, uio);
		    release_pathbuff(pathbuff);
		    break;
		    

		case FSE_ARG_STRING:
		    tmp16 = (int32_t)kea->len;
		    CHECK_UPTR(sizeof(uint16_t));
		    error = uiomove((caddr_t)&tmp16, sizeof(uint16_t), uio);

		    CHECK_UPTR(kea->len);
		    error = uiomove((caddr_t)kea->data.str, kea->len, uio);
		    break;

		case FSE_ARG_INT32:
		    CHECK_UPTR(sizeof(uint16_t) + sizeof(int32_t));
		    tmp16 = sizeof(int32_t);
		    error = uiomove((caddr_t)&tmp16, sizeof(uint16_t), uio);
		    error = uiomove((caddr_t)&kea->data.int32, sizeof(int32_t), uio);
		    break;

		case FSE_ARG_INT64:
		    printf("fs_events: 64-bit args not implemented on copyout.\n");
//		    CHECK_UPTR(sizeof(uint16_t) + sizeof(int64_t));
//		    tmp16 = sizeof(int64_t);
//		    error = uiomove((caddr_t)&tmp16, sizeof(uint16_t), uio);
//		    error = uiomove((caddr_t)&kea->data.int64, sizeof(int64_t), uio);
		    break;

		case FSE_ARG_RAW:
		    tmp16 = (uint16_t)kea->len;
		    CHECK_UPTR(sizeof(uint16_t));
		    error = uiomove((caddr_t)&tmp16, sizeof(uint16_t), uio);

		    CHECK_UPTR(kea->len);
		    error = uiomove((caddr_t)kea->data.ptr, kea->len, uio);
		    break;

		case FSE_ARG_DEV:
		    CHECK_UPTR(sizeof(uint16_t) + sizeof(dev_t));
		    tmp16 = sizeof(dev_t);
		    error = uiomove((caddr_t)&tmp16, sizeof(uint16_t), uio);
		    error = uiomove((caddr_t)&kea->data.dev, sizeof(dev_t), uio);
		    break;

		case FSE_ARG_INO:
		    CHECK_UPTR(sizeof(uint16_t) + sizeof(ino_t));
		    tmp16 = sizeof(ino_t);
		    error = uiomove((caddr_t)&tmp16, sizeof(uint16_t), uio);
		    error = uiomove((caddr_t)&kea->data.ino, sizeof(ino_t), uio);
		    break;

		case FSE_ARG_MODE:
		    // XXXdbg - NOTE: we use 32-bits for the mode, not
		    //                16-bits like a real mode_t
		    CHECK_UPTR(sizeof(uint16_t) + sizeof(int32_t));
		    tmp16 = sizeof(int32_t);
		    error = uiomove((caddr_t)&tmp16, sizeof(uint16_t), uio);
		    error = uiomove((caddr_t)&kea->data.mode, sizeof(int32_t), uio);
		    break;

		case FSE_ARG_UID:
		    CHECK_UPTR(sizeof(uint16_t) + sizeof(uid_t));
		    tmp16 = sizeof(uid_t);
		    error = uiomove((caddr_t)&tmp16, sizeof(uint16_t), uio);
		    error = uiomove((caddr_t)&kea->data.uid, sizeof(uid_t), uio);
		    break;

		case FSE_ARG_GID:
		    CHECK_UPTR(sizeof(uint16_t) + sizeof(gid_t));
		    tmp16 = sizeof(gid_t);
		    error = uiomove((caddr_t)&tmp16, sizeof(uint16_t), uio);
		    error = uiomove((caddr_t)&kea->data.gid, sizeof(gid_t), uio);
		    break;

		default:
		    printf("fmod_watch: unknown arg type %d.\n", kea->type);
		    break;
	    }
	}

	// make sure that we always end with a FSE_ARG_DONE
	if (i >= KFS_NUM_ARGS) {
	    tmp16 = FSE_ARG_DONE;
	    CHECK_UPTR(sizeof(uint16_t));
	    error = uiomove((caddr_t)&tmp16, sizeof(uint16_t), uio);
	}
	

	// LP64todo - fix this
	last_full_event_resid = uio_resid(uio);
	
	watcher->rd = (watcher->rd + 1) % watcher->eventq_size;
	    
	if (OSAddAtomic(-1, (SInt32 *)&kfse->refcount) == 1) {
	    do_free_event(kfse);
	}
    }

  get_out:
    return error;
}


// release any references we might have on vnodes which are 
// the mount point passed to us (so that it can be cleanly
// unmounted).
//
// since we don't want to lose the events we'll convert the
// vnode refs to the full path, inode #, and uid.
//
void
fsevent_unmount(struct mount *mp)
{
    int            i, j;
    kfs_event     *kfse;
    kfs_event_arg *kea;
    
    lck_rw_lock_exclusive(&fsevent_big_lock);
    lock_fs_event_buf();
    
    for(i=0; i < MAX_KFS_EVENTS; i++) {
	if (fs_event_buf[i].type == FSE_INVALID) {
	    continue;
	}

	kfse = &fs_event_buf[i];
	for(j=0; j < KFS_NUM_ARGS; j++) {
	    kea = &kfse->args[j];
	    if (kea->type == FSE_ARG_DONE) {
		break;
	    }

	    if (kea->type == FSE_ARG_VNODE && kea->data.vp->v_mount == mp) {
		struct vnode *vp;
		char         *pathbuff;
		int           pathbuff_len;

		vp = kea->data.vp;
		pathbuff = get_pathbuff();
		pathbuff_len = MAXPATHLEN;
		    
		if (vn_getpath(vp, pathbuff, &pathbuff_len) != 0 || pathbuff[0] == '\0') {
		        char *vname;

			vname = vnode_getname(vp);

			printf("fsevent_unmount: vn_getpath failed! vp 0x%x vname 0x%x (%s) vparent 0x%x\n",
			       vp, vname, vname ? vname : "<null>", vp->v_parent);

			if (vname)
			        vnode_putname(vname);
		}

		// switch the type of the string
		kea->type     = FSE_ARG_STRING;
		kea->data.str = vfs_addname(pathbuff, pathbuff_len, 0, 0);
		kea->len      = pathbuff_len;
		release_pathbuff(pathbuff);

		// and finally let go of the reference on the vnode
		vnode_rele_ext(vp, O_EVTONLY, 0);
	    }
	}
    }

    unlock_fs_event_buf();
    lck_rw_done(&fsevent_big_lock);
}


//
// /dev/fsevents device code
//
static int fsevents_installed = 0;
static struct lock__bsd__ fsevents_lck;

typedef struct fsevent_handle {
    fs_event_watcher *watcher;
    struct selinfo    si;
} fsevent_handle;


static int
fseventsf_read(struct fileproc *fp, struct uio *uio,
		__unused kauth_cred_t *cred, __unused int flags,
		__unused struct proc *p)
{
    fsevent_handle *fseh = (struct fsevent_handle *)fp->f_fglob->fg_data;
    int error;

    error = fmod_watch(fseh->watcher, uio);

    return error;
}

static int
fseventsf_write(__unused struct fileproc *fp, __unused struct uio *uio,
		__unused kauth_cred_t *cred, __unused int flags,
		__unused struct proc *p)
{
    return EIO;
}


static int
fseventsf_ioctl(struct fileproc *fp, u_long cmd, caddr_t data, struct proc *p)
{
    fsevent_handle *fseh = (struct fsevent_handle *)fp->f_fglob->fg_data;
    int ret = 0;
    pid_t pid = 0;
    fsevent_dev_filter_args *devfilt_args=(fsevent_dev_filter_args *)data;

    switch (cmd) {
	case FIONBIO:
	case FIOASYNC:
	    return 0;

	case FSEVENTS_DEVICE_FILTER: {
	    int new_num_devices;
	    dev_t *devices_to_watch, *tmp=NULL;
	    
	    if (devfilt_args->num_devices > 256) {
		ret = EINVAL;
		break;
	    }
	    
	    new_num_devices = devfilt_args->num_devices;
	    if (new_num_devices == 0) {
		tmp = fseh->watcher->devices_to_watch;

		lock_watch_list();
		fseh->watcher->devices_to_watch = NULL;
		fseh->watcher->num_devices = new_num_devices;
		unlock_watch_list();

		if (tmp) {
		    FREE(tmp, M_TEMP);
		}
		break;
	    }

	    MALLOC(devices_to_watch, dev_t *,
		   new_num_devices * sizeof(dev_t),
		   M_TEMP, M_WAITOK);
	    if (devices_to_watch == NULL) {
		ret = ENOMEM;
		break;
	    }
    
	    ret = copyin(CAST_USER_ADDR_T(devfilt_args->devices),
			 (void *)devices_to_watch,
			 new_num_devices * sizeof(dev_t));
	    if (ret) {
		FREE(devices_to_watch, M_TEMP);
		break;
	    }

	    lock_watch_list();
	    fseh->watcher->num_devices = new_num_devices;
	    tmp = fseh->watcher->devices_to_watch;
	    fseh->watcher->devices_to_watch = devices_to_watch;
	    unlock_watch_list();

	    if (tmp) {
		FREE(tmp, M_TEMP);
	    }
	    
	    break;
	}	    

	default:
	    ret = EINVAL;
	    break;
    }

    return (ret);
}


static int
fseventsf_select(struct fileproc *fp, int which, void *wql, struct proc *p)
{
    fsevent_handle *fseh = (struct fsevent_handle *)fp->f_fglob->fg_data;
    int ready = 0;

    if ((which != FREAD) || (fseh->watcher->flags & WATCHER_CLOSING)) {
	return 0;
    }


    // if there's nothing in the queue, we're not ready
    if (fseh->watcher->rd == fseh->watcher->wr) {
	ready = 0;
    } else {
	ready = 1;
    }

    if (!ready) {
	selrecord(p, &fseh->si, wql);
    }

    return ready;
}


static int
fseventsf_stat(struct fileproc *fp, struct stat *sb, struct proc *p)
{
    return ENOTSUP;
}


static int
fseventsf_close(struct fileglob *fg, struct proc *p)
{
    fsevent_handle *fseh = (struct fsevent_handle *)fg->fg_data;

    remove_watcher(fseh->watcher);

    fg->fg_data = NULL;
    fseh->watcher = NULL;
    FREE(fseh, M_TEMP);

    return 0;
}

int
fseventsf_kqfilter(struct fileproc *fp, struct knote *kn, struct proc *p)
{
    // XXXdbg
    return 0;
}


static int
fseventsf_drain(struct fileproc *fp, struct proc *p)
{
    int counter = 0;
    fsevent_handle *fseh = (struct fsevent_handle *)fp->f_fglob->fg_data;

    fseh->watcher->flags |= WATCHER_CLOSING;

    // if there are people still waiting, sleep for 10ms to
    // let them clean up and get out of there.  however we
    // also don't want to get stuck forever so if they don't
    // exit after 5 seconds we're tearing things down anyway.
    while(fseh->watcher->blockers && counter++ < 500) {
        // issue wakeup in case anyone is blocked waiting for an event
        // do this each time we wakeup in case the blocker missed
        // the wakeup due to the unprotected test of WATCHER_CLOSING
        // and decision to tsleep in fmod_watch... this bit of 
        // latency is a decent tradeoff against not having to
        // take and drop a lock in fmod_watch
	wakeup((caddr_t)fseh->watcher);

	tsleep((caddr_t)fseh->watcher, PRIBIO, "watcher-close", 1);
    }

    return 0;
}


static int
fseventsopen(dev_t dev, int flag, int mode, struct proc *p)
{
    if (!is_suser()) {
	return EPERM;
    }
    
    return 0;
}

static int
fseventsclose(dev_t dev, int flag, int mode, struct proc *p)
{
    return 0;
}

static int
fseventsread(dev_t dev, struct uio *uio, int ioflag)
{
    return EIO;
}

static int
fseventswrite(dev_t dev, struct uio *uio, int ioflag)
{
    return EIO;
}


static struct fileops fsevents_fops = {
    fseventsf_read,
    fseventsf_write,
    fseventsf_ioctl,
    fseventsf_select,
    fseventsf_close,
    fseventsf_kqfilter,
    fseventsf_drain
};



static int
fseventsioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p)
{
    struct fileproc *f;
    int fd, error;
    fsevent_handle *fseh = NULL;
    fsevent_clone_args *fse_clone_args=(fsevent_clone_args *)data;
    int8_t *event_list;

    switch (cmd) {
	case FSEVENTS_CLONE:
	    if (fse_clone_args->num_events < 0 || fse_clone_args->num_events > 4096) {
		return EINVAL;
	    }

	    MALLOC(fseh, fsevent_handle *, sizeof(fsevent_handle),
		   M_TEMP, M_WAITOK);
	    memset(fseh, 0, sizeof(fsevent_handle));

	    MALLOC(event_list, int8_t *,
		   fse_clone_args->num_events * sizeof(int8_t),
		   M_TEMP, M_WAITOK);
    
	    error = copyin(CAST_USER_ADDR_T(fse_clone_args->event_list),
			   (void *)event_list,
			   fse_clone_args->num_events * sizeof(int8_t));
	    if (error) {
		FREE(event_list, M_TEMP);
		FREE(fseh, M_TEMP);
		return error;
	    }
    
	    error = add_watcher(event_list,
				fse_clone_args->num_events,
				fse_clone_args->event_queue_depth,
				&fseh->watcher);
	    if (error) {
		FREE(event_list, M_TEMP);
		FREE(fseh, M_TEMP);
		return error;
	    }

	    error = falloc(p, &f, &fd);
	    if (error) {
		FREE(event_list, M_TEMP);
		FREE(fseh, M_TEMP);
		return (error);
	    }
	    proc_fdlock(p);
	    f->f_fglob->fg_flag = FREAD | FWRITE;
	    f->f_fglob->fg_type = DTYPE_FSEVENTS;
	    f->f_fglob->fg_ops = &fsevents_fops;
	    f->f_fglob->fg_data = (caddr_t) fseh;
		proc_fdunlock(p);
	    copyout((void *)&fd, CAST_USER_ADDR_T(fse_clone_args->fd), sizeof(int32_t));
		proc_fdlock(p);
	    *fdflags(p, fd) &= ~UF_RESERVED;
		fp_drop(p, fd, f, 1);
		proc_fdunlock(p);
	    break;

	default:
	    error = EINVAL;
	    break;
    }

    return error;
}

static int
fseventsselect(dev_t dev, int rw, struct proc *p)
{
    return 0;
}

static void
fsevents_wakeup(fsevent_handle *fseh)
{
    wakeup((caddr_t)fseh);
    selwakeup(&fseh->si);
}


/*
 * A struct describing which functions will get invoked for certain
 * actions.
 */
static struct cdevsw fsevents_cdevsw =
{
    fseventsopen,		/* open */
    fseventsclose,		/* close */
    fseventsread,		/* read */
    fseventswrite,		/* write */
    fseventsioctl,		/* ioctl */
    nulldev,			/* stop */
    nulldev,			/* reset */
    NULL,			/* tty's */
    eno_select,			/* select */
    eno_mmap,			/* mmap */
    eno_strat,			/* strategy */
    eno_getc,			/* getc */
    eno_putc,			/* putc */
    0				/* type */
};


/*
 * Called to initialize our device,
 * and to register ourselves with devfs
 */

void
fsevents_init(void)
{
    int ret;

    if (fsevents_installed) {
	return;
    } 

    fsevents_installed = 1;

    lockinit(&fsevents_lck, PLOCK, "fsevents", 0, 0);

    ret = cdevsw_add(-1, &fsevents_cdevsw);
    if (ret < 0) {
	fsevents_installed = 0;
	return;
    }

    devfs_make_node(makedev (ret, 0), DEVFS_CHAR,
		    UID_ROOT, GID_WHEEL, 0644, "fsevents", 0);

    fsevents_internal_init();
}



//
// XXXdbg - temporary path buffer handling
//
#define NUM_PATH_BUFFS  16
static char path_buff[NUM_PATH_BUFFS][MAXPATHLEN];
static char path_buff_inuse[NUM_PATH_BUFFS];

static lck_grp_attr_t * pathbuff_group_attr;
static lck_attr_t *     pathbuff_lock_attr;
static lck_grp_t *      pathbuff_mutex_group;
static lck_mtx_t        pathbuff_lock;

static void
init_pathbuff(void)
{
    pathbuff_lock_attr    = lck_attr_alloc_init();
    pathbuff_group_attr   = lck_grp_attr_alloc_init();
    pathbuff_mutex_group  = lck_grp_alloc_init("pathbuff-mutex", pathbuff_group_attr);

    lck_mtx_init(&pathbuff_lock, pathbuff_mutex_group, pathbuff_lock_attr);
}

static void
lock_pathbuff(void)
{
    lck_mtx_lock(&pathbuff_lock);
}

static void
unlock_pathbuff(void)
{
    lck_mtx_unlock(&pathbuff_lock);
}


char *
get_pathbuff(void)
{
    int i;

    lock_pathbuff();
    for(i=0; i < NUM_PATH_BUFFS; i++) {
	if (path_buff_inuse[i] == 0) {
	    break;
	}
    }

    if (i >= NUM_PATH_BUFFS) {
	char *path;
	
	unlock_pathbuff();
	MALLOC_ZONE(path, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
	return path;
    }

    path_buff_inuse[i] = 1;
    unlock_pathbuff();
    return &path_buff[i][0];
}

void
release_pathbuff(char *path)
{
    int i;

    if (path == NULL) {
	return;
    }

    lock_pathbuff();
    for(i=0; i < NUM_PATH_BUFFS; i++) {
	if (path == &path_buff[i][0]) {
	    path_buff[i][0] = '\0';
	    path_buff_inuse[i] = 0;
	    unlock_pathbuff();
	    return;
	}
    }

    unlock_pathbuff();

    // if we get here then it wasn't one of our temp buffers
    FREE_ZONE(path, MAXPATHLEN, M_NAMEI);
}

int
get_fse_info(struct vnode *vp, fse_info *fse, vfs_context_t ctx)
{
    struct vnode_attr va;

    VATTR_INIT(&va);
    VATTR_WANTED(&va, va_fsid);
    VATTR_WANTED(&va, va_fileid);
    VATTR_WANTED(&va, va_mode);
    VATTR_WANTED(&va, va_uid);
    VATTR_WANTED(&va, va_gid);
    if (vnode_getattr(vp, &va, ctx) != 0) {
	return -1;
    }
    
    fse->dev  = (dev_t)va.va_fsid;
    fse->ino  = (ino_t)va.va_fileid;
    fse->mode = (int32_t)vnode_vttoif(vnode_vtype(vp)) | va.va_mode;
    fse->uid  = (uid_t)va.va_uid;
    fse->gid  = (gid_t)va.va_gid;
    
    return 0;
}
