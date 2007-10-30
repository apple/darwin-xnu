/*
 * Copyright (c) 2004-2006 Apple Computer, Inc. All rights reserved.
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
#include <libsa/stdlib.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/fsevents.h>

#if CONFIG_FSE
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
#include <kern/locks.h>
#include <libkern/OSAtomic.h>
#include <kern/zalloc.h>
#include <mach/mach_time.h>
#include <kern/thread_call.h>
#include <kern/clock.h>

#include <bsm/audit_kernel.h>
#include <bsm/audit_kevents.h>



typedef struct kfs_event {
    LIST_ENTRY(kfs_event) kevent_list;
    int16_t        type;           // type code of this event
    u_int16_t      flags,          // per-event flags
                   len;            // the length of the path in "str"
    int32_t        refcount;       // number of clients referencing this
    pid_t          pid;            // pid of the process that did the op

    uint64_t       abstime;        // when this event happened (mach_absolute_time())
    ino64_t        ino;
    dev_t          dev;
    int32_t        mode;
    uid_t          uid;
    gid_t          gid;

    const char    *str;

    struct kfs_event *dest;    // if this is a two-file op
} kfs_event;

// flags for the flags field
#define KFSE_COMBINED_EVENTS          0x0001
#define KFSE_CONTAINS_DROPPED_EVENTS  0x0002
#define KFSE_RECYCLED_EVENT           0x0004
#define KFSE_BEING_CREATED            0x0008

LIST_HEAD(kfse_list, kfs_event) kfse_list_head = LIST_HEAD_INITIALIZER(x);
int num_events_outstanding = 0;
int num_pending_rename = 0;


struct fsevent_handle;

typedef struct fs_event_watcher {
    int8_t      *event_list;             // the events we're interested in
    int32_t      num_events;
    dev_t       *devices_to_watch;       // only report events from these devices
    uint32_t     num_devices;
    int32_t      flags;
    kfs_event  **event_queue;
    int32_t      eventq_size;            // number of event pointers in queue
    int32_t      num_readers;
    int32_t      rd;                     // read index into the event_queue
    int32_t      wr;                     // write index into the event_queue
    int32_t      blockers;
    int32_t      my_id;
    uint32_t     num_dropped;
    struct fsevent_handle *fseh;
} fs_event_watcher;

// fs_event_watcher flags
#define WATCHER_DROPPED_EVENTS         0x0001
#define WATCHER_CLOSING                0x0002
#define WATCHER_WANTS_COMPACT_EVENTS   0x0004
#define WATCHER_WANTS_EXTENDED_INFO    0x0008


#define MAX_WATCHERS  8
static fs_event_watcher *watcher_table[MAX_WATCHERS];


#define MAX_KFS_EVENTS   4096

// we allocate kfs_event structures out of this zone
static zone_t     event_zone;
static int        fs_event_init = 0;

//
// this array records whether anyone is interested in a
// particular type of event.  if no one is, we bail out
// early from the event delivery
//
static int16_t     fs_event_type_watchers[FSE_MAX_EVENTS];

static int  watcher_add_event(fs_event_watcher *watcher, kfs_event *kfse);
static void fsevents_wakeup(fs_event_watcher *watcher);

//
// Locks
//
static lck_grp_attr_t *  fsevent_group_attr;
static lck_attr_t *      fsevent_lock_attr;
static lck_grp_t *       fsevent_mutex_group;

static lck_grp_t *       fsevent_rw_group;

static lck_rw_t  event_handling_lock; // handles locking for event manipulation and recycling
static lck_mtx_t watch_table_lock;
static lck_mtx_t event_buf_lock;
static lck_mtx_t event_writer_lock;

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

    memset(watcher_table, 0, sizeof(watcher_table));

    fsevent_lock_attr    = lck_attr_alloc_init();
    fsevent_group_attr   = lck_grp_attr_alloc_init();
    fsevent_mutex_group  = lck_grp_alloc_init("fsevent-mutex", fsevent_group_attr);
    fsevent_rw_group     = lck_grp_alloc_init("fsevent-rw", fsevent_group_attr);

    lck_mtx_init(&watch_table_lock, fsevent_mutex_group, fsevent_lock_attr);
    lck_mtx_init(&event_buf_lock, fsevent_mutex_group, fsevent_lock_attr);
    lck_mtx_init(&event_writer_lock, fsevent_mutex_group, fsevent_lock_attr);

    lck_rw_init(&event_handling_lock, fsevent_rw_group, fsevent_lock_attr);

    event_zone = zinit(sizeof(kfs_event),
	               MAX_KFS_EVENTS * sizeof(kfs_event),
	               MAX_KFS_EVENTS * sizeof(kfs_event),
	               "fs-event-buf");
    if (event_zone == NULL) {
	printf("fsevents: failed to initialize the event zone.\n");
    }

    if (zfill(event_zone, MAX_KFS_EVENTS) != MAX_KFS_EVENTS) {
	printf("fsevents: failed to pre-fill the event zone.\n");	
    }
    
    // mark the zone as exhaustible so that it will not
    // ever grow beyond what we initially filled it with
    zone_change(event_zone, Z_EXHAUST, TRUE);
    zone_change(event_zone, Z_COLLECT, FALSE);

    init_pathbuff();
}

static void
lock_watch_table(void)
{
    lck_mtx_lock(&watch_table_lock);
}

static void
unlock_watch_table(void)
{
    lck_mtx_unlock(&watch_table_lock);
}

static void
lock_fs_event_list(void)
{
    lck_mtx_lock(&event_buf_lock);
}

static void
unlock_fs_event_list(void)
{
    lck_mtx_unlock(&event_buf_lock);
}

// forward prototype
static void release_event_ref(kfs_event *kfse);

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
    if (type >= 0 && type < FSE_MAX_EVENTS && fs_event_type_watchers[type] == 0)
	return (0);

    // events in /dev aren't really interesting...
    if (vp->v_tag == VT_DEVFS) {
	return (0);
    }

    return 1;
}

static int
prefix_match_len(const char *str1, const char *str2)
{
    int len=0;

    while(*str1 && *str2 && *str1 == *str2) {
	len++;
	str1++;
	str2++;
    }

    if (*str1 == '\0' && *str2 == '\0') {
	len++;
    }

    return len;
}


struct history_item {
    kfs_event *kfse;
    kfs_event *oldest_kfse;
    int        counter;
};

static int
compare_history_items(const void *_a, const void *_b)
{
    const struct history_item *a = (const struct history_item *)_a;
    const struct history_item *b = (const struct history_item *)_b;

    // we want a descending order
    return (b->counter - a->counter);
}

#define is_throw_away(x)  ((x) == FSE_STAT_CHANGED || (x) == FSE_CONTENT_MODIFIED)


// Ways that an event can be reused:
//
// "combined" events mean that there were two events for 
// the same vnode or path and we're combining both events 
// into a single event.  The primary event gets a bit that
// marks it as having been combined.  The secondary event 
// is essentially dropped and the kfse structure reused.
//
// "collapsed" means that multiple events below a given
// directory are collapsed into a single event.  in this
// case, the directory that we collapse into and all of
// its children must be re-scanned.
//
// "recycled" means that we're completely blowing away 
// the event since there are other events that have info 
// about the same vnode or path (and one of those other 
// events will be marked as combined or collapsed as
// appropriate).
//
#define KFSE_COMBINED   0x0001
#define KFSE_COLLAPSED  0x0002
#define KFSE_RECYCLED   0x0004

int num_dropped         = 0;
int num_combined_events = 0;
int num_added_to_parent = 0;
int num_parent_switch   = 0;
int num_recycled_rename = 0;

//
// NOTE: you must call lock_fs_event_list() before calling
//       this function.
//
static kfs_event *
find_an_event(const char *str, int len, kfs_event *do_not_reuse, int *reuse_type, int *longest_match_len)
{
    kfs_event *kfse, *best_kfse=NULL;

// this seems to be enough to find most duplicate events for the same vnode
#define MAX_HISTORY  12 
    struct history_item history[MAX_HISTORY];
    int           i;

    *longest_match_len = 0;
    *reuse_type = 0;
    
    memset(history, 0, sizeof(history));

    //
    // now walk the list of events and try to find the best match
    // for this event.  if we have a vnode, we look for an event
    // that already references the vnode.  if we don't find one
    // we'll also take the parent of this vnode (in which case it
    // will be marked as having dropped events within it).
    //
    // if we have a string we look for the longest match on the
    // path we have.
    //

    LIST_FOREACH(kfse, &kfse_list_head, kevent_list) {
	int match_len;

	//
	// don't look at events that are still in the process of being
	// created, have a null vnode ptr or rename/exchange events.
	//
	if (   (kfse->flags & KFSE_BEING_CREATED) || kfse->type == FSE_RENAME || kfse->type == FSE_EXCHANGE) {

	    continue;
	}
	
	if (str != NULL) {
	    if (kfse->len != 0 && kfse->str != NULL) {
		match_len = prefix_match_len(str, kfse->str);
		if (match_len > *longest_match_len) {
		    best_kfse = kfse;
		    *longest_match_len = match_len;
		}
	    }
	}

	if (kfse == do_not_reuse) {
	    continue;
	}

	for(i=0; i < MAX_HISTORY; i++) {
	    if (history[i].kfse == NULL) {
		break;
	    }

	    //
	    // do a quick check to see if we've got two simple events
	    // that we can cheaply combine.  if the event we're looking
	    // at and one of the events in the history table are for the
	    // same path then we'll just mark the newer event as combined
	    // and recyle the older event.
	    //
	    if (history[i].kfse->str == kfse->str) {

		OSBitOrAtomic16(KFSE_COMBINED_EVENTS, &kfse->flags);
		*reuse_type = KFSE_RECYCLED;
		history[i].kfse->flags |= KFSE_RECYCLED_EVENT;
		return history[i].kfse;
	    }
	}

	if (i < MAX_HISTORY && history[i].kfse == NULL) {
	    history[i].kfse = kfse;
	    history[i].counter = 1;
	} else if (i >= MAX_HISTORY) {
	    qsort(history, MAX_HISTORY, sizeof(struct history_item), compare_history_items);

	    // pluck off the lowest guy if he's only got a count of 1
	    if (history[MAX_HISTORY-1].counter == 1) {
		history[MAX_HISTORY-1].kfse = kfse;
	    }
	}
    }

    
    if (str != NULL && best_kfse) {
	if (*longest_match_len <= 1) {
	    // if the best match we had was "/" then basically we're toast...
	    *longest_match_len = 0;
	    best_kfse = NULL;
	} else if (*longest_match_len != len) {
	    OSBitOrAtomic16(KFSE_CONTAINS_DROPPED_EVENTS, &best_kfse->flags);
	    *reuse_type = KFSE_COLLAPSED;
	} else {
	    OSBitOrAtomic16(KFSE_COMBINED_EVENTS, &best_kfse->flags);
	    *reuse_type = KFSE_COMBINED;
	}
    }

    return best_kfse;
}


static struct timeval last_print;

//
// These variables are used to track coalescing multiple identical
// events for the same vnode/pathname.  If we get the same event
// type and same vnode/pathname as the previous event, we just drop
// the event since it's superfluous.  This improves some micro-
// benchmarks considerably and actually has a real-world impact on
// tests like a Finder copy where multiple stat-changed events can
// get coalesced.
//
static int     last_event_type=-1;
static void   *last_ptr=NULL;
static char    last_str[MAXPATHLEN];
static int     last_nlen=0;
static int     last_vid=-1;
static uint64_t last_coalesced_time=0;
int            last_coalesced = 0;
static mach_timebase_info_data_t    sTimebaseInfo = { 0, 0 };


int
add_fsevent(int type, vfs_context_t ctx, ...) 
{
    struct proc	     *p = vfs_context_proc(ctx);
    int               i, arg_type, skip_init=0, longest_match_len, ret;
    kfs_event        *kfse, *kfse_dest=NULL, *cur;
    fs_event_watcher *watcher;
    va_list           ap;
    int 	      error = 0, did_alloc=0, need_event_unlock = 0;
    dev_t             dev = 0;
    uint64_t          now, elapsed;
    int               reuse_type = 0;
    char             *pathbuff=NULL;
    int               pathbuff_len;


    va_start(ap, ctx);

    // ignore bogus event types..
    if (type < 0 || type >= FSE_MAX_EVENTS) {
	return EINVAL;
    }

    // if no one cares about this type of event, bail out
    if (fs_event_type_watchers[type] == 0) {
	va_end(ap);
	return 0;
    }

    now = mach_absolute_time();

    // find a free event and snag it for our use
    // NOTE: do not do anything that would block until
    //       the lock is dropped.
    lock_fs_event_list();
    
    //
    // check if this event is identical to the previous one...
    // (as long as it's not an event type that can never be the
    // same as a previous event)
    //
    if (type != FSE_CREATE_FILE && type != FSE_DELETE && type != FSE_RENAME && type != FSE_EXCHANGE) {
	void *ptr=NULL;
	int   vid=0, was_str=0, nlen=0;

	for(arg_type=va_arg(ap, int32_t); arg_type != FSE_ARG_DONE; arg_type=va_arg(ap, int32_t)) {
	    switch(arg_type) {
		case FSE_ARG_VNODE: {
		    ptr = va_arg(ap, void *);
		    vid = vnode_vid((struct vnode *)ptr);
		    last_str[0] = '\0';
		    break;
		}
		case FSE_ARG_STRING: {
		    nlen = va_arg(ap, int32_t);
		    ptr = va_arg(ap, void *);
		    was_str = 1;
		    break;
		}
	    }
	    if (ptr != NULL) {
		break;
	    }
	}

	if ( sTimebaseInfo.denom == 0 ) {
	    (void) clock_timebase_info(&sTimebaseInfo);
	}
	
	elapsed = (now - last_coalesced_time);
	if (sTimebaseInfo.denom != sTimebaseInfo.numer) {
	    if (sTimebaseInfo.denom == 1) {
		elapsed *= sTimebaseInfo.numer;
	    } else {
		// this could overflow... the worst that will happen is that we'll
		// send (or not send) an extra event so I'm not going to worry about
		// doing the math right like dtrace_abs_to_nano() does.
		elapsed = (elapsed * sTimebaseInfo.numer) / (uint64_t)sTimebaseInfo.denom;
	    }
	}
	
	if (type == last_event_type
            && (elapsed < 1000000000)
	    && 
	    ((vid && vid == last_vid && last_ptr == ptr)
	      ||
	     (last_str[0] && last_nlen == nlen && ptr && strcmp(last_str, ptr) == 0))
	   ) {
	    
	    last_coalesced++;
	    unlock_fs_event_list();
	    va_end(ap);
	    return 0;
	} else {
	    last_ptr = ptr;
	    if (was_str) {
		strlcpy(last_str, ptr, sizeof(last_str));
	    }
	    last_nlen = nlen;
	    last_vid = vid;
	    last_event_type = type;
	    last_coalesced_time = now;
	}
    }
    va_start(ap, ctx);


    kfse = zalloc_noblock(event_zone);
    if (kfse && (type == FSE_RENAME || type == FSE_EXCHANGE)) {
	kfse_dest = zalloc_noblock(event_zone);
	if (kfse_dest == NULL) {
	    did_alloc = 1;
	    zfree(event_zone, kfse);
	    kfse = NULL;
	}
    }


    if (kfse == NULL) {        // yikes! no free events
	int len=0;
	char *str;
	
	//
	// Figure out what kind of reference we have to the
	// file in this event.  This helps us find an event
	// to combine/collapse into to make room.
	//
	// If we have a rename or exchange event then we
	// don't want to go through the normal path, we
	// want to "steal" an event instead (which is what
	// find_an_event() will do if str is null).
	//
	arg_type = va_arg(ap, int32_t);
	if (type == FSE_RENAME || type == FSE_EXCHANGE) {
	    str = NULL;
	} else if (arg_type == FSE_ARG_STRING) {
	    len = va_arg(ap, int32_t);
	    str = va_arg(ap, char *);
	} else if (arg_type == FSE_ARG_VNODE) {
	    struct vnode *vp;

	    vp  = va_arg(ap, struct vnode *);
	    pathbuff = get_pathbuff();
	    pathbuff_len = MAXPATHLEN;
	    if (vn_getpath(vp, pathbuff, &pathbuff_len) != 0 || pathbuff[0] == '\0') {
		release_pathbuff(pathbuff);
		pathbuff = NULL;
	    }
	    str = pathbuff;
	} else {
	    str = NULL;
	}

	//
	// This will go through all events and find one that we
        // can combine with (hopefully), or "collapse" into (i.e
	// it has the same parent) or in the worst case we have
	// to "recycle" an event which means that it will combine
	// two other events and return us the now unused event.
	// failing all that, find_an_event() could still return
	// null and if it does then we have a catastrophic dropped
	// events scenario.
	//
	kfse = find_an_event(str, len, NULL, &reuse_type, &longest_match_len);

	if (kfse == NULL) {
	  bail_early:
	    
	    unlock_fs_event_list();
	    lock_watch_table();

	    for(i=0; i < MAX_WATCHERS; i++) {
		watcher = watcher_table[i];
		if (watcher == NULL) {
		    continue;
		}

		watcher->flags |= WATCHER_DROPPED_EVENTS;
		fsevents_wakeup(watcher);
	    }
	    unlock_watch_table();

	    {	    
		struct timeval current_tv;

		num_dropped++;

		// only print a message at most once every 5 seconds
		microuptime(&current_tv);
		if ((current_tv.tv_sec - last_print.tv_sec) > 10) {
		    int ii;
		    void *junkptr=zalloc_noblock(event_zone), *listhead=kfse_list_head.lh_first;
		    
		    printf("add_fsevent: event queue is full! dropping events (num dropped events: %d; num events outstanding: %d).\n", num_dropped, num_events_outstanding);
		    printf("add_fsevent: kfse_list head %p ; num_pending_rename %d\n", listhead, num_pending_rename);
		    printf("add_fsevent: zalloc sez: %p\n", junkptr);
		    printf("add_fsevent: event_zone info: %d %p\n", ((int *)event_zone)[0], (void *)((int *)event_zone)[1]);
		    for(ii=0; ii < MAX_WATCHERS; ii++) {
			if (watcher_table[ii] == NULL) {
			    continue;
			}
			
			printf("add_fsevent: watcher %p: num dropped %d rd %4d wr %4d q_size %4d flags 0x%x\n",
			    watcher_table[ii], watcher_table[ii]->num_dropped,
			    watcher_table[ii]->rd, watcher_table[ii]->wr,
			    watcher_table[ii]->eventq_size, watcher_table[ii]->flags);
		    }

		    last_print = current_tv;
		    if (junkptr) {
			zfree(event_zone, junkptr);
		    }
		}
	    }

	    if (pathbuff) {
		release_pathbuff(pathbuff);
		pathbuff = NULL;
	    }

	    return ENOSPC;
	}

	if ((type == FSE_RENAME || type == FSE_EXCHANGE) && reuse_type != KFSE_RECYCLED) {
	    panic("add_fsevent: type == %d but reuse type == %d!\n", type, reuse_type);
	} else if ((kfse->type == FSE_RENAME || kfse->type == FSE_EXCHANGE) && kfse->dest == NULL) {
	    panic("add_fsevent: bogus kfse %p (type %d, but dest is NULL)\n", kfse, kfse->type);
	} else if (kfse->type == FSE_RENAME || kfse->type == FSE_EXCHANGE) {
	    panic("add_fsevent: we should never re-use rename events (kfse %p reuse type %d)!\n", kfse, reuse_type);
	}

	if (reuse_type == KFSE_COLLAPSED) {
	    if (str) {
		const char *tmp_ptr, *new_str;
		
		//
		// if we collapsed and have a string we have to chop off the
		// tail component of the pathname to get the parent.
		//
		// NOTE: it is VERY IMPORTANT that we leave the trailing slash
		//       on the pathname.  user-level code depends on this.
		//
		if (str[0] == '\0' || longest_match_len <= 1) {
		    printf("add_fsevent: strange state (str %s / longest_match_len %d)\n", str, longest_match_len);
		    if (longest_match_len < 0) {
			panic("add_fsevent: longest_match_len %d\n", longest_match_len);
		    }
		}
		// chop off the tail component if it's not the
		// first character...
		if (longest_match_len > 1) {
		    str[longest_match_len] = '\0';
		} else if (longest_match_len == 0) {
		    longest_match_len = 1;
		}

		new_str = vfs_addname(str, longest_match_len, 0, 0);
		if (new_str == NULL || new_str[0] == '\0') {
		    panic("add_fsevent: longest match is strange (new_str %p).\n", new_str);
		}
		
		lck_rw_lock_exclusive(&event_handling_lock);

		kfse->len      = longest_match_len;
		tmp_ptr        = kfse->str;
		kfse->str = new_str;
		kfse->ino      = 0;
		kfse->mode     = 0;
		kfse->uid      = 0;
		kfse->gid      = 0;
		
		lck_rw_unlock_exclusive(&event_handling_lock);
		
		vfs_removename(tmp_ptr);
	    } else {
		panic("add_fsevent: don't have a vnode or a string pointer (kfse %p)\n", kfse);
	    }
	}

	if (reuse_type == KFSE_RECYCLED && (type == FSE_RENAME || type == FSE_EXCHANGE)) {
	    
	    // if we're recycling this kfse and we have a rename or
	    // exchange event then we need to also get an event for
	    // kfse_dest. 
	    //
	    if (did_alloc) {
		// only happens if we allocated one but then failed
		// for kfse_dest (and thus free'd the first one we
		// allocated)
		kfse_dest = zalloc_noblock(event_zone);
		if (kfse_dest != NULL) {
		    memset(kfse_dest, 0, sizeof(kfs_event));
		    kfse_dest->refcount = 1;
		    OSBitOrAtomic16(KFSE_BEING_CREATED, &kfse_dest->flags);
		} else {
		    did_alloc = 0;
		}
	    }

	    if (kfse_dest == NULL) {
		int dest_reuse_type, dest_match_len;
		
		kfse_dest = find_an_event(NULL, 0, kfse, &dest_reuse_type, &dest_match_len);
		
		if (kfse_dest == NULL) {
		    // nothing we can do... gotta bail out
		    goto bail_early;
		}

		if (dest_reuse_type != KFSE_RECYCLED) {
		    panic("add_fsevent: type == %d but dest_reuse type == %d!\n", type, dest_reuse_type);
		}
	    }
	}


	//
	// Here we check for some fast-path cases so that we can
	// jump over the normal initialization and just get on
	// with delivering the event.  These cases are when we're
	// combining/collapsing an event and so basically there is
	// no more work to do (aside from a little book-keeping)
	//
	if (str && kfse->len != 0) {
	    kfse->abstime = now;
	    OSAddAtomic(1, (SInt32 *)&kfse->refcount);
	    skip_init = 1;

	    if (reuse_type == KFSE_COMBINED) {
		num_combined_events++;
	    } else if (reuse_type == KFSE_COLLAPSED) {
		num_added_to_parent++;
	    }
	} else if (reuse_type != KFSE_RECYCLED) {
	    panic("add_fsevent: I'm so confused! (reuse_type %d str %p kfse->len %d)\n",
		  reuse_type, str, kfse->len);
	}

	va_end(ap);


	if (skip_init) {
	    if (kfse->refcount < 1) {
		panic("add_fsevent: line %d: kfse recount %d but should be at least 1\n", __LINE__, kfse->refcount);
	    }

	    unlock_fs_event_list();
	    goto normal_delivery;
	    
	} else if (reuse_type == KFSE_RECYCLED || reuse_type == KFSE_COMBINED) {

	    //
	    // If we're here we have to clear out the kfs_event(s)
	    // that we were given by find_an_event() and set it
	    // up to be re-filled in by the normal code path.
	    //
	    va_start(ap, ctx);

	    need_event_unlock = 1;
	    lck_rw_lock_exclusive(&event_handling_lock);

	    OSAddAtomic(1, (SInt32 *)&kfse->refcount);

	    if (kfse->refcount < 1) {
		panic("add_fsevent: line %d: kfse recount %d but should be at least 1\n", __LINE__, kfse->refcount);
	    }

	    if (kfse->len == 0) {
		panic("%s:%d: no more fref.vp\n", __FILE__, __LINE__);
		// vnode_rele_ext(kfse->fref.vp, O_EVTONLY, 0);
	    } else {
		vfs_removename(kfse->str);
		kfse->len = 0;
	    }
	    kfse->str = NULL;

	    if (kfse->kevent_list.le_prev != NULL) {
		num_events_outstanding--;
		if (kfse->type == FSE_RENAME) {
		    num_pending_rename--;
		}
		LIST_REMOVE(kfse, kevent_list);
		memset(&kfse->kevent_list, 0, sizeof(kfse->kevent_list));
	    }

	    kfse->flags = 0 | KFSE_RECYCLED_EVENT;
	    
	    if (kfse_dest) {
		OSAddAtomic(1, (SInt32 *)&kfse_dest->refcount);
		kfse_dest->flags = 0 | KFSE_RECYCLED_EVENT;

		if (did_alloc == 0) {
		    if (kfse_dest->len == 0) {
			panic("%s:%d: no more fref.vp\n", __FILE__, __LINE__);
			// vnode_rele_ext(kfse_dest->fref.vp, O_EVTONLY, 0);
		    } else {
			vfs_removename(kfse_dest->str);
			kfse_dest->len = 0;
		    }
		    kfse_dest->str = NULL;

		    if (kfse_dest->kevent_list.le_prev != NULL) {
			num_events_outstanding--;
			LIST_REMOVE(kfse_dest, kevent_list);
			memset(&kfse_dest->kevent_list, 0, sizeof(kfse_dest->kevent_list));
		    }

		    if (kfse_dest->dest) {
			panic("add_fsevent: should never recycle a rename event! kfse %p\n", kfse);
		    }
		}
	    }

	    OSBitOrAtomic16(KFSE_BEING_CREATED, &kfse->flags);
	    if (kfse_dest) {
		OSBitOrAtomic16(KFSE_BEING_CREATED, &kfse_dest->flags);
	    }

	    goto process_normally;
	}
    }

    if (reuse_type != 0) {
	panic("fsevents: we have a reuse_type (%d) but are about to clear out kfse %p\n", reuse_type, kfse);
    }

    //
    // we only want to do this for brand new events, not
    // events which have been recycled.
    //
    memset(kfse, 0, sizeof(kfs_event));
    kfse->refcount = 1;
    OSBitOrAtomic16(KFSE_BEING_CREATED, &kfse->flags);

  process_normally:
    kfse->type     = type;
    kfse->abstime  = now;
    kfse->pid      = p->p_pid;
    if (type == FSE_RENAME || type == FSE_EXCHANGE) {
	if (need_event_unlock == 0) {
	    memset(kfse_dest, 0, sizeof(kfs_event));
	    kfse_dest->refcount = 1;
	    OSBitOrAtomic16(KFSE_BEING_CREATED, &kfse_dest->flags);
	}
	kfse_dest->type     = type;
	kfse_dest->pid      = p->p_pid;
	kfse_dest->abstime  = now;
	
	kfse->dest = kfse_dest;
    }
    
    num_events_outstanding++;
    if (kfse->type == FSE_RENAME) {
	num_pending_rename++;
    }
    LIST_INSERT_HEAD(&kfse_list_head, kfse, kevent_list);

    if (kfse->refcount < 1) {
	panic("add_fsevent: line %d: kfse recount %d but should be at least 1\n", __LINE__, kfse->refcount);
    }

    unlock_fs_event_list();  // at this point it's safe to unlock

    //
    // now process the arguments passed in and copy them into
    // the kfse
    //
    if (need_event_unlock == 0) {
	lck_rw_lock_shared(&event_handling_lock);
    }
    
    cur = kfse;
    for(arg_type=va_arg(ap, int32_t); arg_type != FSE_ARG_DONE; arg_type=va_arg(ap, int32_t))

	switch(arg_type) {
	    case FSE_ARG_VNODE: {
		// this expands out into multiple arguments to the client
		struct vnode *vp;
		struct vnode_attr va;

		if (kfse->str != NULL) {
		    cur = kfse_dest;
		}

		vp = va_arg(ap, struct vnode *);
		if (vp == NULL) {
		    panic("add_fsevent: you can't pass me a NULL vnode ptr (type %d)!\n",
			  cur->type);
		}

		VATTR_INIT(&va);
		VATTR_WANTED(&va, va_fsid);
		VATTR_WANTED(&va, va_fileid);
		VATTR_WANTED(&va, va_mode);
		VATTR_WANTED(&va, va_uid);
		VATTR_WANTED(&va, va_gid);
		if ((ret = vnode_getattr(vp, &va, ctx)) != 0) {
		    // printf("add_fsevent: failed to getattr on vp %p (%d)\n", cur->fref.vp, ret);
		    cur->str = NULL;
		    error = EINVAL;
		    if (need_event_unlock == 0) {
			// then we only grabbed it shared 
			lck_rw_unlock_shared(&event_handling_lock);
		    }
		    goto clean_up;
		}

		cur->dev  = dev = (dev_t)va.va_fsid;
		cur->ino  = (ino_t)va.va_fileid;
		cur->mode = (int32_t)vnode_vttoif(vnode_vtype(vp)) | va.va_mode;
		cur->uid  = va.va_uid;
		cur->gid  = va.va_gid;

		// if we haven't gotten the path yet, get it.
		if (pathbuff == NULL) {
		    pathbuff = get_pathbuff();
		    pathbuff_len = MAXPATHLEN;
		    
		    pathbuff[0] = '\0';
		    if (vn_getpath(vp, pathbuff, &pathbuff_len) != 0 || pathbuff[0] == '\0') {
			printf("add_fsevent: no name hard-link! dropping the event. (event %d vp == %p (%s)). \n",
			       type, vp, vp->v_name ? vp->v_name : "-UNKNOWN-FILE");
			error = ENOENT;
			release_pathbuff(pathbuff);
			pathbuff = NULL;
			if (need_event_unlock == 0) {
			    // then we only grabbed it shared 
			    lck_rw_unlock_shared(&event_handling_lock);
			}
			goto clean_up;
		    }
		}

		// store the path by adding it to the global string table
		cur->len = pathbuff_len;
		cur->str = vfs_addname(pathbuff, pathbuff_len, 0, 0);
		if (cur->str == NULL || cur->str[0] == '\0') {
		    panic("add_fsevent: was not able to add path %s to event %p.\n", pathbuff, cur);
		}
		
		release_pathbuff(pathbuff);
		pathbuff = NULL;

		break;
	    }

	    case FSE_ARG_FINFO: {
		fse_info *fse;
		
		fse = va_arg(ap, fse_info *);
		
		cur->dev  = dev = (dev_t)fse->dev;
		cur->ino  = (ino_t)fse->ino;
		cur->mode = (int32_t)fse->mode;
		cur->uid  = (uid_t)fse->uid;
		cur->gid  = (uid_t)fse->gid;
		// if it's a hard-link and this is the last link, flag it
		if ((fse->mode & FSE_MODE_HLINK) && fse->nlink == 0) {
		    cur->mode |= FSE_MODE_LAST_HLINK;
		}
		break;
	    }

	    case FSE_ARG_STRING:
		if (kfse->str != NULL) {
		    cur = kfse_dest;
		}

		cur->len = (int16_t)(va_arg(ap, int32_t) & 0x7fff);
		if (cur->len >= 1) {
		    cur->str = vfs_addname(va_arg(ap, char *), cur->len, 0, 0);
		} else {
		    printf("add_fsevent: funny looking string length: %d\n", (int)cur->len);
		    cur->len = 2;
		    cur->str = vfs_addname("/", cur->len, 0, 0);
		}
		if (cur->str[0] == 0) {
		    printf("add_fsevent: bogus looking string (len %d)\n", cur->len);
		}
		break;

	    default:
		printf("add_fsevent: unknown type %d\n", arg_type);
		// just skip one 32-bit word and hope we sync up...
		(void)va_arg(ap, int32_t);
	}

    va_end(ap);

    OSBitAndAtomic16(~KFSE_BEING_CREATED, &kfse->flags);
    if (kfse_dest) {
	OSBitAndAtomic16(~KFSE_BEING_CREATED, &kfse_dest->flags);
    }

    if (need_event_unlock == 0) {
	// then we only grabbed it shared 
	lck_rw_unlock_shared(&event_handling_lock);
    }
    
  normal_delivery:
    // unlock this here so we don't hold it across the
    // event delivery loop.
    if (need_event_unlock) {
	lck_rw_unlock_exclusive(&event_handling_lock);
	need_event_unlock = 0;
    }

    //
    // now we have to go and let everyone know that
    // is interested in this type of event
    //
    lock_watch_table();
    
    for(i=0; i < MAX_WATCHERS; i++) {
	watcher = watcher_table[i];
	if (watcher == NULL) {
	    continue;
	}
	
	if (   watcher->event_list[type] == FSE_REPORT
	    && watcher_cares_about_dev(watcher, dev)) {
	    
	    if (watcher_add_event(watcher, kfse) != 0) {
		watcher->num_dropped++;
	    }
	}

	if (kfse->refcount < 1) {
	    panic("add_fsevent: line %d: kfse recount %d but should be at least 1\n", __LINE__, kfse->refcount);
	}
    }

    unlock_watch_table();

  clean_up:
    // have to check if this needs to be unlocked (in
    // case we came here from an error handling path)
    if (need_event_unlock) {
	lck_rw_unlock_exclusive(&event_handling_lock);
	need_event_unlock = 0;
    }

    if (pathbuff) {
	release_pathbuff(pathbuff);
	pathbuff = NULL;
    }

    release_event_ref(kfse);

    return error;
}


static void
release_event_ref(kfs_event *kfse)
{
    int old_refcount;
    kfs_event copy, dest_copy;
    
    
    old_refcount = OSAddAtomic(-1, (SInt32 *)&kfse->refcount);
    if (old_refcount > 1) {
	return;
    }

    lock_fs_event_list();
    if (kfse->refcount < 0) {
	panic("release_event_ref: bogus kfse refcount %d\n", kfse->refcount);
    }

    if (kfse->refcount > 0 || kfse->type == FSE_INVALID) {
	// This is very subtle.  Either of these conditions can
	// be true if an event got recycled while we were waiting
	// on the fs_event_list lock or the event got recycled,
	// delivered, _and_ free'd by someone else while we were
	// waiting on the fs event list lock.  In either case
	// we need to just unlock the list and return without
	// doing anything because if the refcount is > 0 then
	// someone else will take care of free'ing it and when
	// the kfse->type is invalid then someone else already
	// has handled free'ing the event (while we were blocked
	// on the event list lock).
	//
	unlock_fs_event_list();
	return;
    }

    //
    // make a copy of this so we can free things without
    // holding the fs_event_buf lock
    //
    copy = *kfse;
    if (kfse->dest && OSAddAtomic(-1, (SInt32 *)&kfse->dest->refcount) == 1) {
	dest_copy = *kfse->dest;
    } else {
	dest_copy.str  = NULL;
	dest_copy.len  = 0;
	dest_copy.type = FSE_INVALID;
    }

    kfse->pid = kfse->type;             // save this off for debugging...
    kfse->uid = (uid_t)kfse->str;       // save this off for debugging...
    kfse->gid = (gid_t)current_thread();

    kfse->str = (char *)0xdeadbeef;             // XXXdbg - catch any cheaters...

    if (dest_copy.type != FSE_INVALID) {
	kfse->dest->str = (char *)0xbadc0de;   // XXXdbg - catch any cheaters...
	kfse->dest->type = FSE_INVALID;

	if (kfse->dest->kevent_list.le_prev != NULL) {
	    num_events_outstanding--;
	    LIST_REMOVE(kfse->dest, kevent_list);
	    memset(&kfse->dest->kevent_list, 0xa5, sizeof(kfse->dest->kevent_list));
	}

	zfree(event_zone, kfse->dest);
    }

    // mark this fsevent as invalid
    {
	int otype;
	
	otype = kfse->type;
    kfse->type = FSE_INVALID;

    if (kfse->kevent_list.le_prev != NULL) {
	num_events_outstanding--;
	if (otype == FSE_RENAME) {
	    num_pending_rename--;
	}
	LIST_REMOVE(kfse, kevent_list);
	memset(&kfse->kevent_list, 0, sizeof(kfse->kevent_list));
    }
    }
    
    zfree(event_zone, kfse);
    
    unlock_fs_event_list();
    
    // if we have a pointer in the union
    if (copy.str) {
	if (copy.len == 0) {    // and it's not a string
	    panic("%s:%d: no more fref.vp!\n", __FILE__, __LINE__);
	    // vnode_rele_ext(copy.fref.vp, O_EVTONLY, 0);
	} else {                // else it's a string
	    vfs_removename(copy.str);
	}
    }

    if (dest_copy.type != FSE_INVALID && dest_copy.str) {
	if (dest_copy.len == 0) {
	    panic("%s:%d: no more fref.vp!\n", __FILE__, __LINE__);
	    // vnode_rele_ext(dest_copy.fref.vp, O_EVTONLY, 0);
	} else {
	    vfs_removename(dest_copy.str);
	}
    }
}


static int
add_watcher(int8_t *event_list, int32_t num_events, int32_t eventq_size, fs_event_watcher **watcher_out)
{
    int               i;
    fs_event_watcher *watcher;

    if (eventq_size <= 0 || eventq_size > 100*MAX_KFS_EVENTS) {
	eventq_size = MAX_KFS_EVENTS;
    }

    // Note: the event_queue follows the fs_event_watcher struct
    //       in memory so we only have to do one allocation
    MALLOC(watcher,
	   fs_event_watcher *,
	   sizeof(fs_event_watcher) + eventq_size * sizeof(kfs_event *),
	   M_TEMP, M_WAITOK);
    if (watcher == NULL) {
	return ENOMEM;
    }

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
    watcher->num_readers  = 0;
    watcher->fseh         = NULL;

    watcher->num_dropped  = 0;      // XXXdbg - debugging

    lock_watch_table();

    // now update the global list of who's interested in
    // events of a particular type...
    for(i=0; i < num_events; i++) {
	if (event_list[i] != FSE_IGNORE && i < FSE_MAX_EVENTS) {
	    fs_event_type_watchers[i]++;
	}
    }

    for(i=0; i < MAX_WATCHERS; i++) {
	if (watcher_table[i] == NULL) {
	    watcher->my_id   = i;
	    watcher_table[i] = watcher;
	    break;
	}
    }

    if (i > MAX_WATCHERS) {
	printf("fsevents: too many watchers!\n");
	unlock_watch_table();
	return ENOSPC;
    }

    unlock_watch_table();

    *watcher_out = watcher;

    return 0;
}



static void
remove_watcher(fs_event_watcher *target)
{
    int i, j, counter=0;
    fs_event_watcher *watcher;
    kfs_event *kfse;
    
    lock_watch_table();
    
    for(j=0; j < MAX_WATCHERS; j++) {
	watcher = watcher_table[j];
	if (watcher != target) {
	    continue;
	}

	watcher_table[j] = NULL;

	for(i=0; i < watcher->num_events; i++) {
	    if (watcher->event_list[i] != FSE_IGNORE && i < FSE_MAX_EVENTS) {
		fs_event_type_watchers[i]--;
	    }
	}

	if (watcher->flags & WATCHER_CLOSING) {
	    unlock_watch_table();
	    return;
	}

	// printf("fsevents: removing watcher %p (rd %d wr %d num_readers %d flags 0x%x)\n", watcher, watcher->rd, watcher->wr, watcher->num_readers, watcher->flags);
	watcher->flags |= WATCHER_CLOSING;
	OSAddAtomic(1, (SInt32 *)&watcher->num_readers);
	
	unlock_watch_table();
	    
	while (watcher->num_readers > 1 && counter++ < 5000) {
	    fsevents_wakeup(watcher);      // in case they're asleep
	    
	    tsleep(watcher, PRIBIO, "fsevents-close", 1);
	}
	if (counter++ >= 5000) {
	    // printf("fsevents: close: still have readers! (%d)\n", watcher->num_readers);
	    panic("fsevents: close: still have readers! (%d)\n", watcher->num_readers);
	}

	// drain the event_queue 
	while(watcher->rd != watcher->wr) {
	    lck_rw_lock_shared(&event_handling_lock);

	    kfse = watcher->event_queue[watcher->rd];
	    if (kfse->type == FSE_INVALID || kfse->refcount < 1) {
		panic("remove_watcher: bogus kfse %p during cleanup (type %d refcount %d rd %d wr %d)\n", kfse, kfse->type, kfse->refcount, watcher->rd, watcher->wr);
	    }

	    lck_rw_unlock_shared(&event_handling_lock);
	    
	    watcher->rd = (watcher->rd+1) % watcher->eventq_size;

	    if (kfse != NULL) {
		release_event_ref(kfse);
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

	return;
    }

    unlock_watch_table();
}


#define EVENT_DELAY_IN_MS   10
static thread_call_t event_delivery_timer = NULL;
static int timer_set = 0;


static void
delayed_event_delivery(__unused void *param0, __unused void *param1)
{
    int i;
    
    lock_watch_table();

    for(i=0; i < MAX_WATCHERS; i++) {
	if (watcher_table[i] != NULL && watcher_table[i]->rd != watcher_table[i]->wr) {
	    fsevents_wakeup(watcher_table[i]);
	}
    }

    timer_set = 0;

    unlock_watch_table();
}


//
// The watch table must be locked before calling this function.
//
static void
schedule_event_wakeup(void)
{
    uint64_t deadline;
    
    if (event_delivery_timer == NULL) {
	event_delivery_timer = thread_call_allocate((thread_call_func_t)delayed_event_delivery, NULL);
    }

    clock_interval_to_deadline(EVENT_DELAY_IN_MS, 1000 * 1000, &deadline);
    
    thread_call_enter_delayed(event_delivery_timer, deadline);
    timer_set = 1;
}



#define MAX_NUM_PENDING  16

//
// NOTE: the watch table must be locked before calling
//       this routine.
//
static int
watcher_add_event(fs_event_watcher *watcher, kfs_event *kfse)
{
    if (((watcher->wr + 1) % watcher->eventq_size) == watcher->rd) {
	watcher->flags |= WATCHER_DROPPED_EVENTS;
	fsevents_wakeup(watcher);
	return ENOSPC;
    }

    OSAddAtomic(1, (SInt32 *)&kfse->refcount);
    watcher->event_queue[watcher->wr] = kfse;
    OSSynchronizeIO();
    watcher->wr = (watcher->wr + 1) % watcher->eventq_size;
    
    //
    // wake up the watcher if there are more than MAX_NUM_PENDING events.
    // otherwise schedule a timer (if one isn't already set) which will 
    // send any pending events if no more are received in the next 
    // EVENT_DELAY_IN_MS milli-seconds.
    //
    if (   (watcher->rd < watcher->wr && (watcher->wr - watcher->rd) > MAX_NUM_PENDING)
	|| (watcher->rd > watcher->wr && (watcher->wr + watcher->eventq_size - watcher->rd) > MAX_NUM_PENDING)) {

	fsevents_wakeup(watcher);

    } else if (timer_set == 0) {

	schedule_event_wakeup();
    }

    return 0;
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

static int
fill_buff(uint16_t type, int32_t size, const void *data,
          char *buff, int32_t *_buff_idx, int32_t buff_sz,
          struct uio *uio)
{
    int32_t amt, error = 0, buff_idx = *_buff_idx;
    uint16_t tmp;
    
    //
    // the +1 on the size is to guarantee that the main data
    // copy loop will always copy at least 1 byte
    //
    if ((buff_sz - buff_idx) <= (int)(2*sizeof(uint16_t) + 1)) {
	if (buff_idx > uio_resid(uio)) {
	    error = ENOSPC;
	    goto get_out;
	}

	error = uiomove(buff, buff_idx, uio);
	if (error) {
	    goto get_out;
	}
	buff_idx = 0;
    }

    // copy out the header (type & size)
    memcpy(&buff[buff_idx], &type, sizeof(uint16_t));
    buff_idx += sizeof(uint16_t);
    
    tmp = size & 0xffff;
    memcpy(&buff[buff_idx], &tmp, sizeof(uint16_t));
    buff_idx += sizeof(uint16_t);
    
    // now copy the body of the data, flushing along the way 
    // if the buffer fills up.
    //
    while(size > 0) {
	amt = (size < (buff_sz - buff_idx)) ? size : (buff_sz - buff_idx);
	memcpy(&buff[buff_idx], data, amt);

	size -= amt;
	buff_idx += amt;
	data = (const char *)data + amt;
	if (size > (buff_sz - buff_idx)) {
	    if (buff_idx > uio_resid(uio)) {
		error = ENOSPC;
		goto get_out;
	    }
	    error = uiomove(buff, buff_idx, uio);
	    if (error) {
		goto get_out;
	    }
	    buff_idx = 0;
	}

	if (amt == 0) {   // just in case...
	    break;
	}
    }

  get_out:
    *_buff_idx = buff_idx;
    
    return error;
}


static int copy_out_kfse(fs_event_watcher *watcher, kfs_event *kfse, struct uio *uio)  __attribute__((noinline));

static int
copy_out_kfse(fs_event_watcher *watcher, kfs_event *kfse, struct uio *uio)
{
    int      error;
    uint16_t tmp16;
    int32_t  type;
    kfs_event *cur;
    char     evbuff[512];
    int      evbuff_idx = 0;

    if (kfse->type == FSE_INVALID) {
	panic("fsevents: copy_out_kfse: asked to copy out an invalid event (kfse %p, refcount %d fref ptr %p)\n", kfse, kfse->refcount, kfse->str);
    }

    if (kfse->flags & KFSE_BEING_CREATED) {
	return 0;
    }

    if (kfse->type == FSE_RENAME && kfse->dest == NULL) {
	//
	// This can happen if an event gets recycled but we had a
	// pointer to it in our event queue.  The event is the
	// destination of a rename which we'll process separately
	// (that is, another kfse points to this one so it's ok
	// to skip this guy because we'll process it when we process
	// the other one)
	error = 0;
	goto get_out;
    }

    if (watcher->flags & WATCHER_WANTS_EXTENDED_INFO) {

	type = (kfse->type & 0xfff);

	if (kfse->flags & KFSE_CONTAINS_DROPPED_EVENTS) {
	    type |= (FSE_CONTAINS_DROPPED_EVENTS << FSE_FLAG_SHIFT);
	} else if (kfse->flags & KFSE_COMBINED_EVENTS) {
	    type |= (FSE_COMBINED_EVENTS << FSE_FLAG_SHIFT);
	}

    } else {
	type = (int32_t)kfse->type;
    }

    // copy out the type of the event
    memcpy(evbuff, &type, sizeof(int32_t));
    evbuff_idx += sizeof(int32_t);

    // copy out the pid of the person that generated the event
    memcpy(&evbuff[evbuff_idx], &kfse->pid, sizeof(pid_t));
    evbuff_idx += sizeof(pid_t);

    cur = kfse;

  copy_again:

    if (cur->str == NULL || cur->str[0] == '\0') {
	printf("copy_out_kfse:2: empty/short path (%s)\n", cur->str);
	error = fill_buff(FSE_ARG_STRING, 2, "/", evbuff, &evbuff_idx, sizeof(evbuff), uio);
    } else {
	error = fill_buff(FSE_ARG_STRING, cur->len, cur->str, evbuff, &evbuff_idx, sizeof(evbuff), uio);
    }
    if (error != 0) {
	goto get_out;
    }

    if (cur->dev == 0 && cur->ino == 0) {
	// this happens when a rename event happens and the
	// destination of the rename did not previously exist.
	// it thus has no other file info so skip copying out
	// the stuff below since it isn't initialized
	goto done;
    }

    
    if (watcher->flags & WATCHER_WANTS_COMPACT_EVENTS) {
	int32_t finfo_size;
	
	finfo_size = sizeof(dev_t) + sizeof(ino64_t) + sizeof(int32_t) + sizeof(uid_t) + sizeof(gid_t);
	error = fill_buff(FSE_ARG_FINFO, finfo_size, &cur->ino, evbuff, &evbuff_idx, sizeof(evbuff), uio);
	if (error != 0) {
	    goto get_out;
	}
    } else {
	ino_t ino;
	
	error = fill_buff(FSE_ARG_DEV, sizeof(dev_t), &cur->dev, evbuff, &evbuff_idx, sizeof(evbuff), uio);
	if (error != 0) {
	    goto get_out;
	}

	ino = (ino_t)cur->ino;
	error = fill_buff(FSE_ARG_INO, sizeof(ino_t), &ino, evbuff, &evbuff_idx, sizeof(evbuff), uio);
	if (error != 0) {
	    goto get_out;
	}

	error = fill_buff(FSE_ARG_MODE, sizeof(int32_t), &cur->mode, evbuff, &evbuff_idx, sizeof(evbuff), uio);
	if (error != 0) {
	    goto get_out;
	}

	error = fill_buff(FSE_ARG_UID, sizeof(uid_t), &cur->uid, evbuff, &evbuff_idx, sizeof(evbuff), uio);
	if (error != 0) {
	    goto get_out;
	}

	error = fill_buff(FSE_ARG_GID, sizeof(gid_t), &cur->gid, evbuff, &evbuff_idx, sizeof(evbuff), uio);
	if (error != 0) {
	    goto get_out;
	}
    }


    if (cur->dest) {
	cur = cur->dest;
	goto copy_again;
    }

  done:
    // very last thing: the time stamp
    error = fill_buff(FSE_ARG_INT64, sizeof(uint64_t), &cur->abstime, evbuff, &evbuff_idx, sizeof(evbuff), uio);
    if (error != 0) {
	goto get_out;
    }

    // check if the FSE_ARG_DONE will fit
    if (sizeof(uint16_t) > sizeof(evbuff) - evbuff_idx) {
	if (evbuff_idx > uio_resid(uio)) {
	    error = ENOSPC;
	    goto get_out;
	}
	error = uiomove(evbuff, evbuff_idx, uio);
	if (error) {
	    goto get_out;
	}
	evbuff_idx = 0;
    }

    tmp16 = FSE_ARG_DONE;
    memcpy(&evbuff[evbuff_idx], &tmp16, sizeof(uint16_t));
    evbuff_idx += sizeof(uint16_t);

    // flush any remaining data in the buffer (and hopefully
    // in most cases this is the only uiomove we'll do)
    if (evbuff_idx > uio_resid(uio)) {
	error = ENOSPC;
    } else {
	error = uiomove(evbuff, evbuff_idx, uio);
    }

  get_out:

    return error;
}



static int
fmod_watch(fs_event_watcher *watcher, struct uio *uio)
{
    int               error=0, last_full_event_resid;
    kfs_event        *kfse;
    uint16_t          tmp16;

    // LP64todo - fix this
    last_full_event_resid = uio_resid(uio);

    // need at least 2048 bytes of space (maxpathlen + 1 event buf)
    if  (uio_resid(uio) < 2048 || watcher == NULL) {
	return EINVAL;
    }

    if (watcher->flags & WATCHER_CLOSING) {
	return 0;
    }

    if (OSAddAtomic(1, (SInt32 *)&watcher->num_readers) != 0) {
	// don't allow multiple threads to read from the fd at the same time
	OSAddAtomic(-1, (SInt32 *)&watcher->num_readers);
	return EAGAIN;
    }

    if (watcher->rd == watcher->wr) {
	if (watcher->flags & WATCHER_CLOSING) {
	    OSAddAtomic(-1, (SInt32 *)&watcher->num_readers);
	    return 0;
	}
	OSAddAtomic(1, (SInt32 *)&watcher->blockers);
    
	// there's nothing to do, go to sleep
	error = tsleep((caddr_t)watcher, PUSER|PCATCH, "fsevents_empty", 0);

	OSAddAtomic(-1, (SInt32 *)&watcher->blockers);

	if (error != 0 || (watcher->flags & WATCHER_CLOSING)) {
	    OSAddAtomic(-1, (SInt32 *)&watcher->num_readers);
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

	    // LP64todo - fix this
	    last_full_event_resid = uio_resid(uio);
	} 

	if (error) {
	    OSAddAtomic(-1, (SInt32 *)&watcher->num_readers);
	    return error;
	}
	
	watcher->flags &= ~WATCHER_DROPPED_EVENTS;
    }

    while (uio_resid(uio) > 0 && watcher->rd != watcher->wr) {
	if (watcher->flags & WATCHER_CLOSING) {
	    break;
	}
	
	//
	// check if the event is something of interest to us
	// (since it may have been recycled/reused and changed
	// its type or which device it is for)
	//
	lck_rw_lock_shared(&event_handling_lock);

	kfse = watcher->event_queue[watcher->rd];
	if (kfse->type == FSE_INVALID || kfse->refcount < 1) {
	    panic("fmod_watch: someone left me a bogus kfse %p (type %d refcount %d rd %d wr %d)\n", kfse, kfse->type, kfse->refcount, watcher->rd, watcher->wr);
	}

	if (watcher->event_list[kfse->type] == FSE_REPORT && watcher_cares_about_dev(watcher, kfse->dev)) {

	    error = copy_out_kfse(watcher, kfse, uio);
	    if (error != 0) {
		// if an event won't fit or encountered an error while
		// we were copying it out, then backup to the last full
		// event and just bail out.  if the error was ENOENT
		// then we can continue regular processing, otherwise
		// we should unlock things and return.
		uio_setresid(uio, last_full_event_resid);
		if (error != ENOENT) {
		    lck_rw_unlock_shared(&event_handling_lock);
		    error = 0;
		    goto get_out;
		}
	    }

	    // LP64todo - fix this
	    last_full_event_resid = uio_resid(uio);
	}

	lck_rw_unlock_shared(&event_handling_lock);

	watcher->rd = (watcher->rd + 1) % watcher->eventq_size;
	OSSynchronizeIO();
	    
	if (kfse->type == FSE_INVALID || kfse->refcount < 1) {
	    panic("fmod_watch:2: my kfse became bogus! kfse %p (type %d refcount %d rd %d wr %d)\n", kfse, kfse->type, kfse->refcount, watcher->rd, watcher->wr);
	}

	release_event_ref(kfse);
    }

  get_out:
    OSAddAtomic(-1, (SInt32 *)&watcher->num_readers);

    return error;
}


// release any references we might have on vnodes which are 
// the mount point passed to us (so that it can be cleanly
// unmounted).
//
// since we don't want to lose the events we'll convert the
// vnode refs to full paths.
//
void
fsevent_unmount(__unused struct mount *mp)
{
    // we no longer maintain pointers to vnodes so
    // there is nothing to do... 
}


//
// /dev/fsevents device code
//
static int fsevents_installed = 0;

typedef struct fsevent_handle {
    UInt32            flags;
    SInt32            active;
    fs_event_watcher *watcher;
    struct selinfo    si;
} fsevent_handle;

#define FSEH_CLOSING   0x0001

static int
fseventsf_read(struct fileproc *fp, struct uio *uio,
	       __unused int flags, __unused vfs_context_t ctx)
{
    fsevent_handle *fseh = (struct fsevent_handle *)fp->f_fglob->fg_data;
    int error;

    error = fmod_watch(fseh->watcher, uio);

    return error;
}


static int
fseventsf_write(__unused struct fileproc *fp, __unused struct uio *uio,
		__unused int flags, __unused vfs_context_t ctx)
{
    return EIO;
}

typedef struct ext_fsevent_dev_filter_args {
    uint32_t    num_devices;
    user_addr_t devices;
} ext_fsevent_dev_filter_args;

typedef struct old_fsevent_dev_filter_args {
    uint32_t  num_devices;
    int32_t   devices;
} old_fsevent_dev_filter_args;

#define	OLD_FSEVENTS_DEVICE_FILTER	_IOW('s', 100, old_fsevent_dev_filter_args)
#define	NEW_FSEVENTS_DEVICE_FILTER	_IOW('s', 100, ext_fsevent_dev_filter_args)


static int
fseventsf_ioctl(struct fileproc *fp, u_long cmd, caddr_t data, vfs_context_t ctx)
{
    fsevent_handle *fseh = (struct fsevent_handle *)fp->f_fglob->fg_data;
    int ret = 0;
    ext_fsevent_dev_filter_args *devfilt_args, _devfilt_args;

    if (proc_is64bit(vfs_context_proc(ctx))) {
	devfilt_args = (ext_fsevent_dev_filter_args *)data;
    } else if (cmd == OLD_FSEVENTS_DEVICE_FILTER) {
	old_fsevent_dev_filter_args *udev_filt_args = (old_fsevent_dev_filter_args *)data;
	
	devfilt_args = &_devfilt_args;
	memset(devfilt_args, 0, sizeof(ext_fsevent_dev_filter_args));

	devfilt_args->num_devices = udev_filt_args->num_devices;
	devfilt_args->devices     = CAST_USER_ADDR_T(udev_filt_args->devices);
    } else {
	fsevent_dev_filter_args *udev_filt_args = (fsevent_dev_filter_args *)data;
	
	devfilt_args = &_devfilt_args;
	memset(devfilt_args, 0, sizeof(ext_fsevent_dev_filter_args));

	devfilt_args->num_devices = udev_filt_args->num_devices;
	devfilt_args->devices     = CAST_USER_ADDR_T(udev_filt_args->devices);
    }

    OSAddAtomic(1, &fseh->active);
    if (fseh->flags & FSEH_CLOSING) {
	OSAddAtomic(-1, &fseh->active);
	return 0;
    }

    switch (cmd) {
	case FIONBIO:
	case FIOASYNC:
	    break;

	case FSEVENTS_WANT_COMPACT_EVENTS: {
	    fseh->watcher->flags |= WATCHER_WANTS_COMPACT_EVENTS;
	    break;
	}

	case FSEVENTS_WANT_EXTENDED_INFO: {
	    fseh->watcher->flags |= WATCHER_WANTS_EXTENDED_INFO;
	    break;
	}

	case OLD_FSEVENTS_DEVICE_FILTER:
	case NEW_FSEVENTS_DEVICE_FILTER: {
	    int new_num_devices;
	    dev_t *devices_to_watch, *tmp=NULL;
	    
	    if (devfilt_args->num_devices > 256) {
		ret = EINVAL;
		break;
	    }
	    
	    new_num_devices = devfilt_args->num_devices;
	    if (new_num_devices == 0) {
		tmp = fseh->watcher->devices_to_watch;

		lock_watch_table();
		fseh->watcher->devices_to_watch = NULL;
		fseh->watcher->num_devices = new_num_devices;
		unlock_watch_table();

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
    
	    ret = copyin(devfilt_args->devices,
			 (void *)devices_to_watch,
			 new_num_devices * sizeof(dev_t));
	    if (ret) {
		FREE(devices_to_watch, M_TEMP);
		break;
	    }

	    lock_watch_table();
	    fseh->watcher->num_devices = new_num_devices;
	    tmp = fseh->watcher->devices_to_watch;
	    fseh->watcher->devices_to_watch = devices_to_watch;
	    unlock_watch_table();

	    if (tmp) {
		FREE(tmp, M_TEMP);
	    }
	    
	    break;
	}	    

	default:
	    ret = EINVAL;
	    break;
    }

    OSAddAtomic(-1, &fseh->active);
    return (ret);
}


static int
fseventsf_select(struct fileproc *fp, int which, __unused void *wql, vfs_context_t ctx)
{
    fsevent_handle *fseh = (struct fsevent_handle *)fp->f_fglob->fg_data;
    int ready = 0;

    if ((which != FREAD) || (fseh->watcher->flags & WATCHER_CLOSING)) {
	return 0;
    }


    // if there's nothing in the queue, we're not ready
    if (fseh->watcher->rd != fseh->watcher->wr) {
	ready = 1;
    }

    if (!ready) {
	selrecord(vfs_context_proc(ctx), &fseh->si, wql);
    }

    return ready;
}


#if NOTUSED
static int
fseventsf_stat(__unused struct fileproc *fp, __unused struct stat *sb, __unused vfs_context_t ctx)
{
    return ENOTSUP;
}
#endif

static int
fseventsf_close(struct fileglob *fg, __unused vfs_context_t ctx)
{
    fsevent_handle *fseh = (struct fsevent_handle *)fg->fg_data;
    fs_event_watcher *watcher;

    OSBitOrAtomic(FSEH_CLOSING, &fseh->flags);
    while (OSAddAtomic(0, &fseh->active) > 0) {
	tsleep((caddr_t)fseh->watcher, PRIBIO, "fsevents-close", 1);
    }

    watcher = fseh->watcher;
    fg->fg_data = NULL;
    fseh->watcher = NULL;

    remove_watcher(watcher);
    FREE(fseh, M_TEMP);

    return 0;
}

static int
fseventsf_kqfilter(__unused struct fileproc *fp, __unused struct knote *kn, __unused vfs_context_t ctx)
{
    // XXXdbg
    return 0;
}


static int
fseventsf_drain(struct fileproc *fp, __unused vfs_context_t ctx)
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
	fsevents_wakeup(fseh->watcher);

	tsleep((caddr_t)fseh->watcher, PRIBIO, "watcher-close", 1);
    }

    return 0;
}


static int
fseventsopen(__unused dev_t dev, __unused int flag, __unused int mode, __unused struct proc *p)
{
    if (!is_suser()) {
	return EPERM;
    }
    
    return 0;
}

static int
fseventsclose(__unused dev_t dev, __unused int flag, __unused int mode, __unused struct proc *p)
{
    return 0;
}

static int
fseventsread(__unused dev_t dev, __unused struct uio *uio, __unused int ioflag)
{
    return EIO;
}


static int
parse_buffer_and_add_events(const char *buffer, int bufsize, vfs_context_t ctx, long *remainder)
{
    const fse_info *finfo, *dest_finfo;
    const char *path, *ptr, *dest_path, *event_start=buffer;
    int path_len, type, dest_path_len, err = 0;


    ptr = buffer;
    while ((ptr+sizeof(int)+sizeof(fse_info)+1) < buffer+bufsize) {
	type = *(const int *)ptr;
	if (type < 0 || type >= FSE_MAX_EVENTS) {
	    err = EINVAL;
	    break;
	}

	ptr += sizeof(int);
	
	finfo = (const fse_info *)ptr;
	ptr += sizeof(fse_info);

	path = ptr;
	while(ptr < buffer+bufsize && *ptr != '\0') {
	    ptr++;
	}

	if (ptr >= buffer+bufsize) {
	    break;
	}

	ptr++;   // advance over the trailing '\0'

	path_len = ptr - path;

	if (type != FSE_RENAME && type != FSE_EXCHANGE) {
	    event_start = ptr;   // record where the next event starts

	    err = add_fsevent(type, ctx, FSE_ARG_STRING, path_len, path, FSE_ARG_FINFO, finfo, FSE_ARG_DONE);
	    if (err) {
		break;
	    }
	    continue;
	}

	//
	// if we're here we have to slurp up the destination finfo
	// and path so that we can pass them to the add_fsevent()
	// call.  basically it's a copy of the above code.
	//
	dest_finfo = (const fse_info *)ptr;
	ptr += sizeof(fse_info);

	dest_path = ptr;
	while(ptr < buffer+bufsize && *ptr != '\0') {
	    ptr++;
	}

	if (ptr >= buffer+bufsize) {
	    break;
	}

	ptr++;               // advance over the trailing '\0'
	event_start = ptr;   // record where the next event starts

	dest_path_len = ptr - dest_path;
	err = add_fsevent(type, ctx,
	                  FSE_ARG_STRING, path_len,      path,      FSE_ARG_FINFO, finfo,
	                  FSE_ARG_STRING, dest_path_len, dest_path, FSE_ARG_FINFO, dest_finfo,
	                  FSE_ARG_DONE);
	if (err) {
	    break;
	}

    }

    // if the last event wasn't complete, set the remainder
    // to be the last event start boundary.
    //
    *remainder = (long)((buffer+bufsize) - event_start);

    return err;
}


//
// Note: this buffer size can not ever be less than
//       2*MAXPATHLEN + 2*sizeof(fse_info) + sizeof(int)
//       because that is the max size for a single event.
//       I made it 4k to be a "nice" size.  making it
//       smaller is not a good idea.
//
#define WRITE_BUFFER_SIZE  4096
char *write_buffer=NULL;

static int
fseventswrite(__unused dev_t dev, struct uio *uio, __unused int ioflag)
{
    int error=0, count;
    vfs_context_t ctx = vfs_context_current();
    long offset=0, remainder;

    lck_mtx_lock(&event_writer_lock);

    if (write_buffer == NULL) {
	if (kmem_alloc(kernel_map, (vm_offset_t *)&write_buffer, WRITE_BUFFER_SIZE)) {
	    lck_mtx_unlock(&event_writer_lock);
	    return ENOMEM;
	}
    }

    //
    // this loop copies in and processes the events written.
    // it takes care to copy in reasonable size chunks and
    // process them.  if there is an event that spans a chunk
    // boundary we're careful to copy those bytes down to the
    // beginning of the buffer and read the next chunk in just
    // after it.
    //
    while(uio_resid(uio)) {
	if (uio_resid(uio) > (WRITE_BUFFER_SIZE-offset)) {
	    count = WRITE_BUFFER_SIZE - offset;
	} else {
	    count = uio_resid(uio);
	}

	error = uiomove(write_buffer+offset, count, uio);
	if (error) {
	    break;
	}

	// printf("fsevents: write: copied in %d bytes (offset: %ld)\n", count, offset);
	error = parse_buffer_and_add_events(write_buffer, offset+count, ctx, &remainder);
	if (error) {
	    break;
	}	    

	//
	// if there's any remainder, copy it down to the beginning
	// of the buffer so that it will get processed the next time
	// through the loop.  note that the remainder always starts
	// at an event boundary.
	//
	if (remainder != 0) {
	    // printf("fsevents: write: an event spanned a %d byte boundary.  remainder: %ld\n",
	    //	WRITE_BUFFER_SIZE, remainder);
	    memmove(write_buffer, (write_buffer+count+offset) - remainder, remainder);
	    offset = remainder;
	} else {
	    offset = 0;
	}
    }

    lck_mtx_unlock(&event_writer_lock);

    return error;
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

typedef struct ext_fsevent_clone_args {
    user_addr_t  event_list;
    int32_t      num_events;
    int32_t      event_queue_depth;
    user_addr_t  fd;
} ext_fsevent_clone_args;

typedef struct old_fsevent_clone_args {
    int32_t  event_list;
    int32_t  num_events;
    int32_t  event_queue_depth;
    int32_t  fd;
} old_fsevent_clone_args;

#define	OLD_FSEVENTS_CLONE	_IOW('s', 1, old_fsevent_clone_args)

static int
fseventsioctl(__unused dev_t dev, u_long cmd, caddr_t data, __unused int flag, struct proc *p)
{
    struct fileproc *f;
    int fd, error;
    fsevent_handle *fseh = NULL;
    ext_fsevent_clone_args *fse_clone_args, _fse_clone;
    int8_t *event_list;
    int is64bit = proc_is64bit(p);

    switch (cmd) {
	case OLD_FSEVENTS_CLONE: {
	    old_fsevent_clone_args *old_args = (old_fsevent_clone_args *)data;

	    fse_clone_args = &_fse_clone;
	    memset(fse_clone_args, 0, sizeof(ext_fsevent_clone_args));

	    fse_clone_args->event_list        = CAST_USER_ADDR_T(old_args->event_list);
	    fse_clone_args->num_events        = old_args->num_events;
	    fse_clone_args->event_queue_depth = old_args->event_queue_depth;
	    fse_clone_args->fd                = CAST_USER_ADDR_T(old_args->fd);
	    goto handle_clone;
	}
	    
	case FSEVENTS_CLONE:
	    if (is64bit) {
		fse_clone_args = (ext_fsevent_clone_args *)data;
	    } else {
		fsevent_clone_args *ufse_clone = (fsevent_clone_args *)data;
		
		fse_clone_args = &_fse_clone;
		memset(fse_clone_args, 0, sizeof(ext_fsevent_clone_args));

		fse_clone_args->event_list        = CAST_USER_ADDR_T(ufse_clone->event_list);
		fse_clone_args->num_events        = ufse_clone->num_events;
		fse_clone_args->event_queue_depth = ufse_clone->event_queue_depth;
		fse_clone_args->fd                = CAST_USER_ADDR_T(ufse_clone->fd);
	    }

	handle_clone:
	    if (fse_clone_args->num_events < 0 || fse_clone_args->num_events > 4096) {
		return EINVAL;
	    }

	    MALLOC(fseh, fsevent_handle *, sizeof(fsevent_handle),
		   M_TEMP, M_WAITOK);
	    if (fseh == NULL) {
		return ENOMEM;
	    }
	    memset(fseh, 0, sizeof(fsevent_handle));

	    MALLOC(event_list, int8_t *,
		   fse_clone_args->num_events * sizeof(int8_t),
		   M_TEMP, M_WAITOK);
	    if (event_list == NULL) {
		FREE(fseh, M_TEMP);
		return ENOMEM;
	    }
    
	    error = copyin(fse_clone_args->event_list,
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

	    // connect up the watcher with this fsevent_handle
	    fseh->watcher->fseh = fseh;

	    error = falloc(p, &f, &fd, vfs_context_current());
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
	    error = copyout((void *)&fd, fse_clone_args->fd, sizeof(int32_t));
	    if (error != 0) {
		fp_free(p, fd, f);
	    } else {
		proc_fdlock(p);
		procfdtbl_releasefd(p, fd, NULL);
		fp_drop(p, fd, f, 1);
		proc_fdunlock(p);
	    }
	    break;

	default:
	    error = EINVAL;
	    break;
    }

    return error;
}

static void
fsevents_wakeup(fs_event_watcher *watcher)
{
    wakeup((caddr_t)watcher);
    selwakeup(&watcher->fseh->si);
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
    (stop_fcn_t *)&nulldev,	/* stop */
    (reset_fcn_t *)&nulldev,	/* reset */
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
    if (vp->v_flag & VISHARDLINK) {
	if (vp->v_type == VDIR) {
	    VATTR_WANTED(&va, va_dirlinkcount);
	} else {
	    VATTR_WANTED(&va, va_nlink);
	}
    }
    
    if (vnode_getattr(vp, &va, ctx) != 0) {
	memset(fse, 0, sizeof(fse_info));
	return -1;
    }
    
    fse->ino  = (ino64_t)va.va_fileid;
    fse->dev  = (dev_t)va.va_fsid;
    fse->mode = (int32_t)vnode_vttoif(vnode_vtype(vp)) | va.va_mode;
    fse->uid  = (uid_t)va.va_uid;
    fse->gid  = (gid_t)va.va_gid;
    if (vp->v_flag & VISHARDLINK) {
	fse->mode |= FSE_MODE_HLINK;
	if (vp->v_type == VDIR) {
	    fse->nlink = (uint64_t)va.va_dirlinkcount;
	} else {
	    fse->nlink = (uint64_t)va.va_nlink;
	}
    }    

    return 0;
}

#else /* CONFIG_FSE */
/*
 * The get_pathbuff and release_pathbuff routines are used in places not
 * related to fsevents, and it's a handy abstraction, so define trivial
 * versions that don't cache a pool of buffers.  This way, we don't have
 * to conditionalize the callers, and they still get the advantage of the
 * pool of buffers if CONFIG_FSE is turned on.
 */
char *
get_pathbuff(void)
{
	char *path;
	MALLOC_ZONE(path, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
	return path;
}

void
release_pathbuff(char *path)
{
	FREE_ZONE(path, MAXPATHLEN, M_NAMEI);
}
#endif /* CONFIG_FSE */
