/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/* Copyright (c) 1998, Apple Computer, Inc. All rights reserved. */
/*
 * Header file for volfs
 */

struct volfs_mntdata
{
	struct vnode *volfs_rootvp;
	LIST_HEAD(volfs_fsvnodelist, vnode) volfs_fsvnodes;
};

/*
 * Volfs vnodes exist only for the root, which allows for the enumeration
 * of all volfs accessible filesystems, and for the filesystems which
 * volfs handles.
 */
#define VOLFS_ROOT	1	/* This volfs vnode represents root of volfs */
#define	VOLFS_FSNODE	2	/* This volfs vnode represents a file system */

struct volfs_vndata
{
	int		vnode_type;
	struct lock__bsd__	lock;
	unsigned int	nodeID;	/* the dev entry of a file system */
	struct mount *	fs_mount;
};

#define MAXVLFSNAMLEN	24	/* max length is really 10, pad to 24 since
				 * some of the math depends on VLFSDIRENTLEN
				 * being a power of 2 */
#define VLFSDIRENTLEN	(MAXVLFSNAMLEN + sizeof(u_int32_t) + sizeof(u_int16_t) + sizeof(u_int8_t) + sizeof(u_int8_t))

#define ROOT_DIRID	2

extern int (**volfs_vnodeop_p)(void *);
__BEGIN_DECLS

int	volfs_mount __P((struct mount *, char *, caddr_t, struct nameidata *,
	struct proc *));
int	volfs_start __P((struct mount *, int, struct proc *));
int	volfs_unmount __P((struct mount *, int, struct proc *));
int	volfs_root __P((struct mount *, struct vnode **));
int	volfs_quotactl __P((struct mount *, int, uid_t, caddr_t, 
	struct proc *));
int	volfs_statfs __P((struct mount *, struct statfs *, struct proc *));
int	volfs_sync __P((struct mount *, int, struct ucred *, struct proc *));
int	volfs_vget __P((struct mount *, void *ino_t, struct vnode **));
int	volfs_fhtovp __P((struct mount *, struct fid *, struct mbuf *,
	struct vnode **, int *, struct ucred **));
int	volfs_vptofh __P((struct vnode *, struct fid *));
int	volfs_init __P((struct vfsconf *));
int	volfs_sysctl __P((int *, u_int, void *, size_t *, void *, size_t,
		struct proc *));

int	volfs_reclaim __P((struct vop_reclaim_args*));
int	volfs_access __P((struct vop_access_args *));
int	volfs_getattr __P((struct vop_getattr_args *));
int	volfs_select __P((struct vop_select_args *));
int	volfs_rmdir __P((struct vop_rmdir_args *));
int	volfs_readdir __P((struct vop_readdir_args *));
int	volfs_lock __P((struct vop_lock_args *));
int	volfs_unlock __P((struct vop_unlock_args *));
int	volfs_islocked __P((struct vop_islocked_args *));
int	volfs_pathconf __P((struct vop_pathconf_args *));
int	volfs_lookup __P((struct vop_lookup_args *));
__END_DECLS

#define VTOVL(VP) ((struct volfs_vndata *)((VP)->v_data))

#define PRINTIT kprintf

#if VOLFS_DEBUG
    #define	DBG_VOP_TEST_LOCKS			1
    #define DBG_FUNC_NAME(FSTR) 		static char *funcname = FSTR
    #define DBG_PRINT_FUNC_NAME() 		PRINTIT("%s\n", funcname);
    #define DBG_VOP_PRINT_FUNCNAME()	PRINTIT("%s: ", funcname);
	#define DBG_VOP_PRINT_CPN_INFO(CN) 	PRINTIT("name: %s",(CN)->cn_nameptr);
	#define DBG_VOP(STR) 				PRINTIT STR;
    #define DBG_VOP_PRINT_VNODE_INFO(VP)	{  if ((VP)) \
      { if ((VP)->v_tag == VT_NON) \
      PRINTIT("\tfs:%s id: %d v: 0x%x ", VTOVL(VP)->fs_mount->mnt_stat.f_fstypename, VTOVL(VP)->nodeID, (u_int)(VP)); \
      else  PRINTIT("\t%s v: 0x%x ", (VP)->v_mount->mnt_stat.f_fstypename, (u_int)(VP)); \
      } else { PRINTIT("*** NULL NODE ***"); } }

#else /* VOLFS_DEBUG */
    #define DBG_VOP_TEST_LOCKS 0
    #define DBG_FUNC_NAME(FSTR)
    #define DBG_PRINT_FUNC_NAME()
    #define DBG_VOP_PRINT_FUNCNAME()
    #define DBG_VOP_PRINT_CPN_INFO(CN)
	#define DBG_VOP(A)
	#define DBG_VOP_PRINT_VNODE_INFO(VP)
#endif /* VOLFS_DEBUG */


#if DBG_VOP_TEST_LOCKS

#define 	VOPDBG_IGNORE			0
#define 	VOPDBG_LOCKED			1
#define 	VOPDBG_UNLOCKED			-1
#define 	VOPDBG_LOCKNOTNIL		2
#define 	VOPDBG_SAME				3

#define 	VOPDBG_ZERO	0
#define 	VOPDBG_POS	1


#define 	MAXDBGLOCKS		15

typedef struct	VopDbgStoreRec {
    short	id;
    struct vnode	*vp;
    short	inState;
    short	outState;
    short	errState;
    int		inValue;
    int		outValue;
    } VopDbgStoreRec;


/*		This sets up the test for the lock state of vnodes. The entry paramaters are:
 *			I = index of paramater
 *			VP = pointer to a vnode
 *			ENTRYSTATE = the inState of the lock
 *			EXITSTATE = the outState of the lock
 *			ERRORSTATE = the error state of the lock
 *		It initializes the structure, does some preliminary validity checks, but does nothing
 *		if the instate is set to be ignored.
 */

#define  DBG_VOP_LOCKS_DECL(I)	VopDbgStoreRec	VopDbgStore[I];short numOfLockSlots=I
#define  DBG_VOP_LOCKS_INIT(I,VP,ENTRYSTATE,EXITSTATE,ERRORSTATE,CHECKFLAG)		\
		if (I >= numOfLockSlots) { \
                PRINTIT("%s: DBG_VOP_LOCKS_INIT: Entry #%d greater than allocated slots!\n", funcname, I); \
            	}; \
            VopDbgStore[I].id 			= I; \
            VopDbgStore[I].vp 			= (VP); \
            VopDbgStore[I].inState 		= ENTRYSTATE; \
            VopDbgStore[I].outState 	= EXITSTATE; \
            VopDbgStore[I].errState 	= ERRORSTATE; \
            VopDbgStore[I].inValue 		= 0; \
            VopDbgStore[I].outValue 	= 0; \
            if ((VopDbgStore[I].inState != VOPDBG_IGNORE)) {		\
                if ((VP) == NULL) 														\
                    PRINTIT ("%s: DBG_VOP_LOCK on start: Null vnode ptr\n", funcname); 	\
                else 																	\
                VopDbgStore[I].inValue = lockstatus (&((struct volfs_vndata *)((VP)->v_data))->lock);			\
                }																		\
            if ((VP) != NULL)															\
                {																		\
                if (CHECKFLAG==VOPDBG_POS && (VP)->v_usecount <= 0) 					\
                    PRINTIT("%s: BAD USECOUNT OF %d !!!!\n", funcname, (VP)->v_usecount);	\
                else if ((VP)->v_usecount < 0) 													\
                    PRINTIT("%s: BAD USECOUNT OF %d !!!!\n", funcname, (VP)->v_usecount);	\
                }
#define DBG_VOP_UPDATE_VP(I, VP) \
    VopDbgStore[I].vp 			= (VP);


#define  DBG_VOP_LOCKS_TEST(status) DbgVopTest (numOfLockSlots, status, VopDbgStore, funcname);

#else   /*DBG_VOP_TEST_LOCKS */
#define  DBG_VOP_LOCKS_DECL(A)
#define  DBG_VOP_LOCKS_INIT(A,B,C,D,E,F)
#define  DBG_VOP_LOCKS_TEST(a)
#define  DBG_VOP_UPDATE_VP(I, VP)

#endif	/* DBG_VOP_TEST_LOCKS */
