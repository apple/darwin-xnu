/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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

/*
 * Copyright 1997,1998 Julian Elischer.  All rights reserved.
 * julian@freebsd.org
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * devfs_tree.c
 */

/*
 * HISTORY
 *  Dieter Siegmund (dieter@apple.com) Thu Apr  8 14:08:19 PDT 1999
 *  - removed mounting of "hidden" mountpoint
 *  - fixed problem in which devnode->dn_vn pointer was not
 *    updated with the vnode returned from checkalias()
 *  - replaced devfs_vntodn() with a macro VTODN()
 *  - rewrote dev_finddir() to not use recursion
 *  - added locking to avoid data structure corruption (DEVFS_(UN)LOCK())
 *  Dieter Siegmund (dieter@apple.com) Wed Jul 14 13:37:59 PDT 1999
 *  - fixed problem with devfs_dntovn() checking the v_id against the
 *    value cached in the device node; a union mount on top of us causes
 *    the v_id to get incremented thus, we would end up returning a new
 *    vnode instead of the existing one that has the mounted_here
 *    field filled in; the net effect was that the filesystem mounted
 *    on top of us would never show up
 *  - added devfs_stats to store how many data structures are actually 
 *    allocated
 */

/* SPLIT_DEVS means each devfs uses a different devnode for the same device */
/* Otherwise the same device always ends up at the same vnode even if  */
/* reached througgh a different devfs instance. The practical difference */
/* is that with the same vnode, chmods and chowns show up on all instances of */
/* a device. (etc) */

#define SPLIT_DEVS 1 /* maybe make this an option */
/*#define SPLIT_DEVS 1*/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <stdarg.h>

#include "devfs.h"
#include "devfsdefs.h"

struct lock__bsd__	devfs_lock;		/* the "big switch" */
devdirent_t *		dev_root = NULL; 	/* root of backing tree */
struct devfs_stats	devfs_stats;		/* hold stats */

#ifdef HIDDEN_MOUNTPOINT
static struct mount *devfs_hidden_mount;
#endif HIDDEN_MOINTPOINT

static int devfs_ready = 0;

#define NOCREATE	FALSE
#define CREATE		TRUE

/*
 * Set up the root directory node in the backing plane
 * This is happenning before the vfs system has been
 * set up yet, so be careful about what we reference..
 * Notice that the ops are by indirection.. as they haven't
 * been set up yet!
 * DEVFS has a hidden mountpoint that is used as the anchor point
 * for the internal 'blueprint' version of the dev filesystem tree.
 */
/*proto*/
int
devfs_sinit(void)
{
    	lockinit(&devfs_lock, PINOD, "devfs", 0, 0);
        if (dev_add_entry("root", NULL, DEV_DIR, NULL, NULL, NULL, 
			  &dev_root)) {
	    printf("devfs_sinit: dev_add_entry failed ");
	    return (EOPNOTSUPP);
	}
#ifdef HIDDEN_MOUNTPOINT
	MALLOC(devfs_hidden_mount, struct mount *, sizeof(struct mount),
	       M_MOUNT, M_WAITOK);
	bzero(devfs_hidden_mount,sizeof(struct mount));

    /* Initialize the default IO constraints */
    mp->mnt_maxreadcnt = mp->mnt_maxwritecnt = MAXPHYS;
    mp->mnt_segreadcnt = mp->mnt_segwritecnt = 32;

	devfs_mount(devfs_hidden_mount,"dummy",NULL,NULL,NULL);
	dev_root->de_dnp->dn_dvm 
	    = (struct devfsmount *)devfs_hidden_mount->mnt_data;
#endif HIDDEN_MOUNTPOINT
	devfs_ready = 1;
	return (0);
}

/***********************************************************************\
*************************************************************************
*	Routines used to find our way to a point in the tree		*
*************************************************************************
\***********************************************************************/


/***************************************************************\
* Search down the linked list off a dir to find "name"		*
* return the devnode_t * for that node.
\***************************************************************/
/*proto*/
devdirent_t *
dev_findname(devnode_t * dir,char *name)
{
	devdirent_t * newfp;
	if (dir->dn_type != DEV_DIR) return 0;/*XXX*/ /* printf?*/

	if (name[0] == '.')
	{
		if(name[1] == 0)
		{
			return dir->dn_typeinfo.Dir.myname;
		}
		if((name[1] == '.') && (name[2] == 0))
		{
			/* for root, .. == . */
			return dir->dn_typeinfo.Dir.parent->dn_typeinfo.Dir.myname;
		}
	}
	newfp = dir->dn_typeinfo.Dir.dirlist;
	while(newfp)
	{
		if(!(strcmp(name,newfp->de_name)))
			return newfp;
		newfp = newfp->de_next;
	}
	return NULL;
}

#if 0
/***********************************************************************\
* Given a starting node (0 for root) and a pathname, return the node	*
* for the end item on the path. It MUST BE A DIRECTORY. If the 'CREATE'	*
* option is true, then create any missing nodes in the path and create	*
* and return the final node as well.					*
* This is used to set up a directory, before making nodes in it..	*
*									*
* Warning: This function is RECURSIVE.					*
\***********************************************************************/
int
dev_finddir(char * orig_path, 	/* find this dir (err if not dir) */
	    devnode_t * dirnode, 	/* starting point */
	    int create, 	/* create path? */
	    devnode_t * * dn_pp)	/* returned */
{
	devdirent_t *	dirent_p;
	devnode_t *	dnp = NULL;
	char	pathbuf[DEVMAXPATHSIZE];
	char	*path;
	char	*name;
	register char *cp;
	int	retval;


	/***************************************\
	* If no parent directory is given	*
	* then start at the root of the tree	*
	\***************************************/
	if(!dirnode) dirnode = dev_root->de_dnp;

	/***************************************\
	* Sanity Checks				*
	\***************************************/
	if (dirnode->dn_type != DEV_DIR) return ENOTDIR;
	if(strlen(orig_path) > (DEVMAXPATHSIZE - 1)) return ENAMETOOLONG;


	path = pathbuf;
	strcpy(path,orig_path);

	/***************************************\
	* always absolute, skip leading / 	*
	*  get rid of / or // or /// etc.	*
	\***************************************/
	while(*path == '/') path++;

	/***************************************\
	* If nothing left, then parent was it..	*
	\***************************************/
	if ( *path == '\0' ) {
		*dn_pp = dirnode;
		return 0;
	}

	/***************************************\
	* find the next segment of the name	*
	\***************************************/
	cp = name = path;
	while((*cp != '/') && (*cp != 0)) {
		cp++;
	}

	/***********************************************\
	* Check to see if it's the last component	*
	\***********************************************/
	if(*cp) {
		path = cp + 1;	/* path refers to the rest */
		*cp = 0; 	/* name is now a separate string */
		if(!(*path)) {
			path = (char *)0; /* was trailing slash */
		}
	} else {
		path = NULL;	/* no more to do */
	}

	/***************************************\
	* Start scanning along the linked list	*
	\***************************************/
	dirent_p = dev_findname(dirnode,name);
	if(dirent_p) {	/* check it's a directory */
		dnp = dirent_p->de_dnp;
		if(dnp->dn_type != DEV_DIR) return ENOTDIR;
	} else {
		/***************************************\
		* The required element does not exist	*
		* So we will add it if asked to.	*
		\***************************************/
		if(!create) return ENOENT;

		if((retval = dev_add_entry(name, dirnode, 
					   DEV_DIR, NULL, NULL, NULL, 
					   &dirent_p)) != 0) {
			return retval;
		}
		dnp = dirent_p->de_dnp;
		devfs_propogate(dirnode->dn_typeinfo.Dir.myname,dirent_p);
	}
	if(path != NULL) {	/* decide whether to recurse more or return */
		return (dev_finddir(path,dnp,create,dn_pp));
	} else {
		*dn_pp = dnp;
		return 0;
	}
}
#endif 0
/***********************************************************************\
* Given a starting node (0 for root) and a pathname, return the node	*
* for the end item on the path. It MUST BE A DIRECTORY. If the 'CREATE'	*
* option is true, then create any missing nodes in the path and create	*
* and return the final node as well.					*
* This is used to set up a directory, before making nodes in it..	*
\***********************************************************************/
/* proto */
int
dev_finddir(char * path, 
	    devnode_t * dirnode,
	    int create, 
	    devnode_t * * dn_pp)
{
	devnode_t *	dnp = NULL;
	int		error = 0;
	char *		scan;


	if (!dirnode) /* dirnode == NULL means start at root */
	    dirnode = dev_root->de_dnp;

	if (dirnode->dn_type != DEV_DIR) 
	    return ENOTDIR;

	if (strlen(path) > (DEVMAXPATHSIZE - 1)) 
	    return ENAMETOOLONG;

	scan = path;

	while (*scan == '/') 
	    scan++;

	*dn_pp = NULL;

	while (1) {
	    char		component[DEVMAXPATHSIZE];
	    devdirent_t *	dirent_p;
	    char * 		start;

	    if (*scan == 0) { 
		/* we hit the end of the string, we're done */
		*dn_pp = dirnode;
		break;
	    }
	    start = scan;
	    while (*scan != '/' && *scan)
		scan++;

	    strncpy(component, start, scan - start);
	    if (*scan == '/')
		scan++;

	    dirent_p = dev_findname(dirnode, component);
	    if (dirent_p) {
		dnp = dirent_p->de_dnp;
		if (dnp->dn_type != DEV_DIR) {
		    error = ENOTDIR;
		    break;
		}
	    }
	    else {
		if (!create) {
		    error = ENOENT;
		    break;
		}
		error = dev_add_entry(component, dirnode, 
				       DEV_DIR, NULL, NULL, NULL, &dirent_p);
		if (error)
		    break;
		dnp = dirent_p->de_dnp;
		devfs_propogate(dirnode->dn_typeinfo.Dir.myname, dirent_p);
	    }
	    dirnode = dnp; /* continue relative to this directory */
	}
	return (error);
}


/***********************************************************************\
* Add a new NAME element to the devfs					*
* If we're creating a root node, then dirname is NULL			*
* Basically this creates a new namespace entry for the device node	*
*									*
* Creates a name node, and links it to the supplied node		*
\***********************************************************************/
/*proto*/
int
dev_add_name(char * name, devnode_t * dirnode, devdirent_t * back, 
    devnode_t * dnp, devdirent_t * *dirent_pp)
{
	devdirent_t * 	dirent_p = NULL;

	if(dirnode != NULL ) {
		if(dirnode->dn_type != DEV_DIR) return(ENOTDIR);
	
		if( dev_findname(dirnode,name))
			return(EEXIST);
	}
	/*
	 * make sure the name is legal
	 * slightly misleading in the case of NULL
	 */
	if (!name || (strlen(name) > (DEVMAXNAMESIZE - 1)))
	    return (ENAMETOOLONG);

	/*
	 * Allocate and fill out a new directory entry 
	 */
	MALLOC(dirent_p, devdirent_t *, sizeof(devdirent_t), 
	       M_DEVFSNAME, M_WAITOK);
	if (!dirent_p) {
	    return ENOMEM;
	}
	bzero(dirent_p,sizeof(devdirent_t));

	/* inherrit our parent's mount info */ /*XXX*/
	/* a kludge but.... */
	if(dirnode && ( dnp->dn_dvm == NULL)) {
		dnp->dn_dvm = dirnode->dn_dvm;
		/* if(!dnp->dn_dvm) printf("parent had null dvm "); */
	}

	/*
	 * Link the two together
	 * include the implicit link in the count of links to the devnode..
	 * this stops it from being accidentally freed later.
	 */
	dirent_p->de_dnp = dnp;
	dnp->dn_links++ ; /* implicit from our own name-node */

	/* 
	 * Make sure that we can find all the links that reference a node
	 * so that we can get them all if we need to zap the node.
	 */
	if(dnp->dn_linklist) {
		dirent_p->de_nextlink = dnp->dn_linklist;
		dirent_p->de_prevlinkp = dirent_p->de_nextlink->de_prevlinkp;
		dirent_p->de_nextlink->de_prevlinkp = &(dirent_p->de_nextlink);
		*dirent_p->de_prevlinkp = dirent_p;
	} else {
		dirent_p->de_nextlink = dirent_p;
		dirent_p->de_prevlinkp = &(dirent_p->de_nextlink);
	}
	dnp->dn_linklist = dirent_p;

	/*
	 * If the node is a directory, then we need to handle the 
	 * creation of the .. link.
	 * A NULL dirnode indicates a root node, so point to ourself.
	 */
	if(dnp->dn_type == DEV_DIR) {
		dnp->dn_typeinfo.Dir.myname = dirent_p;
		/*
		 * If we are unlinking from an old dir, decrement its links
		 * as we point our '..' elsewhere
		 * Note: it's up to the calling code to remove the 
		 * us from the original directory's list
		 */
		if(dnp->dn_typeinfo.Dir.parent) {
			dnp->dn_typeinfo.Dir.parent->dn_links--;
		}
	 	if(dirnode) {
			dnp->dn_typeinfo.Dir.parent = dirnode;
		} else {
			dnp->dn_typeinfo.Dir.parent = dnp;
		}
		dnp->dn_typeinfo.Dir.parent->dn_links++; /* account for the new '..' */
	}

	/*
	 * put the name into the directory entry.
	 */
	strcpy(dirent_p->de_name, name);


	/*
	 * Check if we are not making a root node..
	 * (i.e. have parent)
	 */
	if(dirnode) {
		/*
	 	 * Put it on the END of the linked list of directory entries
	 	 */
	  	int len;

		dirent_p->de_parent = dirnode; /* null for root */
		dirent_p->de_prevp = dirnode->dn_typeinfo.Dir.dirlast;
		dirent_p->de_next = *(dirent_p->de_prevp); /* should be NULL */ 
							/*right?*/
		*(dirent_p->de_prevp) = dirent_p;
		dirnode->dn_typeinfo.Dir.dirlast = &(dirent_p->de_next);
		dirnode->dn_typeinfo.Dir.entrycount++;
		dirnode->dn_len += strlen(name) + 8;/*ok, ok?*/
	}

	*dirent_pp = dirent_p;
	DEVFS_INCR_ENTRIES();
	return 0 ;
}


/***********************************************************************\
* Add a new element to the devfs plane. 				*
*									*
* Creates a new dev_node to go with it if the prototype should not be	*
* reused. (Is a DIR, or we select SPLIT_DEVS at compile time)		*
* typeinfo gives us info to make our node if we don't have a prototype.	*
* If typeinfo is null and proto exists, then the typeinfo field of	*
* the proto is used intead in the CREATE case.				*
* note the 'links' count is 0 (except if a dir)				*
* but it is only cleared on a transition				*
* so this is ok till we link it to something				*
* Even in SPLIT_DEVS mode,						*
* if the node already exists on the wanted plane, just return it	*
\***********************************************************************/
/*proto*/
int
dev_add_node(int entrytype, devnode_type_t * typeinfo, devnode_t * proto,
	     devnode_t * *dn_pp, struct devfsmount *dvm)
{
	devnode_t *	dnp = NULL;

#if defined SPLIT_DEVS
	/*
	 * If we have a prototype, then check if there is already a sibling
	 * on the mount plane we are looking at, if so, just return it.
	 */
	if (proto) {
		dnp = proto->dn_nextsibling;
		while( dnp != proto) {
			if (dnp->dn_dvm == dvm) {
				*dn_pp = dnp;
				return (0);
			}
			dnp = dnp->dn_nextsibling;
		}
		if (typeinfo == NULL)
			typeinfo = &(proto->dn_typeinfo);
	}
#else	/* SPLIT_DEVS */
	if ( proto ) {
		switch (proto->type) {
			case DEV_BDEV:
			case DEV_CDEV:
				*dn_pp = proto;
				return 0;
		}
	}
#endif	/* SPLIT_DEVS */
	MALLOC(dnp, devnode_t *, sizeof(devnode_t), M_DEVFSNODE, M_WAITOK);
	if (!dnp) {
	    return ENOMEM;
	}

	/*
	 * If we have a proto, that means that we are duplicating some
	 * other device, which can only happen if we are not at the back plane
	 */
	if(proto) {
		bcopy(proto, dnp, sizeof(devnode_t));
		dnp->dn_links = 0;
		dnp->dn_linklist = NULL;
		dnp->dn_vn = NULL;
		dnp->dn_len = 0;
		/* add to END of siblings list */
		dnp->dn_prevsiblingp = proto->dn_prevsiblingp;
		*(dnp->dn_prevsiblingp) = dnp;
		dnp->dn_nextsibling = proto;
		proto->dn_prevsiblingp = &(dnp->dn_nextsibling);
	} else {
	        struct timeval tv;

		/* 
		 * We have no prototype, so start off with a clean slate
		 */
		tv = time;
		bzero(dnp,sizeof(devnode_t));
		dnp->dn_type = entrytype;
		dnp->dn_nextsibling = dnp;
		dnp->dn_prevsiblingp = &(dnp->dn_nextsibling);
		dnp->dn_atime.tv_sec = tv.tv_sec;
		dnp->dn_mtime.tv_sec = tv.tv_sec;
		dnp->dn_ctime.tv_sec = tv.tv_sec;
	}
	dnp->dn_dvm = dvm;

	/*
	 * fill out the dev node according to type
	 */
	switch(entrytype) {
	case DEV_DIR:
		/*
		 * As it's a directory, make sure
		 * it has a null entries list
		 */
		dnp->dn_typeinfo.Dir.dirlast = &(dnp->dn_typeinfo.Dir.dirlist);
		dnp->dn_typeinfo.Dir.dirlist = (devdirent_t *)0;
		dnp->dn_typeinfo.Dir.entrycount = 0;
		/*  until we know better, it has a null parent pointer*/
		dnp->dn_typeinfo.Dir.parent = NULL;
		dnp->dn_links++; /* for .*/
		dnp->dn_typeinfo.Dir.myname = NULL;
		/*
		 * make sure that the ops associated with it are the ops
		 * that we use (by default) for directories
		 */
		dnp->dn_ops = &devfs_vnodeop_p;
		dnp->dn_mode |= 0555;	/* default perms */
		break;
	case DEV_SLNK:
		/*
		 * As it's a symlink allocate and store the link info
		 * Symlinks should only ever be created by the user,
		 * so they are not on the back plane and should not be 
		 * propogated forward.. a bit like directories in that way..
		 * A symlink only exists on one plane and has its own
		 * node.. therefore we might be on any random plane.
		 */
	    	MALLOC(dnp->dn_typeinfo.Slnk.name, char *, 
		       typeinfo->Slnk.namelen+1,
		       M_DEVFSNODE, M_WAITOK);
		if (!dnp->dn_typeinfo.Slnk.name) {
		    	FREE(dnp,M_DEVFSNODE);
			return ENOMEM;
		}
		strncpy(dnp->dn_typeinfo.Slnk.name, typeinfo->Slnk.name,
			typeinfo->Slnk.namelen);
		dnp->dn_typeinfo.Slnk.name[typeinfo->Slnk.namelen] = '\0';
		dnp->dn_typeinfo.Slnk.namelen = typeinfo->Slnk.namelen;
		DEVFS_INCR_STRINGSPACE(dnp->dn_typeinfo.Slnk.namelen + 1);
		dnp->dn_ops = &devfs_vnodeop_p;
		dnp->dn_mode |= 0555;	/* default perms */
		break;
	case DEV_CDEV:
	case DEV_BDEV:
		/*
		 * Make sure it has DEVICE type ops
		 * and device specific fields are correct
		 */
		dnp->dn_ops = &devfs_spec_vnodeop_p;
		dnp->dn_typeinfo.dev = typeinfo->dev;
		break;
	default:
		return EINVAL;
	}

	*dn_pp = dnp;
	DEVFS_INCR_NODES();
	return 0 ;
}


/*proto*/
void
devnode_free(devnode_t * dnp)
{
    if (dnp->dn_type == DEV_SLNK) {
        DEVFS_DECR_STRINGSPACE(dnp->dn_typeinfo.Slnk.namelen + 1);
	FREE(dnp->dn_typeinfo.Slnk.name,M_DEVFSNODE);
    }
    FREE(dnp, M_DEVFSNODE);
    DEVFS_DECR_NODES();
    return;
}

/*proto*/
void
devfs_dn_free(devnode_t * dnp)
{
	if(--dnp->dn_links <= 0 ) /* can be -1 for initial free, on error */
	{
		/*probably need to do other cleanups XXX */
		if (dnp->dn_nextsibling != dnp) {
			devnode_t * * 	prevp = dnp->dn_prevsiblingp;
			*prevp = dnp->dn_nextsibling;
			dnp->dn_nextsibling->dn_prevsiblingp = prevp;
			
		}
		if (dnp->dn_vn == NULL) {
#if 0
		    printf("devfs_dn_free: free'ing %x\n", (unsigned int)dnp);
#endif 0
		    devnode_free(dnp); /* no accesses/references */
		}
		else {
#if 0
		    printf("devfs_dn_free: marking %x for deletion\n",
			   (unsigned int)dnp);
#endif 0
		    dnp->dn_delete = TRUE;
		}
	}
}

/***********************************************************************\
*	Front Node Operations						* 
*	Add or delete a chain of front nodes				*
\***********************************************************************/

/***********************************************************************\
* Given a directory backing node, and a child backing node, add the	*
* appropriate front nodes to the front nodes of the directory to	*
* represent the child node to the user					*
*									*
* on failure, front nodes will either be correct or not exist for each	*
* front dir, however dirs completed will not be stripped of completed	*
* frontnodes on failure of a later frontnode				*
*									*
* This allows a new node to be propogated through all mounted planes	*
*									*
\***********************************************************************/
/*proto*/
int
devfs_propogate(devdirent_t * parent,devdirent_t * child)
{
	int	error;
	devdirent_t * newnmp;
	devnode_t *	dnp = child->de_dnp;
	devnode_t *	pdnp = parent->de_dnp;
	devnode_t *	adnp = parent->de_dnp;
	int type = child->de_dnp->dn_type;

	/***********************************************\
	* Find the other instances of the parent node	*
	\***********************************************/
	for (adnp = pdnp->dn_nextsibling;
		adnp != pdnp;
		adnp = adnp->dn_nextsibling)
	{
		/*
		 * Make the node, using the original as a prototype)
		 * if the node already exists on that plane it won't be
		 * re-made..
		 */
		if ((error = dev_add_entry(child->de_name, adnp, type,
					   NULL, dnp, adnp->dn_dvm, 
					   &newnmp)) != 0) {
			printf("duplicating %s failed\n",child->de_name);
		}
	}
	return 0;	/* for now always succeed */
}

/***********************************************************************
 * remove all instances of this devicename [for backing nodes..]
 * note.. if there is another link to the node (non dir nodes only)
 * then the devfs_node will still exist as the ref count will be non-0
 * removing a directory node will remove all sup-nodes on all planes (ZAP)
 *
 * Used by device drivers to remove nodes that are no longer relevant
 * The argument is the 'cookie' they were given when they created the node
 * this function is exported.. see devfs.h
 ***********************************************************************/
void
devfs_remove(void *dirent_p)
{
	devnode_t * dnp = ((devdirent_t *)dirent_p)->de_dnp;
	devnode_t * dnp2;
	boolean_t   funnel_state;
	boolean_t   lastlink;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	if (!devfs_ready) {
		printf("devfs_remove: not ready for devices!\n");
		goto out;
	}

	DEVFS_LOCK(0);

	/* keep removing the next sibling till only we exist. */
	while((dnp2 = dnp->dn_nextsibling) != dnp) {

		/*
		 * Keep removing the next front node till no more exist
		 */
		dnp->dn_nextsibling = dnp2->dn_nextsibling; 
		dnp->dn_nextsibling->dn_prevsiblingp = &(dnp->dn_nextsibling);
		dnp2->dn_nextsibling = dnp2;
		dnp2->dn_prevsiblingp = &(dnp2->dn_nextsibling);
		if(dnp2->dn_linklist) {
			do {
				lastlink = (1 == dnp2->dn_links);
				dev_free_name(dnp2->dn_linklist);
			} while (!lastlink);
		}
	}

	/*
	 * then free the main node
	 * If we are not running in SPLIT_DEVS mode, then
	 * THIS is what gets rid of the propogated nodes.
	 */
	if(dnp->dn_linklist) {
		do {
			lastlink = (1 == dnp->dn_links);
			dev_free_name(dnp->dn_linklist);
		} while (!lastlink);
	}
	DEVFS_UNLOCK(0);
out:
	(void) thread_funnel_set(kernel_flock, funnel_state);
	return ;
}


/***************************************************************
 * duplicate the backing tree into a tree of nodes hung off the
 * mount point given as the argument. Do this by
 * calling dev_dup_entry which recurses all the way
 * up the tree..
 **************************************************************/
/*proto*/
int
dev_dup_plane(struct devfsmount *devfs_mp_p)
{
	devdirent_t *	new;
	int		error = 0;

	if ((error = dev_dup_entry(NULL, dev_root, &new, devfs_mp_p)))
	    return error;
	devfs_mp_p->plane_root = new;
	return error;
}



/***************************************************************\
* Free a whole plane
\***************************************************************/
/*proto*/
void
devfs_free_plane(struct devfsmount *devfs_mp_p)
{
	devdirent_t * dirent_p;

	dirent_p = devfs_mp_p->plane_root;
	if(dirent_p) {
		dev_free_hier(dirent_p);
		dev_free_name(dirent_p);
	}
	devfs_mp_p->plane_root = NULL;
}

/***************************************************************\
* Create and link in a new front element.. 			*
* Parent can be 0 for a root node				*
* Not presently usable to make a symlink XXX			*
* (Ok, symlinks don't propogate)
* recursively will create subnodes corresponding to equivalent	*
* child nodes in the base level					*
\***************************************************************/
/*proto*/
int
dev_dup_entry(devnode_t * parent, devdirent_t * back, devdirent_t * *dnm_pp,
	      struct devfsmount *dvm)
{
	devdirent_t *	entry_p;
	devdirent_t *	newback;
	devdirent_t *	newfront;
	int	error;
	devnode_t *	dnp = back->de_dnp;
	int type = dnp->dn_type;

	/*
	 * go get the node made (if we need to)
	 * use the back one as a prototype
	 */
	if ((error = dev_add_entry(back->de_name, parent, type,
				NULL, dnp,
				parent?parent->dn_dvm:dvm, &entry_p)) != 0) {
		printf("duplicating %s failed\n",back->de_name);
	}

	/*
	 * If we have just made the root, then insert the pointer to the
	 * mount information
	 */
	if(dvm) {
		entry_p->de_dnp->dn_dvm = dvm;
	}

	/*
	 * If it is a directory, then recurse down all the other
	 * subnodes in it....
	 * note that this time we don't pass on the mount info..
	 */
	if (type == DEV_DIR)
	{
		for(newback = back->de_dnp->dn_typeinfo.Dir.dirlist;
				newback; newback = newback->de_next)
		{
			if((error = dev_dup_entry(entry_p->de_dnp,
					    newback, &newfront, NULL)) != 0)
			{
				break; /* back out with an error */
			}
		}
	}
	*dnm_pp = entry_p;
	return error;
}

/***************************************************************\
* Free a name node						*
* remember that if there are other names pointing to the	*
* dev_node then it may not get freed yet			*
* can handle if there is no dnp 				*
\***************************************************************/
/*proto*/
int
dev_free_name(devdirent_t * dirent_p)
{
	devnode_t *	parent = dirent_p->de_parent;
	devnode_t *	dnp = dirent_p->de_dnp;

	if(dnp) {
		if(dnp->dn_type == DEV_DIR)
		{
		    	devnode_t * p;

			if(dnp->dn_typeinfo.Dir.dirlist)
				return (ENOTEMPTY);
			p = dnp->dn_typeinfo.Dir.parent;
			devfs_dn_free(dnp); 	/* account for '.' */
			devfs_dn_free(p); 	/* '..' */
		}
		/*
		 * unlink us from the list of links for this node
		 * If we are the only link, it's easy!
		 * if we are a DIR of course there should not be any
		 * other links.
	 	 */
		if(dirent_p->de_nextlink == dirent_p) {
				dnp->dn_linklist = NULL;
		} else {
			if(dnp->dn_linklist == dirent_p) {
				dnp->dn_linklist = dirent_p->de_nextlink;
			}
			dirent_p->de_nextlink->de_prevlinkp 
			    = dirent_p->de_prevlinkp;
			*dirent_p->de_prevlinkp = dirent_p->de_nextlink;
		}
		devfs_dn_free(dnp);
	}

	/*
	 * unlink ourselves from the directory on this plane
	 */
	if(parent) /* if not fs root */
	{
		if( (*dirent_p->de_prevp = dirent_p->de_next) )/* yes, assign */
		{
			dirent_p->de_next->de_prevp = dirent_p->de_prevp;
		}
		else
		{
			parent->dn_typeinfo.Dir.dirlast
				= dirent_p->de_prevp;
		}
		parent->dn_typeinfo.Dir.entrycount--;
		parent->dn_len -= strlen(dirent_p->de_name) + 8;
	}

	DEVFS_DECR_ENTRIES();
	FREE(dirent_p,M_DEVFSNAME);
	return 0;
}

/***************************************************************\
* Free a hierarchy starting at a directory node name 			*
* remember that if there are other names pointing to the	*
* dev_node then it may not get freed yet			*
* can handle if there is no dnp 				*
* leave the node itself allocated.				*
\***************************************************************/
/*proto*/
void
dev_free_hier(devdirent_t * dirent_p)
{
	devnode_t *	dnp = dirent_p->de_dnp;

	if(dnp) {
		if(dnp->dn_type == DEV_DIR)
		{
			while(dnp->dn_typeinfo.Dir.dirlist)
			{
				dev_free_hier(dnp->dn_typeinfo.Dir.dirlist);
				dev_free_name(dnp->dn_typeinfo.Dir.dirlist);
			}
		}
	}
}

/***************************************************************\
* given a dev_node, find the appropriate vnode if one is already
* associated, or get a new one and associate it with the dev_node
\***************************************************************/
/*proto*/
int
devfs_dntovn(devnode_t * dnp, struct vnode **vn_pp, struct proc * p)
{
	struct vnode *vn_p, *nvp;
	int error = 0;

	*vn_pp = NULL;
	vn_p = dnp->dn_vn;
	if (vn_p) { /* already has a vnode */
	    *vn_pp = vn_p;
	    return(vget(vn_p, LK_EXCLUSIVE, p));
	}
	if (!(error = getnewvnode(VT_DEVFS, dnp->dn_dvm->mount,
				  *(dnp->dn_ops), &vn_p))) {
		switch(dnp->dn_type) {
		case	DEV_SLNK:
			vn_p->v_type = VLNK;
			break;
		case	DEV_DIR:
			if (dnp->dn_typeinfo.Dir.parent == dnp) {
				vn_p->v_flag |= VROOT;
			}
			vn_p->v_type = VDIR;
			break;
		case	DEV_BDEV:
		case	DEV_CDEV:
		    	vn_p->v_type 
			    = (dnp->dn_type == DEV_BDEV) ? VBLK : VCHR;
			if ((nvp = checkalias(vn_p, dnp->dn_typeinfo.dev,
					      dnp->dn_dvm->mount)) != NULL) {
			    vput(vn_p);
			    vn_p = nvp;
			}
			break;
		}
		vn_p->v_mount  = dnp->dn_dvm->mount;/* XXX Duplicated */
		*vn_pp = vn_p;
		vn_p->v_data = (void *)dnp;
		dnp->dn_vn = vn_p;
		error = vn_lock(vn_p, LK_EXCLUSIVE | LK_RETRY, p);
	}
	return error;
}

/***********************************************************************\
* add a whole device, with no prototype.. make name element and node	*
* Used for adding the original device entries 				*
\***********************************************************************/
/*proto*/
int
dev_add_entry(char *name, devnode_t * parent, int type, devnode_type_t * typeinfo,
	      devnode_t * proto, struct devfsmount *dvm, devdirent_t * *nm_pp)
{
	devnode_t *	dnp;
	int	error = 0;

	if ((error = dev_add_node(type, typeinfo, proto, &dnp, 
			(parent?parent->dn_dvm:dvm))) != 0)
	{
		printf("devfs: %s: base node allocation failed (Errno=%d)\n",
			name,error);
		return error;
	}
	if ((error = dev_add_name(name ,parent ,NULL, dnp, nm_pp)) != 0)
	{
		devfs_dn_free(dnp); /* 1->0 for dir, 0->(-1) for other */
		printf("devfs: %s: name slot allocation failed (Errno=%d)\n",
		       name,error);
		
	}
	return error;
}

/*
 * Function: devfs_make_node
 *
 * Purpose
 *   Create a device node with the given pathname in the devfs namespace.
 *
 * Parameters:
 *   dev 	- the dev_t value to associate
 *   chrblk	- block or character device (DEVFS_CHAR or DEVFS_BLOCK)
 *   uid, gid	- ownership
 *   perms	- permissions
 *   fmt, ...	- path format string with printf args to format the path name
 * Returns:
 *   A handle to a device node if successful, NULL otherwise.
 */
void *
devfs_make_node(dev_t dev, int chrblk, uid_t uid,
		gid_t gid, int perms, char *fmt, ...)
{
	devdirent_t *	new_dev = NULL;
	devnode_t *	dnp;	/* devnode for parent directory */
	devnode_type_t	typeinfo;

	char *name, *path, buf[256]; /* XXX */
	boolean_t   funnel_state;
	int i;
	va_list ap;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	if (!devfs_ready) {
		printf("devfs_make_node: not ready for devices!\n");
		goto out;
	}

	if (chrblk != DEVFS_CHAR && chrblk != DEVFS_BLOCK)
		goto out;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	name = NULL;

	for(i=strlen(buf); i>0; i--)
		if(buf[i] == '/') {
			name=&buf[i];
			buf[i]=0;
			break;
		}

	if (name) {
		*name++ = '\0';
		path = buf;
	} else {
		name = buf;
		path = "/";
	}

	DEVFS_LOCK(0);
	/* find/create directory path ie. mkdir -p */
	if (dev_finddir(path, NULL, CREATE, &dnp) == 0) {
	    typeinfo.dev = dev;
	    if (dev_add_entry(name, dnp, 
			      (chrblk == DEVFS_CHAR) ? DEV_CDEV : DEV_BDEV, 
			      &typeinfo, NULL, NULL, &new_dev) == 0) {
		new_dev->de_dnp->dn_gid = gid;
		new_dev->de_dnp->dn_uid = uid;
		new_dev->de_dnp->dn_mode |= perms;
		devfs_propogate(dnp->dn_typeinfo.Dir.myname, new_dev);
	    }
	}
	DEVFS_UNLOCK(0);

out:
	(void) thread_funnel_set(kernel_flock, funnel_state);
	return new_dev;
}

/*
 * Function: devfs_make_link
 *
 * Purpose:
 *   Create a link to a previously created device node.
 *
 * Returns:
 *   0 if successful, -1 if failed
 */
int
devfs_make_link(void *original, char *fmt, ...)
{
	devdirent_t *	new_dev = NULL;
	devdirent_t *	orig = (devdirent_t *) original;
	devnode_t *	dirnode;	/* devnode for parent directory */

	va_list ap;
	char *p, buf[256]; /* XXX */
	int i;
	boolean_t   funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	if (!devfs_ready) {
		printf("devfs_make_link: not ready for devices!\n");
		goto out;
	}

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	p = NULL;

	for(i=strlen(buf); i>0; i--)
		if(buf[i] == '/') {
				p=&buf[i];
				buf[i]=0;
				break;
		}
	DEVFS_LOCK(0);
	if (p) {
	*p++ = '\0';
	if (dev_finddir(buf, NULL, CREATE, &dirnode)
		|| dev_add_name(p, dirnode, NULL, orig->de_dnp, &new_dev))
		goto fail;
	} else {
	    if (dev_finddir("", NULL, CREATE, &dirnode)
		|| dev_add_name(buf, dirnode, NULL, orig->de_dnp, &new_dev))
		goto fail;
	}
	devfs_propogate(dirnode->dn_typeinfo.Dir.myname, new_dev);
fail:
	DEVFS_UNLOCK(0);
out:
	(void) thread_funnel_set(kernel_flock, funnel_state);
	return ((new_dev != NULL) ? 0 : -1);
}

