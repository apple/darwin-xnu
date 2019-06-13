/*
 * Copyright (c) 2015-2016 Apple Inc. All rights reserved.
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
/*	File:	kern/mach_node.h
 *  Author:	Dean Reece
 *  Date:	2016
 *
 *  Implementation of mach node support.
 *  This is the basis for flipc, which provides inter-node communication.
 */


#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>

#include <kern/kern_types.h>
#include <kern/assert.h>

#include <kern/host.h>
#include <kern/kalloc.h>
#include <kern/mach_node_link.h>
#include <kern/mach_node.h>
#include <kern/ipc_mig.h>           // mach_msg_send_from_kernel_proper()

#include <ipc/port.h>
#include <ipc/ipc_types.h>
#include <ipc/ipc_init.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_table.h>
#include <ipc/ipc_entry.h>

#include <ipc/flipc.h>

#include <libkern/OSAtomic.h>		// OSAddAtomic64(), OSCompareAndSwap()
#include <libkern/OSByteOrder.h>    // OSHostByteOrder()

#pragma pack(4)

#define MNL_NAME_TABLE_SIZE	(256)	// Hash is evenly distributed, so ^2 is ok
#define MNL_NAME_HASH(name)	(name % MNL_NAME_TABLE_SIZE)

/*** Visible outside mach_node layer ***/
mach_node_id_t			localnode_id = -1;	// This node's FLIPC id.
#if MACH_FLIPC
mach_node_t				localnode;			// This node's mach_node_t struct


/*** Private to mach_node layer ***/
static int				mach_nodes_to_publish;
static mach_node_t		mach_node_table[MACH_NODES_MAX];
static lck_spin_t       mach_node_table_lock_data;
#define MACH_NODE_TABLE_LOCK()      lck_spin_lock(&mach_node_table_lock_data)
#define MACH_NODE_TABLE_UNLOCK()    lck_spin_unlock(&mach_node_table_lock_data)
#define MACH_NODE_TABLE_LOCK_INIT() lck_spin_init(&mach_node_table_lock_data, \
                                                  &ipc_lck_grp, &ipc_lck_attr)

static volatile SInt64	mnl_name_next;
static queue_head_t		mnl_name_table[MNL_NAME_TABLE_SIZE];
static lck_spin_t       mnl_name_table_lock_data;
#define MNL_NAME_TABLE_LOCK()       lck_spin_lock(&mnl_name_table_lock_data)
#define MNL_NAME_TABLE_UNLOCK()     lck_spin_unlock(&mnl_name_table_lock_data)
#define MNL_NAME_TABLE_LOCK_INIT()  lck_spin_init(&mnl_name_table_lock_data, \
                                                &ipc_lck_grp, &ipc_lck_attr)

static void mach_node_init(void);
static void mnl_name_table_init(void);
static void mach_node_table_init(void);
static void mach_node_publish(mach_node_t node);

static mach_node_t mach_node_alloc_init(mach_node_id_t node_id);
static kern_return_t mach_node_register(mach_node_t node);


/*	mach_node_init() is run lazily when a node link driver registers
 *  or the node special port is set.
 *  The variable localnode_id is used to determine if init has already run.
 */
void
mach_node_init(void)
{
	mach_node_id_t node_id = 0;	// TODO: Read from device tree?
	if (OSCompareAndSwap((UInt32)(HOST_LOCAL_NODE),
                         (UInt32)node_id,
                         &localnode_id)) {
		printf("mach_node_init(): localnode_id=%d of %d\n",
			  localnode_id, MACH_NODES_MAX);
		mach_node_table_init();
		mnl_name_table_init();
		flipc_init();
    } // TODO: else block until init is finished (init completion race)
}

void
mach_node_table_init(void)
{
    MACH_NODE_TABLE_LOCK_INIT();
    MACH_NODE_TABLE_LOCK();

    /* Start with an enpty node table. */
    bzero(mach_node_table, sizeof(mach_node_t) * MACH_NODES_MAX);
    mach_nodes_to_publish = 0;

    /* Allocate localnode's struct */
    localnode = mach_node_for_id_locked(localnode_id, 1, 1);
    assert(MACH_NODE_VALID(localnode));

    MACH_NODE_TABLE_UNLOCK();

    /* Set up localnode's struct */
    bzero(localnode, sizeof(localnode));
    localnode->info.datamodel       = LOCAL_DATA_MODEL;
    localnode->info.byteorder       = OSHostByteOrder();
    localnode->info.proto_vers_min	= MNL_PROTOCOL_V1;
    localnode->info.proto_vers_max	= MNL_PROTOCOL_V1;
    localnode->proto_vers           = MNL_PROTOCOL_V1;
    localnode->published            = 0;
    localnode->active               = 1;

	MACH_NODE_UNLOCK(localnode);
}

/*  Sends a publication message to the local node's bootstrap server.
 *  This function is smart and will only send a notification if one as really
 *  needed - it can be called speculatively on any node at any time.
 *
 *  Note:  MUST be called with the node table lock held.
 */

void
mach_node_publish(mach_node_t node)
{
    kern_return_t kr;

    if (!MACH_NODE_VALID(node) || (!node->active) || (node->published))
        return; // node is invalid or not suitable for publication

    ipc_port_t bs_port = localnode->bootstrap_port;
    if (!IP_VALID(bs_port))
        return; // No bootstrap server to notify!

    /* Node is suitable and server is present, so make registration message */
    struct mach_node_server_register_msg   msg;

    msg.node_header.header.msgh_remote_port = bs_port;
    msg.node_header.header.msgh_size = sizeof(msg);
    msg.node_header.header.msgh_local_port = MACH_PORT_NULL;
    msg.node_header.header.msgh_voucher_port = MACH_PORT_NULL;
    msg.node_header.header.msgh_id = MACH_NODE_SERVER_MSG_ID;
    msg.node_header.node_id = node->info.node_id;
    msg.node_header.options = 0;
    msg.datamodel = node->info.datamodel;
    msg.byteorder = node->info.byteorder;

    if (node == localnode) {
        msg.node_header.identifier = MACH_NODE_SM_REG_LOCAL;
        msg.node_header.header.msgh_bits =
        MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, 0);
    } else {
        msg.node_header.identifier = MACH_NODE_SM_REG_REMOTE;
        msg.node_header.header.msgh_local_port = node->bootstrap_port;
        msg.node_header.header.msgh_bits = MACH_MSGH_BITS_SET
        (MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND, 0, 0);
    }

    kr = mach_msg_send_from_kernel_proper(&msg.node_header.header,
                                          sizeof (msg));
    if (kr == KERN_SUCCESS) {
        node->published = 1;
        mach_nodes_to_publish--;
    }
    printf("mach_node_publish(%d)=%d\n", node->info.node_id, kr);
}

/* Called whenever the node special port changes */
void
mach_node_port_changed(void)
{
	ipc_port_t bs_port;
	
	mach_node_init(); // Lazy init of mach_node layer
	
	/* Cleanup previous bootstrap port if necessary */
    MACH_NODE_LOCK(localnode);
    flipc_node_retire(localnode);
	bs_port = localnode->bootstrap_port;
	if (IP_VALID(bs_port)) {
		localnode->bootstrap_port = IP_NULL;
		// TODO: destroy send right to outgoing bs_port
	}
	
	kernel_get_special_port(host_priv_self(), HOST_NODE_PORT, &bs_port);
	assert(IP_VALID(bs_port));
    localnode->bootstrap_port = bs_port;
    flipc_node_prepare(localnode);
    MACH_NODE_UNLOCK(localnode);

	/* Cleanup the publication state of all nodes in the table */
	MACH_NODE_TABLE_LOCK();
	// TODO:  Signup for bootstrap port death notifications
	localnode->active = 1;
	
	mach_nodes_to_publish = 0;
	
	int n;
	for (n=0; n<MACH_NODES_MAX; n++) {
        mach_node_t np = mach_node_table[n];
		// Publish all active nodes (except the local node)
		if (!MACH_NODE_VALID(np))
			continue;
		np->published = 0;
		if (np->active == 1)
			mach_nodes_to_publish++;
	}
	
	mach_node_publish(localnode); // Always publish local node first
	
	for (n=0; n<MACH_NODES_MAX; n++)
        mach_node_publish(mach_node_table[n]);

    MACH_NODE_TABLE_UNLOCK();
	
	// TODO: notify all active nodes we are bootstrapped
}

/*  Allocate/init a mach_node struct and fill in the node_id field.
 *  This does NOT insert the node struct into the node table.
 */
mach_node_t
mach_node_alloc_init(mach_node_id_t node_id)
{
    mach_node_t node = MACH_NODE_ALLOC();
    if (MACH_NODE_VALID(node)) {
        bzero(node, sizeof(struct mach_node));
        MACH_NODE_LOCK_INIT(node);
        node->info.node_id = node_id;
    }
    return node;
}


/*  This function takes a mach_node struct with a completed info field and
 *  registers it with the mach_node and flipc (if flipc is enabled) layers.
 */
kern_return_t
mach_node_register(mach_node_t	node)
{
    assert(MACH_NODE_VALID(node));
    mach_node_id_t nid = node->info.node_id;
    assert(MACH_NODE_ID_VALID(nid));

    kern_return_t kr;
    ipc_space_t proxy_space = IS_NULL;
    ipc_pset_t  pp_set = IPS_NULL;          // pset for proxy ports
    ipc_port_t  bs_port = MACH_PORT_NULL;
    ipc_port_t  ack_port = MACH_PORT_NULL;

    printf("mach_node_register(%d)\n", nid);

    /* TODO: Support non-native byte order and data models */
    if ((node->info.byteorder != OSHostByteOrder()) ||
        (node->info.datamodel != LOCAL_DATA_MODEL)) {
        printf("mach_node_register: unsupported byte order (%d) or width (%d)",
                node->info.byteorder, node->info.datamodel);
        return KERN_INVALID_ARGUMENT;
    }

    /* Create the space that holds all local rights assigned to <nid> */
    kr = ipc_space_create_special(&proxy_space);
    if (kr != KERN_SUCCESS)
        goto out;
    proxy_space->is_node_id = nid;

    /* Create the bootstrap proxy port for this remote node */
    bs_port = ipc_port_alloc_special(proxy_space);
    if (bs_port == MACH_PORT_NULL) {
        kr = KERN_RESOURCE_SHORTAGE;
        goto out;
    }

    /* Create the control (ack) port for this remote node */
    ack_port = ipc_port_alloc_special(proxy_space);
    if (ack_port == MACH_PORT_NULL) {
        kr = KERN_RESOURCE_SHORTAGE;
        goto out;
    }

    /* Create the set that holds all proxy ports for this remote node */
    pp_set = ipc_pset_alloc_special(proxy_space);
    if (pp_set == IPS_NULL) {
        kr = KERN_RESOURCE_SHORTAGE;
        goto out;
    }

    waitq_set_lazy_init_link(pp_set);
    /* Add the bootstrap port to the proxy port set */
    uint64_t wq_link_id = waitq_link_reserve(NULL);
    uint64_t wq_reserved_prepost = waitq_prepost_reserve(NULL, 10,
                                                         WAITQ_DONT_LOCK);
    ips_lock(pp_set);
    ip_lock(bs_port);
    ipc_pset_add(pp_set,
                 bs_port,
                 &wq_link_id,
                 &wq_reserved_prepost);
    ip_unlock(bs_port);
    ips_unlock(pp_set);

    waitq_link_release(wq_link_id);
    waitq_prepost_release_reserve(wq_reserved_prepost);

    /* Add the control port to the proxy port set */
    wq_link_id = waitq_link_reserve(NULL);
    wq_reserved_prepost = waitq_prepost_reserve(NULL, 10,
                                                WAITQ_DONT_LOCK);
    ips_lock(pp_set);
    ip_lock(ack_port);
    ipc_pset_add(pp_set,
                 ack_port,
                 &wq_link_id,
                 &wq_reserved_prepost);
    ip_unlock(ack_port);
    ips_unlock(pp_set);

    waitq_link_release(wq_link_id);
    waitq_prepost_release_reserve(wq_reserved_prepost);

    // Setup mach_node struct
    node->published         = 0;
    node->active			= 1;
    node->proxy_space		= proxy_space;
    node->proxy_port_set	= pp_set;
    node->bootstrap_port	= bs_port;
    node->proto_vers        = node->info.proto_vers_max;
    node->control_port      = ack_port;

    // Place new mach_node struct into node table
    MACH_NODE_TABLE_LOCK();

    mach_node_t old_node = mach_node_table[nid];
    if (!MACH_NODE_VALID(old_node) || (old_node->dead)) {
        node->antecedent = old_node;
        flipc_node_prepare(node);
        mach_node_table[nid] = node;
        mach_nodes_to_publish++;
        mach_node_publish(node);
        kr = KERN_SUCCESS;
    } else {
        printf("mach_node_register: id %d already active!", nid);
        kr = KERN_FAILURE;
    }
    MACH_NODE_TABLE_UNLOCK();

out:
    if (kr != KERN_SUCCESS) {   // Dispose of whatever we allocated
        if (pp_set) {
            ips_lock(pp_set);
            ipc_pset_destroy(pp_set);
        }

        if (bs_port)
            ipc_port_dealloc_special(bs_port, proxy_space);

        if (ack_port)
            ipc_port_dealloc_special(ack_port, proxy_space);

        if (proxy_space)
            ipc_space_terminate(proxy_space);
    }

    return kr;
}


/*	Gets or allocates a locked mach_node struct for the specified <node_id>.
 *  The current node is locked and returned if it is not dead, or if it is dead
 *  and <alloc_if_dead> is false.  A new node struct is allocated, locked and
 *  returned if the node is dead and <alloc_if_dead> is true, or if the node
 *  is absent and <alloc_if_absent> is true.  MACH_NODE_NULL is returned if
 *  the node is absent and <alloc_if_absent> is false.  MACH_NODE_NULL is also
 *  returned if a new node structure was not able to be allocated.
 *
 *  Note:  This function must be called with the node table lock held!
 */
mach_node_t
mach_node_for_id_locked(mach_node_id_t	node_id,
						boolean_t		alloc_if_dead,
						boolean_t		alloc_if_absent)
{
	if ((node_id < 0) || (node_id >= MACH_NODES_MAX))
		return MACH_NODE_NULL;

	mach_node_t node = mach_node_table[node_id];
	
	if ( (!MACH_NODE_VALID(node) && alloc_if_absent) ||
		 (MACH_NODE_VALID(node) && node->dead && alloc_if_dead) ) {
		node = mach_node_alloc_init(node_id);
		if (MACH_NODE_VALID(node)) {
			node->antecedent = mach_node_table[node_id];
			mach_node_table[node_id] = node;
		}
	}
	
	if (MACH_NODE_VALID(node))
		MACH_NODE_LOCK(node);
		
	return node;
}



/*** Mach Node Link Name and Hash Table Implementation ***/

/*	Allocate a new unique name and return it.
 *  Dispose of this with mnl_name_free().
 *  Returns MNL_NAME_NULL on failure.
 */
mnl_name_t
mnl_name_alloc(void)
{
	return (mnl_name_t)OSAddAtomic64(MACH_NODES_MAX, &mnl_name_next);
}


/*	Deallocate a unique name that was allocated via mnl_name_alloc().
 */
void
mnl_name_free(mnl_name_t name __unused)
{
	;	// Nothing to do for now since we don't recycle mnl names.
}


/*  Called once from mach_node_init(), this sets up the hash table structures.
 */
void
mnl_name_table_init(void)
{
    MNL_NAME_TABLE_LOCK_INIT();
    MNL_NAME_TABLE_LOCK();
	
	// Set the first name to this node's bootstrap name
	mnl_name_next = localnode_id + MACH_NODES_MAX;
	
	for (int i=0; i<MNL_NAME_TABLE_SIZE; i++)
		queue_head_init(mnl_name_table[i]);
	
	MNL_NAME_TABLE_UNLOCK();
}


/*	Initialize the data structures in the mnl_obj structure at the head of the
 *  provided object.  This should be called on an object before it is passed to
 *  any other mnl_obj* routine.
 */
void
mnl_obj_init(mnl_obj_t obj)
{
	queue_chain_init(obj->links);
	obj->name = MNL_NAME_NULL;
}


/*	Search the local node's hash table for the object associated with a
 *  mnl_name_t and return it.  Returns MNL_NAME_NULL on failure.
 */
mnl_obj_t
mnl_obj_lookup(mnl_name_t name)
{
	mnl_obj_t obj = MNL_OBJ_NULL;
	
	if (name != MNL_NAME_NULL) {
		qe_foreach_element(obj, &mnl_name_table[MNL_NAME_HASH(name)], links) {
			if (obj->name == name)
				break;
		}
	}
	return obj;
}


/*	Search the local node's hash table for the object associated with a
 *  mnl_name_t and remove it.  The pointer to the removed object is returned so
 *  that the caller can appropriately dispose of the object.
 *  Returns MNL_NAME_NULL on failure.
 */
mnl_obj_t
mnl_obj_remove(mnl_name_t name)
{
	mnl_obj_t obj = MNL_OBJ_NULL;
	
	if (name != MNL_NAME_NULL) {
		qe_foreach_element_safe(obj, &mnl_name_table[MNL_NAME_HASH(name)], links) {
			if (obj->name == name)
				remqueue(&obj->links);
		}
	}
	return obj;
}


/*	Insert an object into the local node's hash table.  If the name of the
 *  provided object is MNL_NAME_NULL then a new mnl_name is allocated and
 *  assigned to the object.
 *  	Returns KERN_SUCCESS if obj was added to hash table
 *  	Returns KERN_INVALID_ARGUMENT if obj is invalid
 *  	Returns KERN_NAME_EXISTS if obj's name already exists in hash table
 */
kern_return_t
mnl_obj_insert(mnl_obj_t obj)
{
	if (!MNL_OBJ_VALID(obj))
		return KERN_INVALID_ARGUMENT;
	
	MNL_NAME_TABLE_LOCK();
	
	if (!MNL_NAME_VALID(obj->name)) {
		// obj is unnammed, so lets allocate a fresh one
		obj->name = mnl_name_alloc();
	}
	
	enqueue(&mnl_name_table[MNL_NAME_HASH(obj->name)], &obj->links);
	MNL_NAME_TABLE_UNLOCK();

	if(obj->name >= (MACH_NODES_MAX<<1))
		panic("Unexpected MNL_NAME %lld in obj %p", obj->name, obj);

	return KERN_SUCCESS;
}


/*** Mach Node Link Driver Interface Implementation ***/

/*  Allocate a mnl_msg struct plus additional payload.  Link drivers are not
 *  required to use this to allocate messages; any wired and mapped kernel
 *  memory is acceptable.
 *
 *  Arguments:
 *    payload   Number of additional bytes to allocate for message payload
 *    flags     Currently unused; 0 should be passed
 *
 *  Return values:
 *    MNL_MSG_NULL:     Allocation failed
 *    *:                Pointer to new mnl_msg struct of requested size
 */
mnl_msg_t
mnl_msg_alloc(int       payload,
              uint32_t  flags   __unused)
{
	mnl_msg_t msg = kalloc(MNL_MSG_SIZE + payload);

	if (MNL_MSG_VALID(msg)) {
		bzero(msg, MNL_MSG_SIZE); // Only zero the header
		msg->size = payload;
	}

	return msg;
}


/*  Free a mnl_msg struct allocated by mnl_msg_alloc().
 *
 *  Arguments:
 *    msg       Pointer to the message buffer to be freed
 *    flags     Currently unused; 0 should be passed
 */
void
mnl_msg_free(mnl_msg_t  msg,
             uint32_t   flags   __unused)
{
	if (MNL_MSG_VALID(msg))
		kfree(msg, MNL_MSG_SIZE + msg->size);
}


/*  The link driver calls this to setup a new (or restarted) node, and to get
 *  an mnl_node_info struct for use as a parameter to other mnl functions.
 *  If MNL_NODE_NULL is returned, the operation failed.  Otherwise, a pointer
 *  to a new mnl_node struct is returned.  The caller should set all fields
 *  in the structure, then call mnl_register() to complete node registration.
 *
 *  Arguments:
 *    nid       The id of the node to be instantiated
 *    flags     Currently unused; 0 should be passed
 *
 *  Return values:
 *    MNL_NODE_NULL:    Operation failed
 *    *:                Pointer to a new mnl_node struct
 */
mnl_node_info_t
mnl_instantiate(mach_node_id_t  nid,
                uint32_t        flags   __unused)
{
    mach_node_init(); // Lazy init of mach_node layer

    if ((nid==localnode_id) || !MACH_NODE_ID_VALID(nid))
        return MNL_NODE_NULL;

    return (mnl_node_info_t)mach_node_alloc_init(nid);
}

/*  The link driver calls mnl_register() to complete the node registration
 *  process.  KERN_SUCCESS is returned if registration succeeded, otherwise
 *  an error is returned.
 *
 *  Arguments:
 *    node      Pointer to the node's mnl_node structure
 *    flags     Currently unused; 0 should be passed
 *
 *  Return values:
 *    KERN_SUCCESS:           Registration succeeded
 *    KERN_INVALID_ARGUMENT:  Field(s) in <node> contained unacceptable values
 *    KERN_*:                 Values returned from underlying functions
 */
kern_return_t
mnl_register(mnl_node_info_t    node,
             uint32_t           flags   __unused)
{
    if (MNL_NODE_VALID(node) && (node->node_id != localnode_id))
        return mach_node_register((mach_node_t)node);

    return KERN_INVALID_ARGUMENT;
}


/*  The link driver calls this to report that the link has been raised in one
 *  or both directions.  If the link is two uni-directional channels, each link
 *  driver will independently call this function, each only raising the link
 *  they are responsible for.  The mach_node layer will not communicate with
 *  the remote node until both rx and tx links are up.
 *
 *  Arguments:
 *    node      Pointer to the node's mnl_node structure
 *    link      Indicates which link(s) are up (see MNL_LINK_* defines)
 *    flags     Currently unused; 0 should be passed
 *
 *  Return values:
 *    KERN_SUCCESS:           Link state changed successfully.
 *    KERN_INVALID_ARGUMENT:  An argument value was not allowed.
 *    KERN_*:                 Values returned from underlying functions.
 */
kern_return_t
mnl_set_link_state(mnl_node_info_t  node,
                   int              link,
                   uint32_t         flags   __unused)
{
    kern_return_t kr;
	mach_node_t mnode = (mach_node_t)node;

	if (!MACH_NODE_VALID(mnode) || !(link & MNL_LINK_UP) || (link & mnode->link))
		return KERN_INVALID_ARGUMENT;	// bad node, or bad link argument

    MACH_NODE_LOCK(mnode);

    if (mnode->dead) {
		kr = KERN_NODE_DOWN;
    } else {
        mnode->link |= link;
        kr = KERN_SUCCESS;
    }

    MACH_NODE_UNLOCK(mnode);

	return kr;
}

/*  The link driver calls this to indicate a node has terminated and is no
 *  longer available for messaging.  This may be due to a crash or an orderly
 *  shutdown, but either way the remote node no longer retains any state about
 *  the remaining nodes.  References held on behalf of the terminated node
 *  will be cleaned up.  After this is called, both the rx and tx links are
 *  marked as down.  If the remote node restarts, the link driver can bring
 *  up the link using mnl_instantiate() again.
 *
 *  Arguments:
 *    node      Pointer to the node's mnl_node structure
 *    flags     Currently unused; 0 should be passed
 *
 *  Return values:
 *    KERN_SUCCESS:           Node was terminated.
 *    KERN_INVALID_ARGUMENT:  Node id was invalid or non-existant.
 *    KERN_*:                 Values returned from underlying functions.
 */
kern_return_t
mnl_terminate(mnl_node_info_t   node,
              uint32_t          flags   __unused)
{
	kern_return_t kr = KERN_SUCCESS;
	mach_node_t mnode = (mach_node_t)node;

	if (!MACH_NODE_VALID(mnode))
		return KERN_INVALID_ARGUMENT;	// bad node
	
	MACH_NODE_LOCK(mnode);
	if (mnode->dead) {
		kr = KERN_NODE_DOWN;			// node is already terminated
		goto unlock;
	}

	mnode->link = MNL_LINK_DOWN;
	mnode->active = 0;
	mnode->suspended = 0;
	mnode->dead = 1;

	flipc_node_retire(mnode);

    // Wake any threads sleeping on the proxy port set
    if (mnode->proxy_port_set != IPS_NULL) {
        ips_lock(mnode->proxy_port_set);
        ipc_pset_destroy(mnode->proxy_port_set);
        mnode->proxy_port_set = IPS_NULL;
    }

	// TODO: Inform node name server (if registered) of termination

unlock:
	MACH_NODE_UNLOCK(mnode);
	return kr;
}


/*  The link driver calls this to deliver an incoming message.  Note that the
 *  link driver must dispose of the memory pointed to by <msg> after the
 *  function call returns.
 *
 *  Arguments:
 *    node      Pointer to the node's mnl_node structure
 *    msg       Pointer to the message buffer
 *    flags     Currently unused; 0 should be passed
 */
void
mnl_msg_from_node(mnl_node_info_t   node    __unused,
                  mnl_msg_t         msg,
                  uint32_t          flags   __unused)
{
	assert(MNL_MSG_VALID(msg));
	assert(MACH_NODE_ID_VALID(msg->node_id));
	assert(MNL_NODE_VALID(node));

	/*  If node message forwarding is supported, the from_node_id arg may not
	 *  match fmsg->info.node_id.  The former is the node from which we received
	 *  the message; the latter is the node that generated the message originally.
	 *  We always use fmsg->info.node_id, which is where the ack needs to go.
	 */

	switch (msg->sub) {

		case MACH_NODE_SUB_FLIPC:
			flipc_msg_from_node((mach_node_t)node, msg, flags);
			break;

		default:
#if DEBUG
			PE_enter_debugger("mnl_msg_from_node(): Invalid subsystem");
#endif
			break;
	}
}


/*  The link driver calls this to fetch the next message to transmit.
 *  This function will block until a message is available, or will return
 *  FLIPC_MSG_NULL if the link is to be terminated.  After the caller has
 *  completed the transmission and no longer needs the msg buffer, it should
 *  call mnl_msg_complete().
 *
 *  Arguments:
 *    node      Pointer to the node's mnl_node structure
 *    flags     Currently unused; 0 should be passed
 */
mnl_msg_t
mnl_msg_to_node(mnl_node_info_t node    __unused,
                uint32_t        flags   __unused)
{
	assert(MNL_NODE_VALID(node));

#if DEBUG
    thread_set_thread_name(current_thread(), "MNL_Link");
#endif

	return flipc_msg_to_remote_node((mach_node_t)node, 0);
}


/*  The link driver calls this to indicate that the specified msg buffer has
 *  been sent over the link and can be deallocated.
 *
 *  Arguments:
 *    node      Pointer to the node's mnl_node structure
 *    msg       Pointer to the message buffer
 *    flags     Currently unused; 0 should be passed
 */
void
mnl_msg_complete(mnl_node_info_t    node    __unused,
                 mnl_msg_t          msg,
                 uint32_t           flags)
{
    switch (msg->sub) {
        case MACH_NODE_SUB_NODE:
            mnl_msg_free(msg, flags);
            break;

        case MACH_NODE_SUB_FLIPC:
            flipc_msg_free(msg, flags);
            break;

        default:
#if DEBUG
            PE_enter_debugger("mnl_msg_complete(): Invalid subsystem");
#endif
            break;
    }
}

#else // MACH_FLIPC not configured, so provide KPI stubs

mnl_msg_t
mnl_msg_alloc(int payload __unused, uint32_t flags __unused)
{
    return MNL_MSG_NULL;
}

void
mnl_msg_free(mnl_msg_t msg __unused, uint32_t flags __unused)
{
    return;
}

mnl_node_info_t
mnl_instantiate(mach_node_id_t nid __unused, uint32_t flags __unused)
{
    return MNL_NODE_NULL;
}

kern_return_t
mnl_register(mnl_node_info_t node  __unused, uint32_t flags __unused)
{
    return KERN_FAILURE;
}

kern_return_t
mnl_set_link_state(mnl_node_info_t  node    __unused,
                   int              link    __unused,
                   uint32_t         flags   __unused)
{
    return KERN_FAILURE;
}

kern_return_t
mnl_terminate(mnl_node_info_t node __unused, uint32_t flags __unused)
{
    return KERN_FAILURE;
}

void
mnl_msg_from_node(mnl_node_info_t   node    __unused,
                  mnl_msg_t         msg     __unused,
                  uint32_t          flags   __unused)
{
    return;
}

mnl_msg_t
mnl_msg_to_node(mnl_node_info_t node __unused, uint32_t flags __unused)
{
    return MNL_MSG_NULL;
}

void
mnl_msg_complete(mnl_node_info_t    node    __unused,
                 mnl_msg_t          msg     __unused,
                 uint32_t           flags   __unused)
{
    return;
}

#endif // MACH_FLIPC
