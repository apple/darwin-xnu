//
//  vmremaptest.c
//
//  Created by Lionel Desai on 9/16/19.
//  Copyright © 2019 Apple. All rights reserved.
//

#include "mach_vm_tests.h"
#include <sys/sysctl.h>


#define TESTSZ (140 * 1024 * 1024ULL)

void
mach_vm_client(mach_port_t port)
{
	mach_port_t memport = MACH_PORT_NULL;
	mach_vm_address_t       src = 0, dest = 0, tmp = 0;
	mach_vm_size_t          size = 0;
	vm_prot_t cur_prot, max_prot;
	mach_port_name_t        lport = 0;
	kern_return_t           ret = 0;
	boolean_t                       copy = FALSE;
	mach_vm_offset_t misoffset = 0;

	mach_msg_type_number_t countp;
	mach_msg_size_t messageSize = 0;
	ipc_message_t *message = NULL;

	char buffer[PATH_MAX];
	ret = proc_pidpath(getpid(), buffer, sizeof(buffer));
	assert(ret != -1);

	messageSize = sizeof(ipc_message_t) + sizeof(mach_msg_trailer_t) + 64;
	message = (ipc_message_t *)calloc(1, messageSize);

	message->header.msgh_bits = MACH_MSGH_BITS_ZERO;
	message->header.msgh_size = messageSize;
	message->header.msgh_remote_port = MACH_PORT_NULL;
	message->header.msgh_local_port = port;

	while (1) {
		/* Awaiting the pid/src. addr/size from the server so we know what to remap from where */
		ret = mach_msg(&message->header, MACH_RCV_MSG | MACH_RCV_LARGE, 0, messageSize, port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
		if (ret == KERN_SUCCESS) {
			if (debug) {
				T_LOG("CLIENT: received info from server... 0x%llx, %lld, 0x%llx, %d - %d\n", message->address, message->size, message->misoffset, message->vm_op, message->copy);
			}

			switch (message->vm_op) {
			case VM_OP_REMAP:
				ret = task_for_pid(mach_task_self(), (pid_t) message->pid, &lport);
				T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "task_for_pid");

				copy = message->copy;
				size = message->size;
				src = message->address;
				misoffset = 0;

				ret = mach_vm_allocate(mach_task_self(), &tmp, size + 16384, VM_FLAGS_ANYWHERE);
				T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "mach_vm_allocate");
				mach_vm_deallocate(mach_task_self(), tmp, size + 16384);

				dest = tmp + 4096;

				ret = mach_vm_remap(mach_task_self(), &dest, size, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
				    lport, src, copy,
				    &cur_prot,
				    &max_prot,
				    VM_INHERIT_NONE);

				if (ret) {
					char dstval[64];
					memcpy(dstval, (void*) dest, 64);
					T_LOG("CLIENT: mach_vm_remap FAILED: %s -- src 0x%llx, dest 0x%llx (%s)\n", mach_error_string(ret), src, dest, dstval);
					T_FAIL("CLIENT: mach_vm_remap FAILED");
				}

				memcpy(message->value, (void*)dest, 64);
				break;

			case VM_OP_READ_OVERWRITE:
				ret = task_for_pid(mach_task_self(), (pid_t) message->pid, &lport);
				T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "task_for_pid");

				size = message->size;
				src = message->address;
				misoffset = 0;

				mach_vm_size_t  dest_size = 0;
				ret = mach_vm_allocate(mach_task_self(), &tmp, size + 16384, VM_FLAGS_ANYWHERE);
				assert(KERN_SUCCESS == ret);

				dest = tmp + 4096;

				ret = mach_vm_read_overwrite(lport, src, size, dest, &dest_size);

				if (ret) {
					char dstval[64];
					memcpy(dstval, (void*) dest, 64);
					T_LOG("CLIENT: mach_vm_read_overwrite FAILED: %s -- src 0x%llx, dest 0x%llx (%s)\n", mach_error_string(ret), src, dest, dstval);
					T_FAIL("CLIENT: mach_vm_read_overwrite FAILED");
				}

				memcpy(message->value, (void*)dest, 64);
				break;

			case VM_OP_READ:
				ret = task_for_pid(mach_task_self(), (pid_t) message->pid, &lport);
				T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "task_for_pid");

				size = message->size;
				src = message->address;
				misoffset = 0;

				ret = mach_vm_read(lport, src, size, (vm_offset_t*)&dest, &countp);
				if (ret) {
					char dstval[64];
					memcpy(dstval, (void*) dest, 64);
					T_LOG("CLIENT: mach_vm_read FAILED: %s -- src 0x%llx, dest 0x%llx (%s)\n", mach_error_string(ret), src, dest, dstval);
					T_FAIL("CLIENT: mach_vm_read FAILED");
					exit(1);
				}

				memcpy(message->value, (void*)dest, 64);
				break;

#if 0
			case VM_OP_WRITE:
				ret = task_for_pid(mach_task_self(), (pid_t) message->pid, &lport);
				T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "task_for_pid");

				size = message->size;
				src = message->address;
				misoffset = 0;

				ret = mach_vm_write(lport, src, dest, countp);
				if (ret) {
					char dstval[64];
					memcpy(dstval, (void*) dest, 64);
					T_LOG("CLIENT: mach_vm_write FAILED: %s -- src 0x%llx, dest 0x%llx (%s)\n", mach_error_string(ret), src, dest, dstval);
					T_FAIL("CLIENT: mach_vm_write FAILED");
				}

				memcpy(message->value, (void*)dest, 64);
				break;
#endif
			case VM_OP_MEMENTRY:
				assert(message->body.msgh_descriptor_count == 1);
				dest = 0;
				size = message->size;
				memport = message->port_descriptor.name;
				copy = message->copy;
				if (copy) {
					misoffset = 0;
				} else {
					misoffset = message->misoffset;
				}

				cur_prot = max_prot = VM_PROT_READ;
#if 0
				/* This + VM_FLAGS_FIXED in mach_vm_map() will return KERN_INVALID_ARG expectedly */
				ret = mach_vm_allocate(mach_task_self(), &tmp, size + 16384, VM_FLAGS_ANYWHERE);
				dest = tmp + 4095;
				mach_vm_deallocate(mach_task_self(), tmp, size + 16384);
#endif
				ret = mach_vm_map(mach_task_self(), &dest, size, 0 /*mask*/,
				    VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
				    memport, 0 /*offset*/, copy, cur_prot, max_prot, VM_INHERIT_NONE);

				if (ret) {
					T_LOG("CLIENT: mach_vm_map FAILED: %s -- port 0x%x\n", mach_error_string(ret), memport);
					T_FAIL("CLIENT: mach_vm_map FAILED");
				}

				memcpy(message->value, (void*)(dest + misoffset), 64);
				break;

			case VM_OP_UNMAP:
				assert(dest);
				ret = mach_vm_deallocate(mach_task_self(), dest, size);
				if (ret) {
					T_LOG("CLIENT: mach_vm_deallocate FAILED: %s -- dest 0x%llx, size 0x%llx\n", mach_error_string(ret), dest, size);
					T_FAIL("CLIENT: mach_vm_deallocate FAILED");
				}
				/* No message to send here */
				continue;

			case VM_OP_NONE:
				memcpy(message->value, (void*) (dest + misoffset), 64);
				break;

			case VM_OP_EXIT:
				if (debug) {
					T_LOG("CLIENT EXITING ****** \n");
				}
				return;

			case VM_OP_EXIT_ERROR:
				if (debug) {
					T_LOG("CLIENT EXITING WITH ERROR****** \n");
					T_FAIL("Revieved VM_OP_EXIT_ERROR");
				}
				return;
			default:
				break;
			}

			char dstval[64];
			memcpy(dstval, (void*) message->value, 64);
			dstval[63] = '\0';

			if (debug) {
				T_LOG("CLIENT: dest 0x%llx -> 0x%llx (0x%llx), *dest %s\n", dest, dest + misoffset, misoffset, dstval);
				/*memcpy(dstval, (void*) (dest + misoffset), 64);
				 *  dstval[63]='\0';
				 *  T_LOG("*dest %s\n", dstval);*/
			}

			message->header.msgh_local_port = MACH_PORT_NULL;

			ret = mach_msg(&message->header, MACH_SEND_MSG, message->header.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
			T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "CLIENT: mach_msg_send FAILED");
		} else {
			T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "CLIENT: mach_msg_rcv FAILED");
		}
	}
}

void
mach_server_make_memory_entry(mach_port_t replyPort)
{
	mach_vm_address_t       src = 0, lsrc = 0;
	mach_vm_size_t          size = TESTSZ;
	memory_object_size_t memsz = 0;
	kern_return_t           kr;
	boolean_t                       modified_in_server = FALSE, perm_changed = FALSE;
	ipc_message_t               message;
	ipc_message_t               *reply = NULL;
	char                            src_val[64], dst_val[64];
	mach_msg_size_t             replySize = 0;
	void                            *buffer = NULL;
	int                                     flags = 0;
	mach_port_t                     memport = 0;
	int                                     mementry_pass_idx = 0;
	mach_vm_offset_t        misoffset = 0;

	if (debug) {
		T_LOG("\n*************** make_memory_entry_test START ***************\n");
	}

	if (mach_server_data_setup(&buffer) != 0) {
		server_error_out(replyPort);
	}

	if (buffer == NULL) {
		mach_server_data_cleanup(NULL, 0, 0);
		exit(0);
	}

	replySize = sizeof(ipc_message_t) + sizeof(mach_msg_trailer_t) + 64;
	reply = calloc(1, replySize);

test_different_mementry_mode:
	/* create message to send over rights/address/pid/size */
	mach_server_construct_header(&message, replyPort);

	/* allocation that we plan to remap in the client */
	mach_server_create_allocation(&src, size, buffer);

	memsz = 8191;
	lsrc = src + 94095;
	int pgmask = (getpagesize() - 1);
	misoffset = 94095 - (94095 & ~pgmask);

	if (mementry_pass_idx < 2) {
		if (mementry_pass_idx == 0) {
			flags = VM_PROT_DEFAULT | MAP_MEM_VM_COPY | MAP_MEM_USE_DATA_ADDR;
			T_LOG("mach_make_memory_entry VM_COPY | USE_DATA_ADDR test...");
		} else {
			flags = VM_PROT_READ | MAP_MEM_VM_SHARE;
			T_LOG("mach_make_memory_entry VM_SHARE test...");
		}
		kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t) lsrc, (mach_vm_size_t)getpagesize(), FALSE, VM_PROT_READ);
		assert(kr == KERN_SUCCESS);
		perm_changed = TRUE;
	} else {
		flags = VM_PROT_DEFAULT;
		perm_changed = FALSE;
		T_LOG("mach_make_memory_entry DEFAULT test...");
	}

	kr = mach_make_memory_entry_64(mach_task_self(), &memsz, lsrc, flags, &memport, MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		T_LOG("ERROR: mach_make_memory_entry_64 try (%d) failed in Client: (%d) %s\n",
		    mementry_pass_idx + 1, kr, mach_error_string(kr));
		server_error_out(replyPort);
	}

	mach_server_contruct_payload(&message, lsrc, memport, memsz, misoffset, ((flags & MAP_MEM_VM_COPY) == MAP_MEM_VM_COPY) /*copy*/, VM_OP_MEMENTRY);

	memcpy(src_val, (void*) lsrc, 64);
	src_val[63] = '\0';

check_again:
	/* Sending over pid/src address/size */
	kr = mach_msg(&message.header, MACH_SEND_MSG, message.header.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);

	if (kr != KERN_SUCCESS) {
		T_LOG("ERROR: Failed to send message to client: (%d) %s\n", kr, mach_error_string(kr));
		server_error_out(replyPort);
	}

	/* Ack from client that it worked */

	bzero(reply, replySize);

	kr = mach_msg(&reply->header, MACH_RCV_MSG, 0, replySize, replyPort, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		T_LOG("ERROR: Failed to get reply from client: (%d) %s\n", kr, mach_error_string(kr));
		server_error_out(replyPort);
	}

	memcpy(dst_val, &reply->value, 64);
	dst_val[63] = '\0';

	if (modified_in_server == FALSE) {
		if (strncmp(src_val, dst_val, 64)) {
			T_LOG("FAILED\n");
			T_LOG("(%d) Pre modification mach_make_memory_entry() FAILED: copy(%d) src_val: %s  dest_val: %s\n", mementry_pass_idx + 1, message.copy, src_val, dst_val);
			server_error_out(replyPort);
		}
	} else {
		if (message.copy == TRUE) {
			if (strncmp(src_val, dst_val, 64) == 0) {
				T_LOG("FAILED\n");
				T_LOG("(%d) Data mismatch with Copy: %d src_val: %s  dest_val: %s\n",
				    mementry_pass_idx + 1, message.copy, src_val, dst_val);
				server_error_out(replyPort);
			}
		} else {
			if (strncmp(src_val, dst_val, 64)) {
				T_LOG("FAILED\n");
				T_LOG("(%d) Data mismatch with Copy: %d src_val: %s  dest_val: %s\n",
				    mementry_pass_idx + 1, message.copy, src_val, dst_val);
				server_error_out(replyPort);
			}
		}
	}

	if (modified_in_server == FALSE) {
		/* Now we change our data that has been mapped elsewhere */
		if (perm_changed) {
			kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t) lsrc, (mach_vm_size_t)getpagesize(), FALSE, VM_PROT_READ | VM_PROT_WRITE);
			assert(kr == KERN_SUCCESS);
		}

		memcpy((void*) lsrc, "THIS IS DIFFERENT -- BUT WE DON'T know if that's expecTED", 64);

		if (perm_changed) {
			kr = mach_vm_protect(mach_task_self(), (mach_vm_address_t) lsrc, (mach_vm_size_t)getpagesize(), FALSE, VM_PROT_READ);
			assert(kr == KERN_SUCCESS);
		}

		memcpy(src_val, (void*) lsrc, 64);
		src_val[63] = '\0';
		modified_in_server = TRUE;
		message.vm_op = VM_OP_NONE;

		/* Check to see if the data in the other process is as expected */
		goto check_again;
	}

	if (mementry_pass_idx < 2) {
		/* Next remap mode...so ask the other process to unmap the older mapping. */
		message.vm_op = VM_OP_UNMAP;
		kr = mach_msg(&message.header, MACH_SEND_MSG, message.header.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
		if (kr != KERN_SUCCESS) {
			T_LOG("ERROR: Failed to send message to client: (%d) %s\n", kr, mach_error_string(kr));
			server_error_out(replyPort);
		}

		mach_port_deallocate(mach_task_self(), memport);
		memport = MACH_PORT_NULL;
		mach_vm_deallocate(mach_task_self(), src, size);

		T_LOG("PASSED\n");

		mementry_pass_idx++;
		modified_in_server = FALSE;

		goto test_different_mementry_mode;
	}

	T_LOG("PASSED\n");

	/* Unmap old mapping in the other process. */
	message.vm_op = VM_OP_UNMAP;
	kr = mach_msg(&message.header, MACH_SEND_MSG, message.header.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		T_LOG("ERROR: Failed to send message to client: (%d) %s\n", kr, mach_error_string(kr));
		server_error_out(replyPort);
	}

	free(reply);
	reply = NULL;

	mach_port_deallocate(mach_task_self(), memport);
	memport = MACH_PORT_NULL;

	mach_server_data_cleanup(buffer, src, size);
	buffer = NULL;

	if (debug) {
		T_LOG("*************** mach_make_memory_entry_test END ***************\n");
	}
}

void
mach_server_read(mach_port_t replyPort, int op)
{
	mach_vm_address_t       src;
	mach_vm_size_t          size = TESTSZ;
	kern_return_t           kr;
	boolean_t                       modified_in_server = FALSE;
	ipc_message_t               message;
	char                            src_val[64], dst_val[64];
	mach_msg_size_t             replySize = 0;
	ipc_message_t               *reply = NULL;
	void                            *buffer = NULL;

	if (debug) {
		T_LOG("\n*************** vm_read / write / overwrite_test START ***************\n");
	}

	{
		char opname[16];
		if (op == VM_OP_READ) {
			strlcpy(opname, "read", 5);
		}
		if (op == VM_OP_WRITE) {
			strlcpy(opname, "write", 6);
		}
		if (op == VM_OP_READ_OVERWRITE) {
			strlcpy(opname, "read_overwrite", 15);
		}

		T_LOG("vm_%s test...", opname);
	}

	if (mach_server_data_setup(&buffer) != 0) {
		server_error_out(replyPort);
	}

	if (buffer == NULL) {
		mach_server_data_cleanup(NULL, 0, 0);
		exit(0);
	}

	replySize = sizeof(ipc_message_t) + sizeof(mach_msg_trailer_t) + 64;
	reply = calloc(1, replySize);

	/* create message to send over rights/address/pid/size */
	mach_server_construct_header(&message, replyPort);

	/* allocation that we plan to remap in the client */
	mach_server_create_allocation(&src, size, buffer);

	mach_server_contruct_payload(&message, src, MACH_PORT_NULL /* port */, size, 0, TRUE /*copy*/, op);
	if (debug) {
		T_LOG("server COPY: Sending 0x%llx, %d, 0x%llx\n", message.address, getpid(), message.size);
	}
	memcpy(src_val, (void*)message.address, 64);

check_again:
	/* Sending over pid/src address/size */
	kr = mach_msg(&message.header, MACH_SEND_MSG, message.header.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		T_LOG("ERROR: Failed to send message to client: (%d) %s\n", kr, mach_error_string(kr));
		server_error_out(replyPort);
	}

	/* Ack from client that it worked */

	bzero(reply, replySize);

	kr = mach_msg(&reply->header, MACH_RCV_MSG, 0, replySize, replyPort, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		T_LOG("ERROR: Failed to get reply from client: (%d) %s\n", kr, mach_error_string(kr));
		server_error_out(replyPort);
	}

	memcpy(dst_val, &reply->value, 64);

	if (modified_in_server == FALSE) {
		if (strncmp(src_val, dst_val, 64)) {
			T_LOG("Pre modification (op: %d) FAILED: src_val: %s  dest_val: %s\n", op, src_val, dst_val);
			server_error_out(replyPort);
		}
	} else {
		if (strncmp(src_val, dst_val, 64) == 0) {
			T_LOG("Data mismatch (op:%d) with Copy: %d src_val: %s  dest_val: %s\n", op, message.copy, src_val, dst_val);
			server_error_out(replyPort);
		}
	}

	if (modified_in_server == FALSE) {
		/* Now we change our data that has been mapped elsewhere */
		memcpy((void*)message.address, "THIS IS DIFFERENT -- BUT WE DON'T know if that's expecTED", 64);
		memcpy(src_val, (void*)message.address, 64);
		modified_in_server = TRUE;
		message.vm_op = VM_OP_NONE;

		/* Check to see if the data in the other process is as expected */
		goto check_again;
	}

	/* Unmap old mapping in the other process. */
	message.vm_op = VM_OP_UNMAP;
	kr = mach_msg(&message.header, MACH_SEND_MSG, message.header.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		T_LOG("ERROR: Failed to send message to client: (%d) %s\n", kr, mach_error_string(kr));
		server_error_out(replyPort);
	}

	free(reply);
	reply = NULL;

	mach_server_data_cleanup(buffer, src, size);
	buffer = NULL;

	if (debug) {
		T_LOG("*************** vm_read_test END ***************\n");
	}

	T_LOG("PASSED\n");
}

void
mach_server_remap(mach_port_t replyPort)
{
	mach_vm_address_t       src = 0, lsrc = 0;
	mach_vm_size_t          size = TESTSZ;
	kern_return_t           kr;
	int                                     remap_copy_pass_idx = 0;
	boolean_t                       modified_in_server = FALSE;
	void                            *buffer;
	ipc_message_t               message;
	char                            src_val[64], dst_val[64];
	mach_msg_size_t             replySize = 0;
	ipc_message_t               *reply = NULL;

	if (debug) {
		T_LOG("\n*************** vm_remap_test START ***************\n");
	}

	if (mach_server_data_setup(&buffer) != 0) {
		server_error_out(replyPort);
	}

	if (buffer == NULL) {
		mach_server_data_cleanup(NULL, 0, 0);
		exit(0);
	}

	replySize = sizeof(ipc_message_t) + sizeof(mach_msg_trailer_t) + 64;
	reply = calloc(1, replySize);

remap_again:

	T_LOG("vm_remap (copy = %s) test...", ((remap_copy_pass_idx == 0) ? "FALSE" : "TRUE"));

	/* create message to send over rights/address/pid/size */
	mach_server_construct_header(&message, replyPort);

	/* server allocation that we plan to remap in the client */
	mach_server_create_allocation(&src, size, buffer);

	lsrc = src + 8193;

	mach_server_contruct_payload(&message, lsrc, MACH_PORT_NULL /* port */, size - 9000, 0, remap_copy_pass_idx /*copy*/, VM_OP_REMAP);
	if (debug) {
		T_LOG("server COPY: Sending 0x%llx, %d, 0x%llx\n", message.address, getpid(), message.size);
	}

	memcpy(src_val, (void*)lsrc, 64);
	src_val[63] = '\0';

check_again:
	/* Sending over pid/src address/size */
	kr = mach_msg(&message.header, MACH_SEND_MSG, message.header.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		T_LOG("ERROR: Failed to send message to client: (%d) %s\n", kr, mach_error_string(kr));
		server_error_out(replyPort);
	}

	/* Ack from client that it worked */

	bzero(reply, replySize);

	kr = mach_msg(&reply->header, MACH_RCV_MSG, 0, replySize, replyPort, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		T_LOG("ERROR: Failed to get reply from client: (%d) %s\n", kr, mach_error_string(kr));
		server_error_out(replyPort);
	}

	memcpy(dst_val, &reply->value, 64);
	dst_val[63] = '\0';


	if (modified_in_server == FALSE) {
		if (strncmp(src_val, dst_val, 64)) {
			T_LOG("Pre modification remap() FAILED: copy(%d) src_val: %s  dest_val: %s\n",
			    message.copy, src_val, dst_val);
			server_error_out(replyPort);
		}
	} else {
		if (message.copy == TRUE) {
			if (strcmp(src_val, dst_val) == 0) {
				T_LOG("Data mismatch with Copy: %d src_val: %s  dest_val: %s\n",
				    message.copy, src_val, dst_val);
				server_error_out(replyPort);
			}
		} else {
			if (strcmp(src_val, dst_val)) {
				T_LOG("Data mismatch with Copy: %d src_val: %s  dest_val: %s\n",
				    message.copy, src_val, dst_val);
				server_error_out(replyPort);
			}
		}
	}

	if (modified_in_server == FALSE) {
		/* Now we change our data that has been mapped elsewhere */
		memcpy((void*)message.address, "THIS IS DIFFERENT -- BUT WE DON'T know if that's expecTED", 64);
		memcpy(src_val, (void*)message.address, 64);
		src_val[63] = '\0';

		modified_in_server = TRUE;
		message.vm_op = VM_OP_NONE;

		/* Check to see if the data in the other process is as expected */
		goto check_again;
	}

	if (remap_copy_pass_idx == 0) {
		/* Next remap mode...so ask the other process to unmap the older mapping. */
		message.vm_op = VM_OP_UNMAP;
		kr = mach_msg(&message.header, MACH_SEND_MSG, message.header.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
		if (kr != KERN_SUCCESS) {
			T_LOG("ERROR: Failed to send message to client: (%d) %s\n", kr, mach_error_string(kr));
			server_error_out(replyPort);
		}

		mach_vm_deallocate(mach_task_self(), src, size);

		T_LOG("PASSED\n");

		remap_copy_pass_idx++;
		modified_in_server = FALSE;

		/* Next remap pass to test (copy == TRUE). Send data out again to the other process to remap. */
		goto remap_again;
	}

	T_LOG("PASSED\n");

	/* Unmap old mapping in the other process. */
	message.vm_op = VM_OP_UNMAP;
	kr = mach_msg(&message.header, MACH_SEND_MSG, message.header.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	if (kr != KERN_SUCCESS) {
		T_LOG("ERROR: Failed to send message to client: (%d) %s\n", kr, mach_error_string(kr));
		server_error_out(replyPort);
	}

	free(reply);
	reply = NULL;

	mach_server_data_cleanup(buffer, src, size);
	buffer = NULL;

	if (debug) {
		T_LOG("*************** vm_remap_test END ***************\n");
	}
}
