#include "mach_vm_tests.h"
#include "unistd.h"

#define TEST_TXT_FILE "/tmp/xnu.vm.sharing.test.txt"

static const char * lorem_text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \
Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate\
velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";


static int fd = 0;
static struct stat sb;
mach_port_t persistentReplyPort;

int
mach_server_data_setup(void **buffer)
{
	if (0 != access(TEST_TXT_FILE, F_OK)) {
		/* create a test file */
		const size_t lorem_text_length = strlen(lorem_text);
		int w_fd = open(TEST_TXT_FILE, O_WRONLY | O_CREAT | O_TRUNC, (mode_t)0666);
		size_t required_length = 450783;
		assert(w_fd >= 0);
		size_t bytes_written = 0;
		while (bytes_written < required_length) {
			bytes_written += (size_t)write(w_fd, &lorem_text[0], (size_t)(lorem_text_length - 1));
			if ((bytes_written + lorem_text_length) > required_length) {
				bytes_written += (size_t)write(w_fd, &lorem_text[0], (size_t)(required_length - bytes_written));
				break;
			}
		}
		close(w_fd);
	}

	/* Sample data set needs to be mapped in our space */
	fd = open(TEST_TXT_FILE, O_RDONLY | O_EXCL, 0666);

	if (fd < 0) {
		printf("mach_server_data_setup: cannot open file %s - %d (%s).\n", TEST_TXT_FILE, errno, strerror(errno));
		return errno;
	}

	if (fstat(fd, &sb) < 0) {
		printf("mach_server_data_setup: cannot stat file %s - %d (%s).\n", TEST_TXT_FILE, errno, strerror(errno));
		return errno;
	}

#if MMAP_PATH
	*buffer = mmap(NULL, sb.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE, fd, 0);

	if (*buffer == MAP_FAILED) {
		printf("mach_server_remap: mmap failed - %d (%s).\n", errno, strerror(errno));
		*buffer = NULL;
	}
#else
	kern_return_t kr = KERN_SUCCESS;
	kr = mach_vm_allocate(mach_task_self(), (mach_vm_address_t *)buffer, (mach_vm_size_t)sb.st_size, VM_FLAGS_ANYWHERE);
	assert(kr == KERN_SUCCESS);
#endif
	return 0;
}

void
mach_server_data_cleanup(void *buffer, mach_vm_address_t src, mach_vm_size_t size)
{
#if MMAP_PATH
	if (buffer) {
		munmap(buffer, sb.st_size);
	}
#else
	mach_vm_deallocate(mach_task_self(), (mach_vm_address_t)buffer, (mach_vm_size_t)sb.st_size);
#endif

	if (src) {
		mach_vm_deallocate(mach_task_self(), src, size);
	}

	if (fd > 2) {
		close(fd);
	}
}

void
mach_server_construct_header(ipc_message_t *message, mach_port_t replyPort)
{
	bzero(message, sizeof(*message));
	message->header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE) | MACH_MSGH_BITS_COMPLEX;
	message->header.msgh_remote_port = persistentReplyPort;//serverPort;
	message->header.msgh_local_port = replyPort;
	message->header.msgh_size = sizeof(*message);
	message->header.msgh_id = 1;
}

void
mach_server_contruct_payload(ipc_message_t         *message,
    mach_vm_address_t       src,
    mach_port_t                     port,
    mach_vm_size_t          size,
    mach_vm_offset_t        misoffset,
    boolean_t                       copy,
    int                                     vm_op)
{
	if (port == MACH_PORT_NULL) {
		message->address = src;//LD TODO: (src + 8193);
	} else {
		message->body.msgh_descriptor_count = 1;
		message->port_descriptor.name = port;
		message->port_descriptor.disposition = MACH_MSG_TYPE_COPY_SEND;
		message->port_descriptor.type = MACH_MSG_PORT_DESCRIPTOR;
	}

	message->pid = (uint64_t)getpid();
	message->size = size;
	message->vm_op = vm_op;
	message->copy = copy;
	message->misoffset = misoffset;
}

void
mach_server_create_allocation(mach_vm_address_t *src, mach_vm_size_t size, void *buffer)
{
	kern_return_t       kr = KERN_SUCCESS;
	mach_vm_size_t      chunk_size = 0;
	unsigned int        chunk_count = 0;
	mach_vm_address_t   localsrc = 0;

	kr = mach_vm_allocate(mach_task_self(), &localsrc, size, VM_FLAGS_ANYWHERE);
	assert(KERN_SUCCESS == kr);

	chunk_size = MIN(size, (mach_vm_size_t)sb.st_size);

	if (chunk_size == 0) {
		printf("mach_server_remap: Input size is 0\n");
		exit(0);
	}

	chunk_count = (unsigned int)(size / (mach_vm_size_t)sb.st_size);

	if (debug && 0) {
		printf("Chunks of size: 0x%llx and count: %d\n", chunk_size, chunk_count);
	}

	for (unsigned int i = 0; i < chunk_count; i++) {
		memcpy((void*)(localsrc + (i * chunk_size)), buffer, chunk_size);
	}

	*src = localsrc;
}

void
server_error_out(mach_port_t port)
{
	/* All done here...*/
	kern_return_t ret;

	mach_msg_size_t messageSize = sizeof(ipc_message_t) + sizeof(mach_msg_trailer_t) + 64;
	ipc_message_t *message = (ipc_message_t *)calloc(1, messageSize);

	message->header.msgh_bits = MACH_MSGH_BITS_ZERO;
	message->header.msgh_size = messageSize;
	message->header.msgh_remote_port = MACH_PORT_NULL;
	message->header.msgh_local_port = port;

	mach_server_construct_header(message, port);
	message->vm_op = VM_OP_EXIT_ERROR;
	ret = mach_msg(&message->header, MACH_SEND_MSG, message->header.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	if (ret != KERN_SUCCESS) {
		T_LOG("ERROR: Failed to send message to client: (%d) %s\n", ret, mach_error_string(ret));
		exit(1);
	}
	T_LOG("server_error_out. abort()\n");
	abort();
}
