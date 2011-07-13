#if defined(i386) || defined(__x86_64__)

#include <libkern/OSAtomic.h>
#include <stdio.h>
#include <string.h>
#include <err.h>

typedef struct {
	void *next;
	char *str;
} QueueNode;

int atomic_fifo_queue_test( void *the_argp ) {
	OSFifoQueueHead head = OS_ATOMIC_FIFO_QUEUE_INIT;
	char *str1 = "String 1", *str2 = "String 2";
	QueueNode node1 = { 0, str1 };
	OSAtomicFifoEnqueue(&head, &node1, 0);
	QueueNode node2 = { 0, str2 };
	OSAtomicFifoEnqueue(&head, &node2, 0);
	QueueNode *node_ptr = OSAtomicFifoDequeue(&head, 0);
	if( strcmp(node_ptr->str, str1) != 0 ) {
		warnx("OSAtomicFifoDequeue returned incorrect string. Expected %s, got %s", str1, node_ptr->str);
		return 1;
	}
	node_ptr = OSAtomicFifoDequeue(&head, 0);
	if( strcmp(node_ptr->str, str2) != 0 ) {
		warnx("OSAtomicFifoDequeue returned incorrect string. Expected %s, got %s", str2, node_ptr->str);
		return 1;
	}
	return 0;
}

#endif
