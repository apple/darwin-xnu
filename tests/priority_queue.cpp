#include <darwintest.h>
#include <darwintest_utils.h>
#include <stdio.h>
#include <assert.h>
#include <setjmp.h>
#include <algorithm>

#define DEVELOPMENT 0
#define DEBUG 0
#define XNU_KERNEL_PRIVATE 1

#define OS_REFCNT_DEBUG 1
#define STRESS_TESTS 0

#define __container_of(ptr, type, field) __extension__({ \
	        const __typeof__(((type *)nullptr)->field) *__ptr = (ptr); \
	        (type *)((uintptr_t)__ptr - offsetof(type, field)); \
	})

#pragma clang diagnostic ignored "-Watomic-implicit-seq-cst"
#pragma clang diagnostic ignored "-Wc++98-compat"

#include "../osfmk/kern/macro_help.h"
#include "../osfmk/kern/priority_queue.h"
#include "../libkern/c++/priority_queue.cpp"

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

static int
compare_numbers_descending(const void * a, const void * b)
{
	const uint16_t x = *(const uint16_t *)a;
	const uint16_t y = *(const uint16_t *)b;
	if (x > y) {
		return -1;
	} else if (x < y) {
		return 1;
	} else {
		return 0;
	}
}

#define PRIORITY_QUEUE_NODES    8

typedef union test_node {
	struct {
		struct priority_queue_entry e;
		uint32_t node_key;
	};
	struct priority_queue_entry_sched ke;
	struct priority_queue_entry_stable se;
} *test_node_t;

static void
dump_pqueue_entry(priority_queue_entry_sched_t e, int depth)
{
	priority_queue_entry_sched_t t;

	printf("%*s [%02d] %p\n", depth * 4, "", e->key, (void *)e);
	t = pqueue_sched_max_t::unpack_child(e);
	if (t) {
		dump_pqueue_entry(t, depth + 1);
	}
	while (e->next) {
		e = e->next;
		dump_pqueue_entry(e, depth);
	}
}

__unused
static void
dump_pqueue(struct priority_queue_sched_max *pq)
{
	dump_pqueue_entry(pq->pq_root, 0);
	printf("\n");
}

T_DECL(priority_queue_sched_max, "Basic sched priority queue testing")
{
	/* Configuration for the test */
	static uint16_t priority_list[] = { 20, 3, 7, 6, 50, 2, 8, 12};

	struct priority_queue_sched_max pq;
	uint16_t increase_pri = 100;
	uint16_t decrease_pri = 90;
	uint16_t key = 0;
	boolean_t update_result = false;
	test_node_t node = NULL;

	priority_queue_init(&pq);

	/* Add all priorities to the first priority queue */
	for (int i = 0; i < PRIORITY_QUEUE_NODES; i++) {
		node = new test_node;
		T_QUIET; T_ASSERT_NOTNULL(node, NULL);

		priority_queue_entry_init(&node->ke);
		priority_queue_entry_set_sched_pri(&pq, &node->ke, priority_list[i], 0);
		priority_queue_insert(&pq, &node->ke);
	}

	/* Test the priority increase operation by updating the last node added (7) */
	priority_queue_entry_set_sched_pri(&pq, &node->ke, increase_pri, 0);
	update_result = priority_queue_entry_increased(&pq, &node->ke);
	T_ASSERT_TRUE(update_result, "increase key updated root");
	key = priority_queue_max_sched_pri(&pq);
	T_ASSERT_EQ(key, increase_pri, "verify priority_queue_entry_increased() operation");

	/* Test the priority decrease operation by updating the last node added */
	priority_queue_entry_set_sched_pri(&pq, &node->ke, decrease_pri, 0);
	update_result = priority_queue_entry_decreased(&pq, &node->ke);
	T_ASSERT_TRUE(update_result, "decrease key updated root");
	key = priority_queue_max_sched_pri(&pq);
	T_ASSERT_EQ(key, decrease_pri, "verify priority_queue_entry_decreased() operation");

	/* Update our local priority list as well */
	priority_list[PRIORITY_QUEUE_NODES - 1] = decrease_pri;

	/* Sort the local list in descending order */
	qsort(priority_list, PRIORITY_QUEUE_NODES, sizeof(priority_list[0]), compare_numbers_descending);

	priority_queue_entry_sched_t k = NULL;

	node = pqe_element_fast(k, test_node, ke);

	/* Test the maximum operation by comparing max node with local list */
	for (int i = 0; i < PRIORITY_QUEUE_NODES; i++) {
		key = priority_queue_max_sched_pri(&pq);
		T_ASSERT_EQ(key, priority_list[i], "[%d] priority queue max node removal", i);
		node = priority_queue_remove_max(&pq, test_node, ke);
		delete node;
	}

	T_ASSERT_TRUE(priority_queue_empty(&pq), "queue is empty");
	priority_queue_destroy(&pq, union test_node, ke, ^(test_node_t n) {
		T_FAIL("Called with %p", n);
	});
}

T_DECL(priority_queue_max, "Basic generic priority queue testing")
{
	/* Configuration for the test */
	static uint16_t priority_list[] = { 20, 3, 7, 6, 50, 2, 8, 12};

	struct priority_queue_max pq;
	uint16_t increase_pri = 100;
	uint16_t decrease_pri = 90;
	test_node_t result;
	boolean_t update_result = false;
	test_node_t node = NULL;

	priority_queue_compare_fn_t cmp_fn =
	    priority_heap_make_comparator(a, b, union test_node, e, {
		if (a->node_key != b->node_key) {
		        return priority_heap_compare_ints(a->node_key, b->node_key);
		}
		return 0;
	});

	priority_queue_init(&pq, cmp_fn);

	/* Add all priorities to the first priority queue */
	for (int i = 0; i < PRIORITY_QUEUE_NODES; i++) {
		node = new test_node;
		T_QUIET; T_ASSERT_NOTNULL(node, NULL);

		priority_queue_entry_init(&node->e);
		node->node_key = priority_list[i];
		priority_queue_insert(&pq, &node->e);
	}

	/* Test the priority increase operation by updating the last node added (8) */
	node->node_key = increase_pri;
	update_result = priority_queue_entry_increased(&pq, &node->e);
	T_ASSERT_TRUE(update_result, "increase key updated root");
	result = priority_queue_max(&pq, union test_node, e);
	T_ASSERT_EQ(result->node_key, increase_pri, "verify priority_queue_entry_increased() operation");


	/* Test the priority decrease operation by updating the last node added */
	node->node_key = decrease_pri;
	update_result = priority_queue_entry_decreased(&pq, &node->e);
	T_ASSERT_TRUE(update_result, "decrease key updated root");
	result = priority_queue_max(&pq, union test_node, e);
	T_ASSERT_EQ(result->node_key, decrease_pri, "verify priority_queue_entry_decreased() operation");

	/* Update our local priority list as well */
	priority_list[PRIORITY_QUEUE_NODES - 1] = decrease_pri;

	/* Sort the local list in descending order */
	qsort(priority_list, PRIORITY_QUEUE_NODES, sizeof(priority_list[0]), compare_numbers_descending);

	/* Test the maximum operation by comparing max node with local list */
	for (int i = 0; i < PRIORITY_QUEUE_NODES; i++) {
		result = priority_queue_remove_max(&pq, union test_node, e);
		T_ASSERT_EQ(result->node_key, priority_list[i],
		    "[%d] priority queue max node removal", i);
		delete result;
	}

	T_ASSERT_TRUE(priority_queue_empty(&pq), "queue is empty");
	priority_queue_destroy(&pq, union test_node, e, ^(test_node_t n) {
		T_FAIL("Called with %p", n);
	});
}

T_DECL(priority_queue_sched_stable_max, "Basic stable sched priority queue testing")
{
	/* Configuration for the test */
	static struct config {
		uint16_t pri;
		priority_queue_entry_sched_modifier_t modifier;
		uint64_t stamp;
	} config[] = {
		{ 20, PRIORITY_QUEUE_ENTRY_NONE, 8 },
		{  3, PRIORITY_QUEUE_ENTRY_NONE, 7 },
		{  3, PRIORITY_QUEUE_ENTRY_PREEMPTED, 6 },
		{  6, PRIORITY_QUEUE_ENTRY_NONE, 5 },
		{ 50, PRIORITY_QUEUE_ENTRY_PREEMPTED, 4 },
		{ 50, PRIORITY_QUEUE_ENTRY_PREEMPTED, 3 },
		{ 50, PRIORITY_QUEUE_ENTRY_NONE, 2 },
		{ 50, PRIORITY_QUEUE_ENTRY_NONE, 1 },
	};

	struct priority_queue_sched_stable_max pq;
	test_node_t node = NULL;

	priority_queue_init(&pq);

	/* Add all priorities to the first priority queue */
	for (int i = 0; i < PRIORITY_QUEUE_NODES; i++) {
		node = new test_node;
		T_QUIET; T_ASSERT_NOTNULL(node, NULL);

		priority_queue_entry_init(node);
		node->se.stamp = config[i].stamp;
		priority_queue_entry_set_sched_pri(&pq, &node->se,
		    config[i].pri, config[i].modifier);
		priority_queue_insert(&pq, &node->se);
	}

	/* Sort the local list in descending order */
	qsort_b(config, PRIORITY_QUEUE_NODES, sizeof(struct config), ^(const void *a, const void *b){
		const struct config &c1 = *(const struct config *)a;
		const struct config &c2 = *(const struct config *)b;
		if (c1.pri != c2.pri) {
		        return c1.pri < c2.pri ? 1 : -1;
		}
		if (c1.modifier != c2.modifier) {
		        return c1.modifier < c2.modifier ? 1 : -1;
		}
		if (c1.stamp != c2.stamp) {
		        if (c1.modifier) {
		                /* younger is better */
		                return c1.stamp < c1.stamp ? 1 : -1;
			} else {
		                /* older is better */
		                return c1.stamp > c2.stamp ? 1 : -1;
			}
		}
		return 0;
	});

	/* Test the maximum operation by comparing max node with local list */
	for (int i = 0; i < PRIORITY_QUEUE_NODES; i++) {
		node = priority_queue_max(&pq, union test_node, se);
		T_LOG("[%d]: { pri: %2d, modifier: %d, stamp: %lld }\n",
		    i, config[i].pri, config[i].modifier, config[i].stamp);
		auto pri = priority_queue_entry_sched_pri(&pq, &node->se);
		T_ASSERT_EQ(pri, config[i].pri,
		    "[%d] priority queue max node removal", i);
		auto modifier = priority_queue_entry_sched_modifier(&pq, &node->se);
		T_ASSERT_EQ(modifier, config[i].modifier,
		    "[%d] priority queue max node removal", i);
		T_ASSERT_EQ(node->se.stamp, config[i].stamp,
		    "[%d] priority queue max node removal", i);
		priority_queue_remove_max(&pq, union test_node, se);
		delete node;
	}

	T_ASSERT_TRUE(priority_queue_empty(&pq), "queue is empty");
	priority_queue_destroy(&pq, union test_node, se, ^(test_node_t n) {
		T_FAIL("Called with %p", n);
	});
}
