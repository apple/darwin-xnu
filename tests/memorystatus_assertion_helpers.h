#ifndef MEMORYSTATUS_ASSERTION_HELPERS_H
#define MEMORYSTATUS_ASSERTION_HELPERS_H

#include <stdlib.h>
#include <stdint.h>

#define ASSERTION_STATE_IS_SET          true
#define ASSERTION_STATE_IS_RELINQUISHED false

/* Helper functions for setting and checking memorystatus assertions
 * on processes.
 */

/*
 * Set the jetsam priority and user data for a process.
 *
 * If this request is assertion driven, the kernel will
 * set the process's assertion priority.
 *
 * If this request is not assertion driven, the kernel
 * will set the process's requested priority.
 *
 * The kernel will then apply policy and move the process
 * to the appropriate jetsam priority.
 *
 * Returns:    0 on success
 *	   non-0 on failure
 */
int
set_priority(pid_t pid, int32_t priority, uint64_t user_data, boolean_t is_assertion_driven);

/*
 * Return: true on success
 *         false on failure  --> this asserts a failure and quits test
 */
boolean_t
check_properties(pid_t pid, int32_t expected_priority, int32_t expected_limit_mb, uint64_t expected_user_data, boolean_t expected_assertion_state, const char *test);

/*
 *  Set the active and inactive memlimits for a process.
 *  Set the fatalness for each limit.
 *
 * Returns:     0 on success
 *              non-zero on failure
 */
int
set_memlimits(
	pid_t pid,
	int32_t active_limit_mb, int32_t inactive_limit_mb,
	boolean_t active_is_fatal, boolean_t inactive_is_fatal);

/*
 * Returns:    0 on success
 *	   non-0 on failure
 */
int
set_assertion_priority(pid_t pid, int32_t priority, uint64_t user_data);

/*
 * Returns:    0 on success
 *	   non-0 on failure
 */
int
relinquish_assertion_priority(pid_t pid, uint64_t user_data);

/*
 * Get the priority properties for a single process.
 *
 * This returns the process's effective jetsam priority, jetsam limit,
 * user_data (not kernel related), and proc's kernel state.
 * If this call fails, there is no reason to continue the test.
 *
 * Return: true on success
 *	   false on failure  --> this asserts fail and test quits
 */
boolean_t
get_priority_props(pid_t pid, boolean_t verbose, int32_t *priority, int32_t *limit_mb, uint64_t *user_data, uint32_t *state);

/*
 * Input:
 *	state:   kernel state bits from the get_priority_props() call
 *      expected_assertion_state:
 *		true if process should be holding an assertion state.
 *		false if no assertion state is held (eg: relinquished).
 *
 * Return  true:  verification passed
 *	  false:  verification failed
 */
boolean_t
verify_assertion_state(uint32_t state, boolean_t expected_assertion_state);

#endif /* MEMORYSTATUS_ASSERTION_HELPERS_H */
