#!/usr/sbin/dtrace -s

vminfo::log_unnest_badness:
{
	printf("%d[%s]: unexpected unnest(0x%llx, 0x%llx) below 0x%llx",
	       pid,
	       execname,
	       (uint64_t) arg1,
	       (uint64_t) arg2,
	       (uint64_t) arg3);
	stack();
	ustack();
}
