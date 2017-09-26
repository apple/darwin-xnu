#!/usr/sbin/dtrace -s

vminfo::vm_map_delete_permanent:
{
	printf("%d[%s]: attempt to delete permanent mapping (0x%llx, 0x%llx) prot 0x%x/0x%x",
	       $pid,
	       execname,
	       (uint64_t) arg0,
	       (uint64_t) arg1,
	       arg2,
	       arg3);
	stack();
	ustack();
}
