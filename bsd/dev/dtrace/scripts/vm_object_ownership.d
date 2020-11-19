#!/usr/sbin/dtrace -s

vminfo:::object_ownership_change
{
	old_owner = (task_t)arg1;
	if (old_owner == 0) {
		old_pid = -1;
		old_name = "(nil)";
	} else {
		old_proc = (proc_t)old_owner->bsd_info;
		old_pid = old_proc->p_pid;
		old_name = old_proc->p_comm;
	}
	new_owner = (task_t)arg4;
	if (new_owner == 0) {
		new_pid = -1;
		new_name = "(nil)";
	} else {
		new_proc = (proc_t)new_owner->bsd_info;
		new_pid = new_proc->p_pid;
		new_name = new_proc->p_comm;
	}

	printf("%d[%s] object 0x%p id 0x%x purgeable:%d owner:0x%p (%d[%s]) tag:%d nofootprint:%d -> owner:0x%p (%d[%s]) tag:%d nofootprint:%d",
	       pid, execname, arg0, arg7, ((vm_object_t)arg0)->purgable,
	       old_owner, old_pid, old_name,
	       arg2, arg3,
	       new_owner, new_pid, new_name,
	       arg5, arg6);
	stack();
	ustack();
}
