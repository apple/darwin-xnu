#
# Kernel gdb macros
#
#  These gdb macros should be useful during kernel development in
#  determining what's going on in the kernel.
#
#  All the convenience variables used by these macros begin with $kgm_

set $kgm_vers = 2

echo Loading Kernel GDB Macros package.  Type "help kgm" for more info.\n

define kgm
printf "These are the kernel gdb macros version %d.  ", $kgm_vers
echo  Type "help kgm" for more info.\n
end

document kgm
| These are the kernel gdb macros.  These gdb macros are intended to be
| used when debugging a remote kernel via the kdp protocol.  Typically, you
| would connect to your remote target like so:
|     (gdb) target remote-kdp
|     (gdb) attach <name-of-remote-host>
|
| The following macros are available in this package:
|
|     showalltasks   Display a summary listing of tasks
|     showallacts    Display a summary listing of all activations
|     showallstacks  Display the kernel stacks for all activations
|     showallvm      Display a summary listing of all the vm maps
|     showallvme     Display a summary listing of all the vm map entries
|     showallipc     Display a summary listing of all the ipc spaces
|     showallrights  Display a summary listing of all the ipc rights
|     showallkmods   Display a summary listing of all the kernel modules
|
|     showtask       Display status of the specified task
|     showtaskacts   Display the status of all activations in the task
|     showtaskstacks Display all kernel stacks for all activations in the task
|     showtaskvm     Display status of the specified task's vm_map
|     showtaskvme    Display a summary list of the task's vm_map entries
|     showtaskipc    Display status of the specified task's ipc space
|     showtaskrights Display a summary list of the task's ipc space entries
|
|     showact	     Display status of the specified thread activation
|     showactstack   Display the kernel stack for the specified activation
|
|     showmap	     Display the status of the specified vm_map
|     showmapvme     Display a summary list of the specified vm_map's entries
|
|     showipc        Display the status of the specified ipc space
|     showrights     Display a summary list of all the rights in an ipc space
|
|     showpid        Display the status of the process identified by pid
|     showproc       Display the status of the process identified by a proc pointer
|
|     showkmod	     Display information about a kernel module
|     showkmodaddr   Given an address, display the kernel module and offset
|
|     zprint         Display zone information
|
| Type "help <macro>" for more specific help on a particular macro.
| Type "show user <macro>" to see what the macro is really doing.
end


define showkmodheader
    printf "kmod        address     size        "
    printf "id    refs     version  name\n"
end

define showkmodint
    set $kgm_kmodp = (struct kmod_info *)$arg0
    printf "0x%08x  ", $arg0
    printf "0x%08x  ", $kgm_kmodp->address
    printf "0x%08x  ", $kgm_kmodp->size
    printf "%3d  ", $kgm_kmodp->id
    printf "%5d  ", $kgm_kmodp->reference_count
    printf "%10s  ", &$kgm_kmodp->version
    printf "%s\n", &$kgm_kmodp->name
end

set $kgm_kmodmin = 0xffffffff
set $kgm_fkmodmin = 0x00000000
set $kgm_kmodmax = 0x00000000
set $kgm_fkmodmax = 0xffffffff
set $kgm_pkmod = 0
set $kgm_pkmodst = 0
set $kgm_pkmoden = 0
define showkmodaddr
    printf "0x%x" , $arg0
    if ((unsigned int)$arg0 >= (unsigned int)$kgm_pkmodst) && ((unsigned int)$arg0 <= (unsigned int)$kgm_pkmoden)
	set $kgm_off = ((unsigned int)$arg0 - (unsigned int)$kgm_pkmodst)
	printf " <%s + 0x%x>", $kgm_pkmod->name, $kgm_off
    else
        if  ((unsigned int)$arg0 <= (unsigned int)$kgm_fkmodmax) && ((unsigned int)$arg0 >= (unsigned int)$kgm_fkmodmin)
	    set $kgm_kmodp = (struct kmod_info *)kmod
	    while $kgm_kmodp
		set $kgm_kmod = *$kgm_kmodp
		if $kgm_kmod.address && ($kgm_kmod.address < $kgm_kmodmin)
		    set $kgm_kmodmin = $kgm_kmod.address
		end
		if ($kgm_kmod.address + $kgm_kmod.size) > $kgm_kmodmax
	    	    set $kgm_kmodmax = $kgm_kmod.address
	    	end
	        set $kgm_off = ((unsigned int)$arg0 - (unsigned int)$kgm_kmod.address)
	        if ($kgm_kmod.address <= $arg0) && ($kgm_off <= $kgm_kmod.size)
		    printf " <%s + 0x%x>", $kgm_kmodp->name, $kgm_off
		    set $kgm_pkmod = $kgm_kmodp
		    set $kgm_pkmodst = $kgm_kmod.address
		    set $kgm_pkmoden = $kgm_pkmodst + $kgm_kmod.size
	    	    set $kgm_kmodp = 0
	        else
	    	    set $kgm_kmodp = $kgm_kmod.next
	        end
	    end
	    if !$kgm_pkmod
		set $kgm_fkmodmin = $kgm_kmodmin
		set $kgm_fkmodmax = $kgm_kmodmax
	    end
	end
    end
end
document showkmodaddr
| Given an address, print the offset and name for the kmod containing it
| The following is the syntax:
|     (gdb) showkmodaddr <addr>
end

define showkmod
    showkmodheader
    showkmodint $arg0
end
document showkmod
| Routine to print info about a kernel module
| The following is the syntax:
|     (gdb) showkmod <kmod>
end

define showallkmods
    showkmodheader
    set $kgm_kmodp = (struct kmod_info *)kmod
    while $kgm_kmodp
	showkmodint $kgm_kmodp
    	set $kgm_kmodp = $kgm_kmodp->next
    end
end
document showallkmods
| Routine to print a summary listing of all the kernel modules
| The following is the syntax:
|     (gdb) showallkmods
end

define showactheader
    printf "            activation  "
    printf "thread      pri  state  wait_queue  wait_event\n"
end


define showactint
   printf "            0x%08x  ", $arg0
   set $kgm_actp = *(Thread_Activation *)$arg0
   if $kgm_actp.thread
	set $kgm_thread = *$kgm_actp.thread
	printf "0x%08x  ", $kgm_actp.thread
	printf "%3d  ", $kgm_thread.sched_pri
	set $kgm_state = $kgm_thread.state
	if $kgm_state & 0x80
	    printf "I" 
	end
	if $kgm_state & 0x40
	    printf "P" 
	end
	if $kgm_state & 0x20
	    printf "A" 
	end
	if $kgm_state & 0x10
	    printf "H" 
	end
	if $kgm_state & 0x08
	    printf "U" 
	end
	if $kgm_state & 0x04
	    printf "R" 
	end
	if $kgm_state & 0x02
	    printf "S" 
	end
   	if $kgm_state & 0x01
	    printf "W\t" 
	    printf "0x%08x  ", $kgm_thread.wait_queue
	    output /a $kgm_thread.wait_event
	end
	if $arg1 != 0
	    if ($kgm_thread.kernel_stack != 0)
		if ($kgm_thread.stack_privilege != 0)
			printf "\n\t\tstack_privilege=0x%08x", $kgm_thread.stack_privilege
		end
		printf "\n\t\tkernel_stack=0x%08x", $kgm_thread.kernel_stack
		set $mysp = $kgm_actp->mact.pcb.ss.r1
		set $prevsp = 0
		printf "\n\t\tstacktop=0x%08x", $mysp
	    	while ($mysp != 0) && (($mysp & 0xf) == 0) && ($mysp < 0xb0000000) && ($mysp > $prevsp)
				printf "\n\t\t0x%08x  ", $mysp
				set $kgm_return = *($mysp + 8)
				if ($kgm_return > end)
				    showkmodaddr $kgm_return
				else
				    output /a * ($mysp + 8)
				end
				set $prevsp = $mysp
				set $mysp = * $mysp
		end
		printf "\n\t\tstackbottom=0x%08x", $prevsp
	    else
		printf "\n\t\t\tcontinuation="
		output /a $kgm_thread.continuation
	    end
	    printf "\n"
	else
	    printf "\n"
	end
    end
end	    

define showact
    showactheader
    showactint $arg0 0
end
document showact
| Routine to print out the state of a specific thread activation.
| The following is the syntax:
|     (gdb) showact <activation> 
end


define showactstack
    showactheader
    showactint $arg0 1
end
document showactstack
| Routine to print out the stack of a specific thread activation.
| The following is the syntax:
|     (gdb) showactstack <activation> 
end


define showallacts
    set $kgm_head_taskp = &default_pset.tasks
    set $kgm_taskp = (Task *)($kgm_head_taskp->next)
    while $kgm_taskp != $kgm_head_taskp
        showtaskheader
	showtaskint $kgm_taskp
	showactheader
	set $kgm_head_actp = &($kgm_taskp->thr_acts)
        set $kgm_actp = (Thread_Activation *)($kgm_taskp->thr_acts.next)
	while $kgm_actp != $kgm_head_actp
	    showactint $kgm_actp 0
  	    set $kgm_actp = (Thread_Activation *)($kgm_actp->thr_acts.next)
        end
	printf "\n"
    	set $kgm_taskp = (Task *)($kgm_taskp->pset_tasks.next)
    end
end
document showallacts
| Routine to print out a summary listing of all the thread activations.
| The following is the syntax:
|     (gdb) showallacts
end


define showallstacks
    set $kgm_head_taskp = &default_pset.tasks
    set $kgm_taskp = (Task *)($kgm_head_taskp->next)
    while $kgm_taskp != $kgm_head_taskp
        showtaskheader
	showtaskint $kgm_taskp
	set $kgm_head_actp = &($kgm_taskp->thr_acts)
        set $kgm_actp = (Thread_Activation *)($kgm_taskp->thr_acts.next)
	while $kgm_actp != $kgm_head_actp
	    showactheader
	    showactint $kgm_actp 1
  	    set $kgm_actp = (Thread_Activation *)($kgm_actp->thr_acts.next)
        end
	printf "\n"
    	set $kgm_taskp = (Task *)($kgm_taskp->pset_tasks.next)
    end
end
document showallstacks
| Routine to print out a summary listing of all the thread kernel stacks.
| The following is the syntax:
|     (gdb) showallstacks
end

define showwaitqmembercount
    set $kgm_waitqsubp = (wait_queue_sub_t)$arg0
    set $kgm_sublinksp = &($kgm_waitqsubp->wqs_sublinks)
    set $kgm_wql = (wait_queue_link_t)$kgm_sublinksp->next
    set $kgm_count = 0
    while ( (queue_entry_t)$kgm_wql != (queue_entry_t)$kgm_sublinksp)
        set $kgm_waitqp = $kgm_wql->wql_element->wqe_queue
        if !$kgm_found  
	    showwaitqmemberheader
	    set $kgm_found = 1
        end
        showwaitqmemberint $kgm_waitqp
    end
end

    
define showwaitqmemberint
    set $kgm_waitqp = (wait_queue_t)$arg0
    printf "            0x%08x  ", $kgm_waitqp
    printf "0x%08x  ", $kgm_waitqp->wq_interlock
    if ($kgm_waitqp->wq_fifo)
        printf "Fifo"
    else
	printf "Prio"
    end
    if ($kgm_waitqp->wq_issub)
	printf "S"
    else
	printf " "
    end
    printf "       "
    showwaitqwaitercount $kgm_waitqp
    showwaitqmembercount $kgm_waitqp
    printf "\n"
end


define showwaitqmembers
    set $kgm_waitqsubp = (wait_queue_sub_t)$arg0
    set $kgm_sublinksp = &($kgm_waitqsubp->wqs_sublinks)
    set $kgm_wql = (wait_queue_link_t)$kgm_sublinksp->next
    set $kgm_found = 0
    while ( (queue_entry_t)$kgm_wql != (queue_entry_t)$kgm_sublinksp)
        set $kgm_waitqp = $kgm_wql->wql_element->wqe_queue
        if !$kgm_found  
	    showwaitqmemberheader
	    set $kgm_found = 1
        end
        showwaitqmemberint $kgm_waitqp
    end
end

define showwaitq
    set $kgm_waitq = (wait_queue_t)$arg0
    showwaitqheader
    showwaitqwaiters
    if ($kgm_waitq->wq_issub)
	showwaitqmembers
    end
end

define showmapheader
    printf "vm_map      pmap        vm_size    "
    printf "#ents rpage  hint        first_free\n"
end

define showvmeheader
    printf "            entry       start       "
    printf "prot #page  object      offset\n"
end

define showvmint
    set $kgm_mapp = (vm_map_t)$arg0
    set $kgm_map = *$kgm_mapp
    printf "0x%08x  ", $arg0
    printf "0x%08x  ", $kgm_map.pmap
    printf "0x%08x  ", $kgm_map.size
    printf "%3d  ", $kgm_map.hdr.nentries
    printf "%5d  ", $kgm_map.pmap->stats.resident_count
    printf "0x%08x  ", $kgm_map.hint
    printf "0x%08x\n", $kgm_map.first_free
    if $arg1 != 0
	showvmeheader	
	set $kgm_head_vmep = &($kgm_mapp->hdr.links)
	set $kgm_vmep = $kgm_map.hdr.links.next
	while (($kgm_vmep != 0) && ($kgm_vmep != $kgm_head_vmep))
	    set $kgm_vme = *$kgm_vmep
	    printf "            0x%08x  ", $kgm_vmep
	    printf "0x%08x  ", $kgm_vme.links.start
	    printf "%1x", $kgm_vme.protection
	    printf "%1x", $kgm_vme.max_protection
	    if $kgm_vme.inheritance == 0x0
		printf "S"
	    end
	    if $kgm_vme.inheritance == 0x1
		printf "C"
	    end
	    if $kgm_vme.inheritance == 0x2
		printf "-"
	    end
	    if $kgm_vme.inheritance == 0x3
		printf "D"
	    end
	    if $kgm_vme.is_sub_map
		printf "s "
	    else
		if $kgm_vme.needs_copy
		    printf "n "
		else
		    printf "  "
		end
	    end
	    printf "%5d  ",($kgm_vme.links.end - $kgm_vme.links.start) >> 12
	    printf "0x%08x  ", $kgm_vme.object.vm_object
	    printf "0x%08x\n", $kgm_vme.offset
  	    set $kgm_vmep = $kgm_vme.links.next
        end
    end
    printf "\n"
end


define showmapvme
	showmapheader
	showvmint $arg0 1
end
document showmapvme
| Routine to print out a summary listing of all the entries in a vm_map
| The following is the syntax:
|     (gdb) showmapvme <vm_map>
end


define showmap
	showmapheader
	showvmint $arg0 0
end
document showmap
| Routine to print out a summary description of a vm_map
| The following is the syntax:
|     (gdb) showmap <vm_map>
end

define showallvm
    set $kgm_head_taskp = &default_pset.tasks
    set $kgm_taskp = (Task *)($kgm_head_taskp->next)
    while $kgm_taskp != $kgm_head_taskp
        showtaskheader
	showmapheader
	showtaskint $kgm_taskp
	showvmint $kgm_taskp->map 0
    	set $kgm_taskp = (Task *)($kgm_taskp->pset_tasks.next)
    end
end
document showallvm
| Routine to print a summary listing of all the vm maps
| The following is the syntax:
|     (gdb) showallvm
end


define showallvme
    set $kgm_head_taskp = &default_pset.tasks
    set $kgm_taskp = (Task *)($kgm_head_taskp->next)
    while $kgm_taskp != $kgm_head_taskp
        showtaskheader
	showmapheader
	showtaskint $kgm_taskp
	showvmint $kgm_taskp->map 1
    	set $kgm_taskp = (Task *)($kgm_taskp->pset_tasks.next)
    end
end
document showallvme
| Routine to print a summary listing of all the vm map entries
| The following is the syntax:
|     (gdb) showallvme
end


define showipcheader
    printf "ipc_space   is_table    table_next "
    printf "flags tsize  splaytree   splaybase\n"
end

define showipceheader
    printf "            name        object      "
    printf "rite urefs  destname    destination\n"
end

define showipceint
    set $kgm_ie = *(ipc_entry_t)$arg0
    printf "            0x%08x  ", $arg1
    printf "0x%08x  ", $kgm_ie.ie_object
    if $kgm_ie.ie_bits & 0x00100000
	printf "Dead "
        printf "%5d\n", $kgm_ie.ie_bits & 0xffff
    else
        if $kgm_ie.ie_bits & 0x00080000
	    printf "SET  "
            printf "%5d\n", $kgm_ie.ie_bits & 0xffff
        else
            if $kgm_ie.ie_bits & 0x00010000
	        if $kgm_ie.ie_bits & 0x00020000
	            printf " SR"
	        else
	            printf "  S"
	        end
            else
	        if $kgm_ie.ie_bits & 0x00020000
	           printf "  R"
	        end
            end
            if $kgm_ie.ie_bits & 0x00040000
	        printf "  O"
            end
            if $kgm_ie.index.request
	        printf "n"
            else
                printf " "
            end
            if $kgm_ie.ie_bits & 0x00800000
		printf "c"
    	    else
		printf " "
    	    end
            printf "%5d  ", $kgm_ie.ie_bits & 0xffff
            showportdest $kgm_ie.ie_object
        end
    end
end

define showipcint
    set $kgm_isp = (ipc_space_t)$arg0
    set $kgm_is = *$kgm_isp
    printf "0x%08x  ", $arg0
    printf "0x%08x  ", $kgm_is.is_table
    printf "0x%08x  ", $kgm_is.is_table_next
    if $kgm_is.is_growing != 0
	printf "G"
    else
	printf " "
    end
    if $kgm_is.is_fast != 0
	printf "F"
    else
	printf " "
    end
    if $kgm_is.is_active != 0
	printf "A  "
    else
	printf "   "
    end
    printf "%5d  ", $kgm_is.is_table_size
    printf "0x%08x  ", $kgm_is.is_tree_total
    printf "0x%08x\n", &$kgm_isp->is_tree
    if $arg1 != 0
	showipceheader
	set $kgm_iindex = 0
	set $kgm_iep = $kgm_is.is_table
	set $kgm_destspacep = (ipc_space_t)0
        while ( $kgm_iindex < $kgm_is.is_table_size )
	    set $kgm_ie = *$kgm_iep
	    if $kgm_ie.ie_bits & 0x001f0000
		set $kgm_name = (($kgm_iindex << 8)|($kgm_ie.ie_bits >> 24))
		showipceint $kgm_iep $kgm_name
	    end
	    set $kgm_iindex = $kgm_iindex + 1
	    set $kgm_iep = &($kgm_is.is_table[$kgm_iindex])
	end
	if $kgm_is.is_tree_total
	    printf "Still need to write tree traversal\n"
	end
    end
    printf "\n"
end


define showipc
	set $kgm_isp = (ipc_space_t)$arg0
        showipcheader
	showipcint $kgm_isp 0
end
document showipc
| Routine to print the status of the specified ipc space
| The following is the syntax:
|     (gdb) showipc <ipc_space>
end

define showrights
	set $kgm_isp = (ipc_space_t)$arg0
        showipcheader
	showipcint $kgm_isp 1
end
document showrights
| Routine to print a summary list of all the rights in a specified ipc space
| The following is the syntax:
|     (gdb) showrights <ipc_space>
end


define showtaskipc
	set $kgm_taskp = (task_t)$arg0
	showtaskheader
    showipcheader
	showtaskint $kgm_taskp
	showipcint $kgm_taskp->itk_space 0
end
document showtaskipc
| Routine to print the status of the ipc space for a task
| The following is the syntax:
|     (gdb) showtaskipc <task>
end


define showtaskrights
	set $kgm_taskp = (task_t)$arg0
	showtaskheader
        showipcheader
	showtaskint $kgm_taskp
	showipcint $kgm_taskp->itk_space 1
end
document showtaskrights
| Routine to print a summary listing of all the ipc rights for a task
| The following is the syntax:
|     (gdb) showtaskrights <task>
end

define showallipc
    set $kgm_head_taskp = &default_pset.tasks
    set $kgm_taskp = (Task *)($kgm_head_taskp->next)
    while $kgm_taskp != $kgm_head_taskp
        showtaskheader
        showipcheader
	showtaskint $kgm_taskp
	showipcint $kgm_taskp->itk_space 0
    	set $kgm_taskp = (Task *)($kgm_taskp->pset_tasks.next)
    end
end
document showallipc
| Routine to print a summary listing of all the ipc spaces
| The following is the syntax:
|     (gdb) showallipc
end


define showallrights
    set $kgm_head_taskp = &default_pset.tasks
    set $kgm_taskp = (Task *)($kgm_head_taskp->next)
    while $kgm_taskp != $kgm_head_taskp
        showtaskheader
        showipcheader
	showtaskint $kgm_taskp
	showipcint $kgm_taskp->itk_space 1
    	set $kgm_taskp = (Task *)($kgm_taskp->pset_tasks.next)
    end
end
document showallrights
| Routine to print a summary listing of all the ipc rights
| The following is the syntax:
|     (gdb) showallrights
end


define showtaskvm
	set $kgm_taskp = (task_t)$arg0
	showtaskheader
	showmapheader
	showtaskint $kgm_taskp
	showvmint $kgm_taskp->map 0
end
document showtaskvm
| Routine to print out a summary description of a task's vm_map
| The following is the syntax:
|     (gdb) showtaskvm <task>
end

define showtaskvme
	set $kgm_taskp = (task_t)$arg0
	showtaskheader
	showmapheader
	showtaskint $kgm_taskp
	showvmint $kgm_taskp->map 1
end
document showtaskvme
| Routine to print out a summary listing of a task's vm_map_entries
| The following is the syntax:
|     (gdb) showtaskvme <task>
end


define showtaskheader
    printf "task        vm_map      ipc_space  #acts  "
    showprocheader
end


define showtaskint
    set $kgm_task = *(Task *)$arg0
    printf "0x%08x  ", $arg0
    printf "0x%08x  ", $kgm_task.map
    printf "0x%08x  ", $kgm_task.itk_space
    printf "%3d  ", $kgm_task.thr_act_count
    showprocint $kgm_task.bsd_info
end

define showtask
    showtaskheader
    showtaskint $arg0
end
document showtask
| Routine to print out info about a task.
| The following is the syntax:
|     (gdb) showtask <task>
end


define showtaskacts
    showtaskheader
    set $kgm_taskp = (Task *)$arg0
    showtaskint $kgm_taskp
    showactheader
    set $kgm_head_actp = &($kgm_taskp->thr_acts)
    set $kgm_actp = (Thread_Activation *)($kgm_taskp->thr_acts.next)
    while $kgm_actp != $kgm_head_actp
	showactint $kgm_actp 0
    	set $kgm_actp = (Thread_Activation *)($kgm_actp->thr_acts.next)
    end
end
document showtaskacts
| Routine to print a summary listing of the activations in a task
| The following is the syntax:
|     (gdb) showtaskacts <task>
end


define showtaskstacks
    showtaskheader
    set $kgm_taskp = (Task *)$arg0
    showtaskint $kgm_taskp
    set $kgm_head_actp = &($kgm_taskp->thr_acts)
    set $kgm_actp = (Thread_Activation *)($kgm_taskp->thr_acts.next)
    while $kgm_actp != $kgm_head_actp
        showactheader
	showactint $kgm_actp 1
    	set $kgm_actp = (Thread_Activation *)($kgm_actp->thr_acts.next)
    end
end
document showtaskstacks
| Routine to print a summary listing of the activations in a task and their stacks
| The following is the syntax:
|     (gdb) showtaskstacks <task>
end


define showalltasks
    showtaskheader
    set $kgm_head_taskp = &default_pset.tasks
    set $kgm_taskp = (Task *)($kgm_head_taskp->next)
    while $kgm_taskp != $kgm_head_taskp
	showtaskint $kgm_taskp
    	set $kgm_taskp = (Task *)($kgm_taskp->pset_tasks.next)
    end
end
document showalltasks
| Routine to print a summary listing of all the tasks
| The following is the syntax:
|     (gdb) showalltasks
end


define showprocheader
    printf " pid  proc        command\n"
end

define showprocint
    set $kgm_procp = (struct proc *)$arg0
    if $kgm_procp != 0
        printf "%5d  ", $kgm_procp->p_pid
	printf "0x%08x  ", $kgm_procp
	printf "%s\n", $kgm_procp->p_comm
    else
	printf "  *0*  0x00000000  --\n"
    end
end

define showpid
    showtaskheader
    set $kgm_head_taskp = &default_pset.tasks
    set $kgm_taskp = (Task *)($kgm_head_taskp->next)
    while $kgm_taskp != $kgm_head_taskp
	set $kgm_procp = (struct proc *)$kgm_taskp->bsd_info
	if (($kgm_procp != 0) && ($kgm_procp->p_pid == $arg0))
	    showtaskint $kgm_taskp
	    set $kgm_taskp = $kgm_head_taskp
	else
    	    set $kgm_taskp = (Task *)($kgm_taskp->pset_tasks.next)
	end
    end
end
document showpid
| Routine to print a single process by pid
| The following is the syntax:
|     (gdb) showpid <pid>
end

define showproc
    showtaskheader
    set $kgm_procp = (struct proc *)$arg0
    showtaskint $kgm_procp->task $arg1 $arg2
end


define kdb
    set switch_debugger=1
    continue
end
document kdb
| kdb - Switch to the inline kernel debugger
|
| usage: kdb
|
| The kdb macro allows you to invoke the inline kernel debugger.
end

define showpsetheader
    printf "portset     waitqueue   recvname    "
    printf "flags refs  recvname    process\n"
end

define showportheader
    printf "port        mqueue      recvname    "
    printf "flags refs  recvname    process\n"
end

define showportmemberheader
    printf "            port        recvname    "
    printf "flags refs  mqueue      msgcount\n"
end

define showkmsgheader
    printf "            kmsg        size        "
    printf "disp msgid  remote-port local-port\n"
end

define showkmsgint
    printf "            0x%08x  ", $arg0
    set $kgm_kmsgh = ((ipc_kmsg_t)$arg0)->ikm_header
    printf "0x%08x  ", $kgm_kmsgh.msgh_size
    if (($kgm_kmsgh.msgh_bits & 0xff) == 19)
	printf "rC"
    else
	printf "rM"
    end
    if (($kgm_kmsgh.msgh_bits & 0xff00) == (19 < 8))
	printf "lC"
    else
	printf "lM"
    end
    if ($kgm_kmsgh.msgh_bits & 0xf0000000)
	printf "c"
    else
	printf "s"
    end
    printf "%5d  ", $kgm_kmsgh.msgh_msgid
    printf "0x%08x  ", $kgm_kmsgh.msgh_remote_port
    printf "0x%08x\n", $kgm_kmsgh.msgh_local_port
end



define showkobject
    set $kgm_portp = (ipc_port_t)$arg0
    printf "0x%08x  kobject(", $kgm_portp->ip_kobject
    set $kgm_kotype = ($kgm_portp->ip_object.io_bits & 0x00000fff)
    if ($kgm_kotype == 1)
	printf "THREAD"
    end
    if ($kgm_kotype == 2)
	printf "TASK"
    end
    if ($kgm_kotype == 3)
	printf "HOST"
    end
    if ($kgm_kotype == 4)
	printf "HOST_PRIV"
    end
    if ($kgm_kotype == 5)
	printf "PROCESSOR"
    end
    if ($kgm_kotype == 6)
	printf "PSET"
    end
    if ($kgm_kotype == 7)
	printf "PSET_NAME"
    end
    if ($kgm_kotype == 8)
	printf "TIMER"
    end
    if ($kgm_kotype == 9)
	printf "PAGER_REQ"
    end
    if ($kgm_kotype == 10)
	printf "DEVICE"
    end
    if ($kgm_kotype == 11)
	printf "XMM_OBJECT"
    end
    if ($kgm_kotype == 12)
	printf "XMM_PAGER"
    end
    if ($kgm_kotype == 13)
	printf "XMM_KERNEL"
    end
    if ($kgm_kotype == 14)
	printf "XMM_REPLY"
    end
    if ($kgm_kotype == 15)
	printf "NOTDEF 15"
    end
    if ($kgm_kotype == 16)
	printf "NOTDEF 16"
    end
    if ($kgm_kotype == 17)
	printf "HOST_SEC"
    end
    if ($kgm_kotype == 18)
	printf "LEDGER"
    end
    if ($kgm_kotype == 19)
	printf "MASTER_DEV"
    end
    if ($kgm_kotype == 20)
	printf "ACTIVATION"
    end
    if ($kgm_kotype == 21)
	printf "SUBSYSTEM"
    end
    if ($kgm_kotype == 22)
	printf "IO_DONE_QUE"
    end
    if ($kgm_kotype == 23)
	printf "SEMAPHORE"
    end
    if ($kgm_kotype == 24)
	printf "LOCK_SET"
    end
    if ($kgm_kotype == 25)
	printf "CLOCK"
    end
    if ($kgm_kotype == 26)
	printf "CLOCK_CTRL"
    end
    if ($kgm_kotype == 27)
	printf "IOKIT_SPARE"
    end
    if ($kgm_kotype == 28)
	printf "NAMED_MEM"
    end
    if ($kgm_kotype == 29)
	printf "IOKIT_CON"
    end
    if ($kgm_kotype == 30)
	printf "IOKIT_OBJ"
    end
    if ($kgm_kotype == 31)
	printf "UPL"
    end
    printf ")\n"
end

define showportdestproc
    set $kgm_portp = (ipc_port_t)$arg0
    set $kgm_spacep = $kgm_portp->data.receiver
#   check against the previous cached value - this is slow
    if ($kgm_spacep != $kgm_destspacep)
	set $kgm_destprocp = (struct proc *)0
        set $kgm_head_taskp = &default_pset.tasks
        set $kgm_taskp = (Task *)($kgm_head_taskp->next)
        while (($kgm_destprocp == 0) && ($kgm_taskp != $kgm_head_taskp))
	    set $kgm_destspacep = $kgm_taskp->itk_space
	    if ($kgm_destspacep == $kgm_spacep)
	       set $kgm_destprocp = (struct proc *)$kgm_taskp->bsd_info
	    else
    	       set $kgm_taskp = (Task *)($kgm_taskp->pset_tasks.next)
            end
        end
    end
    if $kgm_destprocp != 0
       printf "%s(%d)\n", $kgm_destprocp->p_comm, $kgm_destprocp->p_pid
    else
       printf "task 0x%08x\n", $kgm_taskp
    end
end

define showportdest
    set $kgm_portp = (ipc_port_t)$arg0
    set $kgm_spacep = $kgm_portp->data.receiver
    if ($kgm_spacep == ipc_space_kernel)
	showkobject $kgm_portp
    else
	if ($kgm_portp->ip_object.io_bits & 0x80000000)
	    printf "0x%08x  ", $kgm_portp->ip_object.io_receiver_name
	    showportdestproc $kgm_portp
	else
	    printf "0x%08x  inactive-port\n", $kgm_portp
	end
    end
end

define showportmember
    printf "            0x%08x  ", $arg0
    set $kgm_portp = (ipc_port_t)$arg0
    printf "0x%08x  ", $kgm_portp->ip_object.io_receiver_name
    if ($kgm_portp->ip_object.io_bits & 0x80000000)
	printf "A"
    else
	printf " "
    end
    if ($kgm_portp->ip_object.io_bits & 0x7fff0000)
	printf "Set "
    else
	printf "Port"
    end
    printf "%5d  ", $kgm_portp->ip_object.io_references
    printf "0x%08x  ", &($kgm_portp->ip_messages)
    printf "0x%08x\n", $kgm_portp->ip_messages.data.port.msgcount
end

define showportint
    printf "0x%08x  ", $arg0
    set $kgm_portp = (ipc_port_t)$arg0
    printf "0x%08x  ", &($kgm_portp->ip_messages)
    printf "0x%08x  ", $kgm_portp->ip_object.io_receiver_name
    if ($kgm_portp->ip_object.io_bits & 0x80000000)
	printf "A"
    else
	printf "D"
    end
    printf "Port"
    printf "%5d  ", $kgm_portp->ip_object.io_references
    set $kgm_destspacep = (ipc_space_t)0
    showportdest $kgm_portp
    set $kgm_kmsgp = (ipc_kmsg_t)$kgm_portp->ip_messages.data.port.messages.ikmq_base
    if $arg1 && $kgm_kmsgp
	showkmsgheader
	showkmsgint $kgm_kmsgp
	set $kgm_kmsgheadp = $kgm_kmsgp
	set $kgm_kmsgp = $kgm_kmsgp->ikm_next
	while $kgm_kmsgp != $kgm_kmsgheadp
	    showkmsgint $kgm_kmsgp
	    set $kgm_kmsgp = $kgm_kmsgp->ikm_next
        end
    end
end

define showpsetint
    printf "0x%08x  ", $arg0
    set $kgm_psetp = (ipc_pset_t)$arg0
    printf "0x%08x  ", &($kgm_psetp->ips_messages)
    printf "0x%08x  ", $kgm_psetp->ips_object.io_receiver_name
    if ($kgm_psetp->ips_object.io_bits & 0x80000000)
	printf "A"
    else
	printf "D"
    end
    printf "Set "
    printf "%5d  ", $kgm_psetp->ips_object.io_references
    set $kgm_sublinksp = &($kgm_psetp->ips_messages.data.set_queue.wqs_sublinks)
    set $kgm_wql = (wait_queue_link_t)$kgm_sublinksp->next
    set $kgm_found = 0
    while ( (queue_entry_t)$kgm_wql != (queue_entry_t)$kgm_sublinksp)
        set $kgm_portp = (ipc_port_t)((int)($kgm_wql->wql_element->wqe_queue) - ((int)$kgm_portoff))
	if !$kgm_found  
	    set $kgm_destspacep = (ipc_space_t)0
	    showportdest $kgm_portp
	    showportmemberheader
	    set $kgm_found = 1
	end
	showportmember $kgm_portp 0
	set $kgm_wql = (wait_queue_link_t)$kgm_wql->wql_sublinks.next
    end
    if !$kgm_found   
	printf "--n/e--     --n/e--\n"
    end
end

define showpset
    showpsetheader
    showpsetint $arg0 1
end

define showport
    showportheader
    showportint $arg0 1
end

define showipcobject
    set $kgm_object = (ipc_object_t)$arg0
    if ($kgm_objectp->io_bits & 0x7fff0000)
	showpset $kgm_objectp
    else
	showport $kgm_objectp
    end
end

define showmqueue
    set $kgm_mqueue = *(ipc_mqueue_t)$arg0
    set $kgm_psetoff = &(((ipc_pset_t)0)->ips_messages)
    set $kgm_portoff = &(((ipc_port_t)0)->ip_messages)
    if ($kgm_mqueue.data.set_queue.wqs_wait_queue.wq_issub)
	set $kgm_pset = (((int)$arg0) - ((int)$kgm_psetoff))
        showpsetheader
	showpsetint $kgm_pset 1
    else
	showportheader
	set $kgm_port = (((int)$arg0) - ((int)$kgm_portoff))
	showportint $kgm_port 1
    end
end

define zprint_one
set $kgm_zone = (struct zone *)$arg0

printf "0x%08x ", $kgm_zone
printf "%8d ",$kgm_zone->count
printf "%8x ",$kgm_zone->cur_size
printf "%8x ",$kgm_zone->max_size
printf "%6d ",$kgm_zone->elem_size
printf "%8x ",$kgm_zone->alloc_size
printf "%s ",$kgm_zone->zone_name

if ($kgm_zone->exhaustible)
	printf "H"
end
if ($kgm_zone->collectable)
	printf "C"
end
if ($kgm_zone->expandable)
	printf "X"
end
printf "\n"
end


define zprint
printf "ZONE          COUNT   TOT_SZ   MAX_SZ ELT_SZ ALLOC_SZ NAME\n"
set $kgm_zone_ptr = (struct zone *)first_zone
while ($kgm_zone_ptr != 0)
	zprint_one $kgm_zone_ptr
	set $kgm_zone_ptr = $kgm_zone_ptr->next_zone
end
printf "\n"
end
document zprint
| Routine to print a summary listing of all the kernel zones
| The following is the syntax:
|     (gdb) zprint
end

