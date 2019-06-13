#!/usr/local/bin/luatrace -s

trace_codename = function(codename, callback)
	local debugid = trace.debugid(codename)
	if debugid ~= 0 then
		trace.single(debugid,callback)
	else
		printf("WARNING: Cannot locate debugid for '%s'\n", codename)
	end
end

initial_timestamp = 0
pid_map = {};
get_prefix = function(buf)
	if initial_timestamp == 0 then
		initial_timestamp = buf.timestamp
	end
	local secs = trace.convert_timestamp_to_nanoseconds(buf.timestamp - initial_timestamp) / 1000000000

	local prefix
	if trace.debugid_is_start(buf.debugid) then
		prefix = "→"
	elseif trace.debugid_is_end(buf.debugid) then
		prefix = "←"
	else
		prefix = "↔"
	end

	local proc
	if buf.pid == buf[1] then
		proc = buf.command
		if pid_map[buf[1]] == nil then
			pid_map[buf[1]] = buf.command
		end
	elseif pid_map[buf[1]] ~= nil then
		proc = pid_map[buf[1]]
	else
		proc = "UNKNOWN"
	end

	return string.format("%s %6.9f %-17s [%05d.%06x] %-24s",
		prefix, secs, proc, buf.pid, buf.threadid, buf.debugname)
end

parse_pthread_priority = function(pri)
	pri = pri & 0xffffffff
	if (pri & 0x02000000) == 0x02000000 then
		return "Manager"
	end
	local qos = (pri & 0x00ffff00) >> 8
	if qos == 0x20 then
		return string.format("UI[%x]", pri);
	elseif qos == 0x10 then
		return string.format("IN[%x]", pri);
	elseif qos == 0x08 then
		return string.format("DF[%x]", pri);
	elseif qos == 0x04 then
		return string.format("UT[%x]", pri);
	elseif qos == 0x02 then
		return string.format("BG[%x]", pri);
	elseif qos == 0x01 then
		return string.format("MT[%x]", pri);
	elseif qos == 0x00 then
		return string.format("--[%x]", pri);
	else
		return string.format("??[%x]", pri);
	end
end

parse_thread_qos = function(pri)
	if pri == 7 then
		return string.format("MG", pri);
	elseif pri == 6 then
		return string.format("UI", pri);
	elseif pri == 5 then
		return string.format("IN", pri);
	elseif pri == 4 then
		return string.format("DF", pri);
	elseif pri == 3 then
		return string.format("UT", pri);
	elseif pri == 2 then
		return string.format("BG", pri);
	elseif pri == 1 then
		return string.format("MT", pri);
	elseif pri == 0 then
		return string.format("--", pri);
	else
		return string.format("??[%x]", pri);
	end
end

parse_thactive_req_qos = function(pri)
	if pri ~= 0 then
		return parse_thread_qos(pri)
	end
	return "None"
end

get_thactive = function(low, high)
	return string.format("req: %s, MG: %d, UI: %d, IN: %d, DE: %d, UT: %d, BG: %d, MT: %d",
			parse_thactive_req_qos(high >> (16 * 3)), (high >> (2 * 16)) & 0xffff,
			(high >> (1 * 16)) & 0xffff, (high >> (0 * 16)) & 0xffff,
			(low  >> (3 * 16)) & 0xffff, (low  >> (2 * 16)) & 0xffff,
			(low  >> (1 * 16)) & 0xffff, (low  >> (0 * 16)) & 0xffff)
end

-- workqueue lifecycle

trace_codename("wq_pthread_exit", function(buf)
	local prefix = get_prefix(buf)
	if trace.debugid_is_start(buf.debugid) then
		printf("%s\tprocess is exiting\n",prefix)
	else
		printf("%s\tworkqueue marked as exiting and timer is complete\n",prefix)
	end
end)

trace_codename("wq_workqueue_exit", function(buf)
	local prefix = get_prefix(buf)
	if trace.debugid_is_start(buf.debugid) then
		printf("%s\tall threads have exited, cleaning up\n",prefix)
	else
		printf("%s\tclean up complete\n",prefix)
	end
end)

trace_codename("wq_start_add_timer", function(buf)
	local prefix = get_prefix(buf)
	printf("%s\tarming timer to fire in %d us (flags: %x, reqcount: %d)\n",
		prefix, buf.arg4, buf.arg3, buf.arg2)
end)

trace_codename("wq_add_timer", function(buf)
	local prefix = get_prefix(buf)
	if trace.debugid_is_start(buf.debugid) then
		printf("%s\tadd_timer fired (flags: %x, nthreads: %d, thidlecount: %d)\n",
			prefix, buf.arg2, buf.arg3, buf.arg4)
	elseif trace.debugid_is_end(buf.debugid) then
		printf("%s\tadd_timer completed (start_timer: %x, nthreads: %d, thidlecount: %d)\n",
			prefix, buf.arg2, buf.arg3, buf.arg4)
	end
end)

trace_codename("wq_select_threadreq", function(buf)
	local prefix = get_prefix(buf)
	if buf[2] == 0 then
		printf("%s\tSelection failed: process exiting\n", prefix)
	elseif buf[2] == 1 then
		printf("%s\tSelection failed: no request\n", prefix)
	elseif buf[2] == 2 then
		printf("%s\tSelection failed: throttled\n", prefix)
	end
end)

trace_codename("wq_creator_select", function(buf)
	local prefix = get_prefix(buf)
	if buf[2] == 1 then
		printf("%s\t\tcreator %x overridden at %s\n", prefix, buf[3],
			parse_thread_qos(buf[4]))
	elseif buf[2] == 2 then
		printf("%s\t\tcreator %x selected at %s\n", prefix, buf[3],
			parse_thread_qos(buf[4]))
	elseif buf[2] == 3 then
		printf("%s\t\tcreator idled (%d yields)\n", prefix, buf[4])
	elseif buf[2] == 4 then
		printf("%s\t\tcreator removed (%d yields)\n", prefix, buf[4])
	end
end)

trace_codename("wq_creator_yield", function(buf)
	local prefix = get_prefix(buf)
	local reason = "unknown"
	if buf[2] == 1 then
		reason = "fast steal rate"
	elseif buf[2] == 2 then
		reason = "above ncpu scheduled"
	end
	printf("%s\t\tcreator yielded (%s, current:%d snapshot:%d)\n",
			prefix, reason, buf[3], buf[4])
end)

trace_codename("wq_thread_logical_run", function(buf)
	local prefix = get_prefix(buf)
	if trace.debugid_is_start(buf.debugid) then
		printf("%s\tthread unparking (request %x)\n", prefix, buf[2])
	else
		printf("%s\tthread parking\n", prefix)
	end
end)

trace.enable_thread_cputime()
runthread_time_map = {}
runthread_cputime_map = {}
trace_codename("wq_runthread", function(buf)
	local prefix = get_prefix(buf)
	if trace.debugid_is_start(buf.debugid) then
		printf("%s\tSTART running thread\n", prefix)
		runthread_time_map[buf.threadid] = buf.timestamp;
		runthread_cputime_map[buf.threadid] = trace.cputime_for_thread(buf.threadid);
	elseif runthread_time_map[buf.threadid] then
		local time = buf.timestamp - runthread_time_map[buf.threadid]
		local cputime = trace.cputime_for_thread(buf.threadid) - runthread_cputime_map[buf.threadid]

		local time_ms = trace.convert_timestamp_to_nanoseconds(time) / 1000000
		local cputime_ms = trace.convert_timestamp_to_nanoseconds(cputime) / 1000000

		printf("%s\tDONE running thread: time = %6.6f ms, cputime = %6.6f ms\n",
				prefix, time_ms, cputime_ms)

		runthread_time_map[buf.threadid] = 0
		runthread_cputime_map[buf.threadid] = 0
	elseif trace.debugid_is_end(buf.debugid) then
		printf("%s\tDONE running thread\n", prefix)
	end
end)

trace_codename("wq_thactive_update", function(buf)
	local prefix = get_prefix(buf)
	local thactive = get_thactive(buf[2], buf[3])
	printf("%s\tthactive updated (%s)\n", prefix, thactive)
end)

trace_codename("wq_thread_block", function(buf)
	local prefix = get_prefix(buf)
	local req_pri = parse_thread_qos(buf[3] >> 8)
	if trace.debugid_is_start(buf.debugid) then
		printf("%s\tthread blocked (activecount: %d, priority: %s, req_pri: %s, reqcount: %d, start_timer: %d)\n",
			prefix, buf[2], parse_thread_qos(buf[3] & 0xff), req_pri, buf[4] >> 1, buf[4] & 0x1)
	else
		printf("%s\tthread unblocked (activecount: %d, priority: %s, req_pri: %s, threads_scheduled: %d)\n",
			prefix, buf[2], parse_thread_qos(buf[3] & 0xff), req_pri, buf[4])
	end
end)

trace_codename("wq_thread_create_failed", function(buf)
	local prefix = get_prefix(buf)
	if buf[3] == 0 then
		printf("%s\tfailed to create new workqueue thread, kern_return: 0x%x\n",
			prefix, buf[2])
	elseif buf[3] == 1 then
		printf("%s\tfailed to vm_map workq thread stack: 0x%x\n", prefix, buf[2])
	elseif buf[3] == 2 then
		printf("%s\tfailed to vm_protect workq thread guardsize: 0x%x\n", prefix, buf[2])
	end
end)

trace_codename("wq_thread_create", function(buf)
	printf("%s\tcreated new workqueue thread\n", get_prefix(buf))
end)

trace_codename("wq_thread_terminate", function(buf)
	local prefix = get_prefix(buf)
	local what
	if trace.debugid_is_start(buf.debugid) then
		what = "try to terminate thread"
	else
		what = "terminated thread"
	end
	printf("%s\t%s: currently idle %d\n", prefix, what, buf[2])
end)

trace_codename("wq_wqops_reqthreads", function(buf)
	local prefix = get_prefix(buf)
	printf("%s\tlegacy thread request made for %d threads at %s\n", prefix, buf[2], parse_pthread_priority(buf[3]));
end)

trace_codename("wq_thread_request_initiate", function(buf)
	local prefix = get_prefix(buf)
	printf("%s\tthread request %x made at %s (count:%d)\n", prefix, buf[2], parse_thread_qos(buf[3]), buf[4]);
end)

trace_codename("wq_thread_request_modify", function(buf)
	local prefix = get_prefix(buf)
	printf("%s\tthread request %x priorty updated to %s\n", prefix, buf[2], parse_thread_qos(buf[3]));
end)

trace_codename("wq_thread_request_cancel", function(buf)
	local prefix = get_prefix(buf)
	printf("%s\tthread request %x canceled\n", prefix, buf[2], parse_thread_qos(buf[3]));
end)

trace_codename("wq_constrained_admission", function(buf)
	local prefix = get_prefix(buf)
	if buf[2] == 1 then
		printf("fail: %s\twq_constrained_threads_scheduled=%d >= wq_max_constrained_threads=%d\n",
				prefix, buf[3], buf[4])
	elseif (buf[2] == 2) or (buf[2] == 3) then
		local success = nil;
		if buf[2] == 2 then success = "success"
		else success = "fail" end
		printf("%s\t%s\tthactive_count=%d + busycount=%d >= wq->wq_max_concurrency\n",
				prefix, success, buf[3], buf[4])
	end
end)

trace_codename("wq_death_call", function(buf)
	local prefix = get_prefix(buf)
	if trace.debugid_is_start(buf.debugid) then
		printf("%s\tentering death call\n", prefix);
	elseif trace.debugid_is_end(buf.debugid) then
		printf("%s\tleaving death call\n", prefix);
	else
		printf("%s\tscheduling death call\n", prefix);
	end
end)
--
-- vim:ts=4:sw=4:noet:
