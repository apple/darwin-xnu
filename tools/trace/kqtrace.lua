#!/usr/local/bin/luatrace -s

trace_eventname = function(codename, callback)
	local debugid = trace.debugid(codename)
	if debugid ~= 0 then
		trace.single(debugid,callback)
	else
		printf("WARNING: Cannot locate debugid for '%s'\n", codename)
	end
end

initial_timestamp = 0

function event_prefix_string(buf, workq)
	if initial_timestamp == 0 then
		initial_timestamp = buf.timestamp
	end
	local secs = trace.convert_timestamp_to_nanoseconds(buf.timestamp - initial_timestamp) / 1000000000

	local type
	if trace.debugid_is_start(buf.debugid) then
		type = "→"
	elseif trace.debugid_is_end(buf.debugid) then
		type = "←"
	else
		type = "↔"
	end

	proc = buf.command

	local prefix = string.format("%s %6.9f %-17s [%05d.%06x] %-28s\t",
		type, secs, proc, buf.pid, buf.threadid, buf.debugname)
	if not workq then
		prefix = prefix .. string.format(" 0x%16x", buf.arg1)
	end

	return prefix
end

function qos_string(qos)
	if qos == 0 then
		return "--"
	elseif qos == 1 then
		return "MT"
	elseif qos == 2 then
		return "BG"
	elseif qos == 3 then
		return "UT"
	elseif qos == 4 then
		return "DF"
	elseif qos == 5 then
		return "IN"
	elseif qos == 6 then
		return "UI"
	elseif qos == 7 then
		return "MG"
	else
		return string.format("??[0x%x]", qos)
	end
end

function state_string(strings, state)
	local str = ''
	local first = true
	for name, bit in pairs(strings) do
		if (state & bit) == bit then
			if not first then
				str = str .. ' '
			end
			str = str .. name
			first = false
		end
	end
	return str
end

kqrequest_state_strings = {
	['THREQUESTED'] = 0x02,
	['WAKEUP'] = 0x04,
	['BOUND'] = 0x08,
	['DRAIN'] = 0x40,
}

kqueue_state_strings = {
	['SEL'] = 0x001,
	['SLEEP'] = 0x002,
	['PROCWAIT'] = 0x004,
	['KEV32'] = 0x008,
	['KEV64'] = 0x010,
	['KEV_QOS'] = 0x020,
	['WORKQ'] = 0x040,
	['WORKLOOP'] = 0x080,
	['PROCESSING'] = 0x100,
	['DRAIN'] = 0x200,
	['WAKEUP'] = 0x400,
	['DYNAMIC'] = 0x800,
}

knote_state_strings = {
	['ACTIVE'] = 0x0001,
	['QUEUED'] = 0x0002,
	['DISABLED'] = 0x0004,
	['DROPPING'] = 0x0008,
	['LOCKED'] = 0x0010,
	['ATTACHING'] = 0x0020,
	['STAYACTIVE'] = 0x0040,
	['DEFERDELETE'] = 0x0080,
	['ATTACHED'] = 0x0100,
	['DISPATCH'] = 0x0200,
	['UDATA_SPECIFIC'] = 0x0400,
	['SUPPRESSED'] = 0x0800,
	['MERGE_QOS'] = 0x1000,
	['REQVANISH'] = 0x2000,
	['VANISHED'] = 0x4000,
}

kevent_flags_strings = {
	['ADD'] = 0x0001,
	['DELETE'] = 0x0002,
	['ENABLE'] = 0x0004,
	['DISABLE'] = 0x0008,
	['ONESHOT'] = 0x0010,
	['CLEAR'] = 0x0020,
	['RECEIPT'] = 0x0040,
	['DISPATCH'] = 0x0080,
	['UDATA_SPECIFIC'] = 0x0100,
	['VANISHED'] = 0x0200,
	['FLAG0'] = 0x1000,
	['FLAG1'] = 0x2000,
	['EOF'] = 0x8000,
	['ERROR'] = 0x4000,
}

function kevent_filter_string(filt)
	if filt == -1 then
		return 'READ'
	elseif filt == -2 then
		return 'WRITE'
	elseif filt == -3 then
		return 'AIO'
	elseif filt == -4 then
		return 'VNODE'
	elseif filt == -5 then
		return 'PROC'
	elseif filt == -6 then
		return 'SIGNAL'
	elseif filt == -7 then
		return 'TIMER'
	elseif filt == -8 then
		return 'MACHPORT'
	elseif filt == -9 then
		return 'FS'
	elseif filt == -10 then
		return 'USER'
	-- -11 unused
	elseif filt == -12 then
		return 'VM'
	elseif filt == -13 then
		return 'SOCK'
	elseif filt == -14 then
		return 'MEMORYSTATUS'
	elseif filt == 15 then
		return 'KQREAD'
	elseif filt == 16 then
		return 'PIPE_R'
	elseif filt == 17 then
		return 'PIPE_W'
	elseif filt == 18 then
		return 'PTSD'
	elseif filt == 19 then
		return 'SOWRITE'
	elseif filt == 20 then
		return 'SOEXCEPT'
	elseif filt == 21 then
		return 'SPEC'
	elseif filt == 22 then
		return 'BPFREAD'
	elseif filt == 23 then
		return 'NECP_FD'
	elseif filt == 24 then
		return 'SKYWALK_CHANNEL_W'
	elseif filt == 25 then
		return 'SKYWALK_CHANNEL_R'
	elseif filt == 26 then
		return 'FSEVENT'
	elseif filt == 27 then
		return 'VN'
	elseif filt == 28 then
		return 'SKYWALK_CHANNEL_E'
	elseif filt == 29 then
		return 'TTY'
	else
		return string.format('[%d]', filt)
	end
end

-- kqueue lifecycle

function processing_begin(workq)
	return function(buf)
		local prefix = event_prefix_string(buf, workq)
		if trace.debugid_is_start(buf.debugid) then
			local qos
			if workq then
				qos = buf.arg2
			else
				qos = buf.arg3
			end
			printf("%s QoS = %s\n", prefix, qos_string(qos))
		else
			printf("%s request thread = 0x%x, kqrequest state = %s\n", prefix,
					buf.arg1, state_string(kqrequest_state_strings, buf.arg2))
		end
	end
end

trace_eventname("KEVENT_kq_processing_begin", processing_begin(false))
trace_eventname("KEVENT_kqwq_processing_begin", processing_begin(true))
trace_eventname("KEVENT_kqwl_processing_begin", processing_begin(false))

function processing_end(workq)
	return function(buf)
		local qos
		if workq then
			qos = buf.arg2
		else
			qos = buf.arg3
		end
		printf("%s QoS = %s\n", event_prefix_string(buf, workq), qos_string(qos))
	end
end

trace_eventname("KEVENT_kq_processing_end", processing_end(false))
trace_eventname("KEVENT_kqwq_processing_end", processing_end(true))
trace_eventname("KEVENT_kqwl_processing_end", processing_end(false))

trace_eventname("KEVENT_kqwq_bind", function(buf)
	printf("%s thread = 0x%x, QoS = %s, kqrequest state = %s\n",
			event_prefix_string(buf, true), buf.arg1, qos_string(buf.arg3),
			state_string(kqrequest_state_strings, buf.arg4))
end)

trace_eventname("KEVENT_kqwq_unbind", function(buf)
	printf("%s thread = 0x%x, QoS = %s\n", event_prefix_string(buf, true),
			buf.arg1, qos_string(buf.arg3))
end)

trace_eventname("KEVENT_kqwl_bind", function(buf)
	qos = buf.arg3 & 0xff
	duplicate = buf.arg3 & (1 << 8)
	kqr_override_qos_delta = buf.arg4 >> 8
	kqr_state = buf.arg4 & 0xff

	printf("%s thread = 0x%x, QoS = %s, override QoS delta = %d, kqrequest state = %s%s\n",
			event_prefix_string(buf, false), buf.arg2, qos_string(qos),
			kqr_override_qos_delta,
			state_string(kqrequest_state_strings, kqr_state),
			duplicate and ", duplicate" or "")
end)

trace_eventname("KEVENT_kqwl_unbind", function(buf)
	flags = buf.arg3
	qos = buf.arg4

	printf("%s thread = 0x%x, QoS = %s, flags = 0x%x\n", event_prefix_string(buf, false),
			buf.arg2, qos_string(qos), flags)
end)

function thread_request(workq)
	return function(buf)
		printf("%s QoS = %s, kqrequest state = %s, override QoS delta = %d\n",
				event_prefix_string(buf, workq), qos_string(buf.arg2),
				state_string(kqrequest_state_strings, buf.arg3), buf.arg3 >> 8)
	end
end

function thread_adjust(buf)
	tid = buf.arg2
	kqr_qos = buf.arg3 >> 8
	new_qos = buf.arg3 & 0xff
	kqr_qos_override = buf.arg4 >> 8
	kqr_state = buf.arg4 & 0xff

	printf("%s thread = 0x%x, old/new QoS = %s/%s, old/new override QoS delta = %d/%d, kqrequest state = %s\n",
			event_prefix_string(buf, false),
			tid,
			qos_string(kqr_qos),
			qos_string(new_qos),
			kqr_qos_override,
			new_qos - kqr_qos,
			state_string(kqrequest_state_strings, kqr_state))
end

trace_eventname("KEVENT_kqwq_thread_request", thread_request(true))
trace_eventname("KEVENT_kqwl_thread_request", thread_request(false))
trace_eventname("KEVENT_kqwl_thread_adjust", thread_adjust)

function kevent_register(workq)
	return function(buf)
		printf("%s kevent udata = 0x%x, kevent filter = %s, kevent flags = %s\n",
				event_prefix_string(buf, workq), buf.arg2,
				kevent_filter_string(buf.arg4),
				state_string(kevent_flags_strings, buf.arg3))
	end
end

trace_eventname("KEVENT_kq_register", kevent_register(false))
trace_eventname("KEVENT_kqwq_register", kevent_register(true))
trace_eventname("KEVENT_kqwl_register", kevent_register(false))

function kevent_process(workq)
	return function(buf)
		printf("%s kevent ident = 0x%x, udata = 0x%x, kevent filter = %s, knote status = %s\n",
				event_prefix_string(buf, workq), buf.arg3 >> 32, buf.arg2,
				kevent_filter_string(buf.arg4),
				state_string(knote_state_strings, buf.arg3 & 0xffffffff))
	end
end

trace_eventname("KEVENT_kq_process", kevent_process(false))
trace_eventname("KEVENT_kqwq_process", kevent_process(true))
trace_eventname("KEVENT_kqwl_process", kevent_process(false))
