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
get_prefix = function(buf, char)
	-- if initial_timestamp == 0 then
		-- initial_timestamp = buf.timestamp
	-- end
	local secs = trace.convert_timestamp_to_nanoseconds(buf.timestamp - initial_timestamp) / 1000000000

	return string.format("%s %6.9f %-30s",
		char, secs, buf.debugname)
end

initial_arm_timestamp = 0
format_timestamp_arm = function(ts)
	local secs = trace.convert_timestamp_to_nanoseconds(ts - initial_arm_timestamp) / 1000000000
	return string.format("%6.9f", secs);
end

initial_intel_timestamp = 0
format_timestamp_intel = function(ts)
	local secs = (ts - initial_intel_timestamp) / 1000000000
	return string.format("%6.9f", secs);
end

format_timestamp_ns = function(ts)
	local secs = (ts) / 1000000000
	return string.format("%6.9f", secs);
end

trace_codename("MACH_CLOCK_BRIDGE_RESET_TS", function(buf)
	local prefix = get_prefix(buf, "X")
	local reason = "UNKNOWN";
	if buf[3] == 1 then
		reason = "RecvSentinel"
	elseif buf[3] == 2 then
		reason = "ResetTrue"
	elseif buf[3] == 3 then
		reason = "RateZero"
	elseif buf[3] == 4 then
		reason = "TSMismatch"
	end
	printf("%s %-15s ( %-10s %-10s ) ----------------------------------------\n",
		prefix, reason, format_timestamp_arm(buf[1]), format_timestamp_intel(buf[2]))

	-- initial_arm_timestamp = buf[1]
	-- initial_intel_timestamp = buf[2]
end)

trace_codename("MACH_CLOCK_BRIDGE_TS_PARAMS", function(buf)
	local prefix = get_prefix(buf, ">")

	local rate
	if darwin.uint64_to_double then
		rate = darwin.uint64_to_double(buf[3])
	else
		rate = math.nan
	end

	printf("%s %30s( %-10s %-10s ) rate = %f\n",
		prefix, "", format_timestamp_ns(buf[1]), format_timestamp_intel(buf[2]),
		rate)
end)

trace_codename("MACH_CLOCK_BRIDGE_REMOTE_TIME", function(buf)
	local prefix = get_prefix(buf, "-")

	printf("%s ( %-10s %-10s ) @ %-20s\n",
		prefix, format_timestamp_arm(buf[1]), format_timestamp_intel(buf[2]), format_timestamp_arm(buf[3]))
end)

trace_codename("MACH_CLOCK_BRIDGE_RCV_TS", function(buf)
	local prefix = get_prefix(buf, "<")

	if buf[2] == 0xfffffffffffffffe then
		printf("%s ( %-10s  Sleep )\n",
			prefix, format_timestamp_arm(buf[1]), format_timestamp_intel(buf[2]))
	elseif buf[2] == 0xfffffffffffffffd then
		printf("%s ( %-10s Wake )\n",
			prefix, format_timestamp_arm(buf[1]), format_timestamp_intel(buf[2]))
	elseif buf[2] == 0xfffffffffffffffc then
		printf("%s ( %-10s Reset )\n",
			prefix, format_timestamp_arm(buf[1]), format_timestamp_intel(buf[2]))
	else
		local skip = ""
		if buf[1] == 0 then
			skip = "Int handler"
		end
		printf("%s ( %-10s %-10s ) %s\n",
			prefix, format_timestamp_arm(buf[1]), format_timestamp_intel(buf[2]), skip)
	end

end)

trace_codename("MACH_CLOCK_BRIDGE_SKIP_TS", function(buf)
	local prefix = get_prefix(buf, "*")

	if buf[4] > 0 then
		printf("%s SKIP_RESET:%3d (Cur: %-10s Prev:%-10s) %-10s\n",
			prefix, buf[4], format_timestamp_arm(buf[1]), format_timestamp_arm(buf[3]),
			format_timestamp_intel(buf[2]))
	else
		printf("%s SKIP_DISTANCE: (Cur: %-10s Prev: %-10s) %-10s\n",
			prefix, format_timestamp_arm(buf[1]), format_timestamp_arm(buf[3]),
			format_timestamp_intel(buf[2]))
	end

end)

trace_codename("MACH_CLOCK_BRIDGE_TS_MISMATCH", function(buf)
	local prefix = get_prefix(buf, "?")

	local diff = (math.abs(buf[2] - buf[3]))/1000000

	printf("%s ( Cur: %-10s Pred: %-10s Diff: %5.6f ms Count: %d ) @ %-20s\n",
		prefix, format_timestamp_intel(buf[2]), format_timestamp_intel(buf[3]),
		diff, buf[4], format_timestamp_arm(buf[1]))

end)

trace_codename("MACH_CLOCK_BRIDGE_OBSV_RATE", function(buf)
	local prefix = get_prefix(buf, "=")

	local rate
	if darwin.uint64_to_double then
		rate = darwin.uint64_to_double(buf[1])
	else
		rate = math.nan
	end

	printf("%s obsv_rate = %f exceeded limits(0.8, 1.2)\n", prefix, rate)

end)
