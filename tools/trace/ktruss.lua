#!/usr/local/bin/recon

local ktrace = require 'ktrace'

if not arg[1] or arg[1] == '-h' then
  print[[
usage: ktruss <syscall-name> [<more-names> ...]

Use Kernel TRace to print User Space Syscalls (ktruss).]]
  os.exit(arg[1] == nil)
end

local sess = ktrace.Session.new()

for i = 1, #arg do
  sess:add_callback_pair('BSC_' .. arg[i], function (start, finish)
    print(('%s[%d]: %s(0x%x, 0x%x, 0x%x, 0x%x) -> %d'):format(
        sess:procname_for_threadid(start.threadid),
        sess:pid_for_threadid(start.threadid), arg[1], start[1], start[2],
        start[3], start[4], finish[2]))
  end)
end

local ok, err = sess:start()
if not ok then
  io.stderr:write('tracing failed: ', err, '\n')
  os.exit(1)
end
