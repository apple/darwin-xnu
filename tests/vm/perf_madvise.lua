#!/usr/local/bin/recon

local benchrun = require 'benchrun'
local perfdata = require 'perfdata'
local csv = require 'csv'

require 'strict'

local kDefaultDuration = 15 
local kDefaultSizeMb = 16

local benchmark = benchrun.new {
    name = 'xnu.madvise',
    version = 1,
    arg = arg,
    modify_argparser = function(parser)
        parser:argument {
          name = 'path',
          description = 'Path to perf_madvise binary'
        }
        parser:option{
          name = '--duration',
          description = 'How long, in seconds, to run each iteration',
          default = kDefaultDuration
        }
        parser:option{
            name = '--variant',
            description = 'Which benchmark variant to run (MADV_FREE)',
            default = 'MADV_FREE',
            choices = {"MADV_FREE"}
        }
        parser:option{
            name = '--verbose',
            description = 'Enable verbose logging',
        }
        parser:option{
            name = '--size',
            description = 'Madvise buffer size (MB)',
            default = kDefaultSizeMb
        }
    end
}

local unit = perfdata.unit.custom('pages/sec')
local tests = {
    path = benchmark.opt.path,
}

local args = {benchmark.opt.path, benchmark.opt.variant, benchmark.opt.duration, benchmark.opt.size}
if benchmark.opt.verbose then
    table.insert(args, "-v")
end
args.echo = true
for out in benchmark:run(args) do
    local result = out:match("-----Results-----\n(.*)")
    benchmark:assert(result, "Unable to find result data in output")
    local data = csv.openstring(result, {header = true})
    for field in data:lines() do
        for k, v in pairs(field) do
            benchmark.writer:add_value(k, unit, tonumber(v), {
              [perfdata.larger_better] = true,
              variant = benchmark.opt.variant
            })
        end
    end
end
benchmark.writer:set_primary_metric("Throughput (bytes / CPU second)")

benchmark:finish()
