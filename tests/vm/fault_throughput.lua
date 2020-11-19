#!/usr/local/bin/recon
require 'strict'

local benchrun = require 'benchrun'
local perfdata = require 'perfdata'
local csv = require 'csv'
local sysctl = require 'sysctl'
local os = require 'os'

local kDefaultDuration = 30

local benchmark = benchrun.new {
    name = 'xnu.zero_fill_fault_throughput',
    version = 1,
    arg = arg,
    modify_argparser = function(parser)
        parser:option{
            name = '--cpu-workers',
            description = 'Number of cpu workers'
        }
        parser:flag{
          name = '--through-max-workers',
          description = 'Run benchmark for [1..n] cpu workers'
        }
        parser:flag{
          name = '--through-max-workers-fast',
          description = 'Run benchmark for [1..2] and each power of four value in [4..n] cpu workers'
        }
        parser:option{
          name = '--path',
          description = 'Path to fault throughput binary'
        }
        parser:option{
          name = '--duration',
          description = 'How long, in seconds, to run each iteration',
          default = kDefaultDuration
        }
        parser:option{
            name = '--variant',
            description = 'Which benchmark variant to run (sparate-objects or share-objects)',
            default = 'separate-objects'
        }
    end
}

assert(benchmark.opt.path, "No path supplied for fault throughput binary")
assert(benchmark.opt.variant == "separate-objects" or
    benchmark.opt.variant == "share-objects", "Unsupported benchmark variant")

local ncpus, err = sysctl('hw.logicalcpu_max')
assert(ncpus > 0, 'invalid number of logical cpus')
local cpu_workers = tonumber(benchmark.opt.cpu_workers) or ncpus

local unit = perfdata.unit.custom('pages/sec')
local tests = {}

function QueueTest(num_cores)
    table.insert(tests, {
        path = benchmark.opt.path,
        num_cores = num_cores,
    })
end

if benchmark.opt.through_max_workers then
    for i = 1, cpu_workers do
        QueueTest(i)
    end
elseif benchmark.opt.through_max_workers_fast then
    local i = 1
    while i <= cpu_workers do
        QueueTest(i)
        -- Always do a run with two threads to see what the first part of
        -- the scaling curve looks like
        -- (and to measure perf on dual core systems).
        if i == 1 and cpu_workers >= 2 then
            QueueTest(i + 1)
        end
        i = i * 4
    end
else
    QueueTest(cpu_workers)
end

for _, test in ipairs(tests) do
    local args = {test.path, "-v", benchmark.opt.variant, benchmark.opt.duration, test.num_cores,
                     echo = true}
    for out in benchmark:run(args) do
        local result = out:match("-----Results-----\n(.*)")
        benchmark:assert(result, "Unable to find result data in output")
        local data = csv.openstring(result, {header = true})
        for field in data:lines() do
            for k, v in pairs(field) do
                benchmark.writer:add_value(k, unit, tonumber(v), {
                  [perfdata.larger_better] = true,
                  threads = test.num_cores,
                  variant = benchmark.opt.variant
                })
            end
        end
    end
end

benchmark:finish()
