#!/usr/local/bin/recon
require 'strict'

local benchrun = require 'benchrun'
local perfdata = require 'perfdata'
local sysctl = require 'sysctl'
local csv = require 'csv'

local kDefaultNumWrites = 10000000000

local benchmark = benchrun.new {
    name = 'xnu.per_cpu_counter',
    version = 1,
    arg = arg,
    modify_argparser = function(parser)
        parser:argument{
          name = 'path',
          description = 'Path to benchmark binary'
        }
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
        parser:option {
            name = "--num-writes",
            description = "number of writes",
            default = kDefaultNumWrites
        }
        parser:option{
            name = '--variant',
            description = 'Which benchmark variant to run (scalable, atomic, or racy)',
            default = 'scalable',
            choices = {"scalable", "atomic", "racy"}
        }
    end
}

assert(benchmark.opt.path, "No path supplied for fault throughput binary")

local ncpus, err = sysctl('hw.logicalcpu_max')
assert(ncpus > 0, 'invalid number of logical cpus')
local cpu_workers = tonumber(benchmark.opt.cpu_workers) or ncpus

local writes_per_second = perfdata.unit.custom('writes/sec')
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
    local args = {test.path, benchmark.opt.variant, benchmark.opt.num_writes, test.num_cores,
                     echo = true}
    for out in benchmark:run(args) do
        local result = out:match("-----Results-----\n(.*)")
        benchmark:assert(result, "Unable to find result data in output")
        local data = csv.openstring(result, {header = true})
        for field in data:lines() do
            for k, v in pairs(field) do
                local unit = writes_per_second
                local larger_better = true
                if k == "loss" then
                    unit = percentage
                    larger_better = false
                end
                benchmark.writer:add_value(k, unit, tonumber(v), {
                  [perfdata.larger_better] = larger_better,
                  threads = test.num_cores,
                  variant = benchmark.opt.variant
                })
            end
        end
    end
end

benchmark:finish()
