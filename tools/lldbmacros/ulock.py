from xnu import *
from scheduler import GetRecentTimestamp
import xnudefines

ulock_types = {
    1: "COMPARE_AND_WAIT",
    2: "UNFAIR_LOCK",
    3: "UNFAIR_LOCK64_SHARED",
    4: "COMPARE_AND_WAIT64",
    5: "COMPARE_AND_WAIT64_SHARED"
}

@header("{:<20s} {:<20s} {:<20s} {:<10s} {:<20s} {:<20s} {:<20s}".format(
    'ull_t', 'kind', 'addr/obj', 'pid/offs', 'owner', 'turnstile', 'waiters'))
def GetUlockSummary(ull):
    code = int(ull.ull_opcode)
    if ulock_types.has_key(code):
        ull_type = ulock_types[code]
    else:
        ull_type = "{:#x}".format(code)

    s = "{ull: <#20x} {ull_type: <20s}".format(ull=ull, ull_type=ull_type)
    ulk=ull.ull_key
    if int(ulk.ulk_key_type) is 1:
        s += " {ulk.ulk_addr: <#20x} {ulk.ulk_pid: <10d}".format(ulk=ulk)
    elif int(ulk.ulk_key_type) is 2:
        s += " {ulk.ulk_object: <#20x} {ulk.ulk_offset: <10d}".format(ulk=ulk)
    else:
        s += " {:<20s} {:<10s}".format("", "")

    return s + " {ull.ull_owner: <#20x} {ull.ull_turnstile: <#20x} {ull.ull_nwaiters: >7d}".format(ull=ull)

@lldb_command('showallulocks', fancy=True)
def ShowAllUlocks(cmd_args=None, cmd_options={}, O=None):
    """ Display a summary of all the ulocks in the system

        usage: showallulocks
    """

    with O.table(GetUlockSummary.header):
        count = kern.globals.ull_hash_buckets;
        buckets = kern.globals.ull_bucket
        for i in xrange(0, count):
            for ull in IterateLinkageChain(addressof(buckets[i].ulb_head), 'ull_t *', 'ull_hash_link'):
                print GetUlockSummary(ull)
