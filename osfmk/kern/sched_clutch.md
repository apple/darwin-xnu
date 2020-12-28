# Clutch Scheduler

## Background

The XNU kernel runs on a variety of platforms with strong requirements for being dynamic and efficient. It needs to deliver on a wide range of requirements; from quick access to CPU for latency sensitive workloads (eg. UI interactions, multimedia recording/playback) to starvation avoidance for lower priority batch workloads (eg. photos sync, source compilation). The traditional Mach scheduler attempts to achieve these goals by expecting all threads in the system to be tagged with a priority number and treating high priority threads as interactive threads and low priority threads as batch threads. It then uses a timesharing model based on priority decay to penalize threads as they use CPU to achieve fairshare and starvation avoidance. This approach however loses the relationship between threads and higher level user workloads, making it impossible for the scheduler to reason about the workload as a whole which is what the end user cares about. One artifact of this thread based timesharing approach is that threads at the same priority level are treated similarly irrespective of which user workload they are servicing, which often leads to non-optimal decisions. It ultimately leads to priority inflation across the platform with individual subsystems raising their priority to avoid starvation and timesharing with other unrelated threads. The traditional thread level scheduling model also suffers from the following issues:

* **Inaccurate accounting**: CPU accounting at the thread level incentivizes creating more threads on the system. Also in the world of GCD and workqueues where threads are created and destroyed rapidly, thread level accounting is inaccurate and allows excessive CPU usage.
* **Poor isolation**: In the Mach scheduler, timesharing is achieved by decaying the priority of threads depending on global system load. This property could lead to a burst of activity at the same or lower priority band causing decay for the App/UI thread leading to poor performance and responsiveness. The scheduler offers very limited isolation between threads working on latency sensitive UI workloads and threads performing bulk non-latency sensitive operations.

## Clutch Scheduler Design

In order to reason about higher level user workloads, the clutch scheduler schedules groups of threads instead of individual threads. Breaking away from the traditional single-tier scheduling model, it implements a hierarchical scheduler which makes optimal decisions at various thread grouping levels. The hierarchical scheduler, as its implemented today, has 3 levels:

* Scheduling Bucket Level
* Thread Group Level
* Thread Level

### Scheduling Bucket Level

The highest level is the scheduling bucket level which decides which class of threads should be picked for execution. The kernel maintains a notion of scheduling bucket per thread which are defined based on the base/scheduling priority of the threads. These scheduling buckets roughly map to the QoS classes used by the OS runtime to define performance expectations for various pieces of work. All runnable threads with the same scheduling bucket are represented by a single entry at this level. These entries are known as *root buckets* throughout the implementation. The goal of this level is to provide low latency access to the CPU for high QoS classes while ensuring starvation avoidance for the low QoS classes.

**Implementation**

The scheduling bucket level uses an Earliest Deadline First (EDF) algorithm to decide which root bucket should be selected next for execution. Each root bucket with runnable threads is represented as an entry in a priority queue which is ordered by the bucket's deadline. The bucket selection algorithm simply selects the root bucket with the earliest deadline in the priority queue. The deadline for a root bucket is calculated based on its first-runnable timestamp and its **Worst Case Execution Latency (WCEL)** value which is pre-defined for each bucket. The WCEL values are picked based on the decay curve followed by the Mach timesharing algorithm to allow the system to function similar to the existing scheduler from a higher level perspective.

```
static uint32_t sched_clutch_root_bucket_wcel_us[TH_BUCKET_SCHED_MAX] = {
        SCHED_CLUTCH_INVALID_TIME_32,                   /* FIXPRI */
        0,                                              /* FG */
        37500,                                          /* IN (37.5ms) */
        75000,                                          /* DF (75ms) */
        150000,                                         /* UT (150ms) */
        250000                                          /* BG (250ms) */
};
```

Whenever a root bucket transitions from non-runnable to runnable, its deadline is set to (now + WCEL[bucket]). This ensures that the bucket would be scheduled at WCEL[bucket] even in a heavily loaded system. Once the root bucket is picked for execution, its deadline is pushed by WCEL[bucket] into the future. This basic implementation of EDF suffers from one major issue. In a heavily loaded system, it is possible that the higher buckets have used up enough CPU in the recent past such that its behind the lower buckets in deadline order. Now, if a small burst of user-critical workload shows up, the high bucket has to wait for the lower buckets to run before it can get CPU which might lead to performance issues. In order to address that, the bucket level scheduler implements a root bucket warp mechanism. Each bucket is provided a warp value which is refreshed whenever the bucket is selected due to its deadline expiring. 

```
static uint32_t sched_clutch_root_bucket_warp_us[TH_BUCKET_SCHED_MAX] = {
        SCHED_CLUTCH_INVALID_TIME_32,                   /* FIXPRI */
        8000,                                           /* FG (8ms)*/
        4000,                                           /* IN (4ms) */
        2000,                                           /* DF (2ms) */
        1000,                                           /* UT (1ms) */
        0                                               /* BG (0ms) */
};
```
The root bucket selection logic finds the earliest deadline bucket and then checks if there are any higher (in natural priority order) buckets that have warp remaining. If there is such a higher bucket, it would select that bucket and effectively open a warp window. During this warp window the scheduler would continue to select this warping bucket over lower priority buckets. Once the warping bucket is drained or the warp window expires, the scheduler goes back to scheduling buckets in deadline order. This mechanism provides a bounded advantage to higher level buckets to allow them to remain responsive in the presence of bursty workloads.

The FIXPRI bucket is special cased since it contains extremely latency sensitive threads. Since the priority range for AboveUI and FG Timeshare buckets overlap, it is important to maintain some native priority order between those buckets. The policy implemented here is to compare the highest clutch buckets of both buckets; if the Above UI bucket is higher, schedule it immediately. Otherwise fall through to the deadline based scheduling as described above. The implementation allows extremely low latency CPU access for Above UI threads while supporting the use case of high priority timeshare threads contending with lower priority fixed priority threads which is observed in some media workloads. Since the timeshare bucket will eventually drop in priority as it consumes CPU, this model provides the desired behavior for timeshare threads above UI. 

The scheduling bucket level also maintains a bitmap of runnable root buckets to allow quick checks for empty hierarchy and root level priority calculation. 

The EDF algorithm is the best choice for this level due to the following reasons:

* Deadline based scheduling allows the scheduler to define strict bounds on worst case execution latencies for all scheduling buckets.
* The EDF algorithm is dynamic based on bucket runnability and selection. Since all deadline updates are computationally cheap, the algorithm can maintain up-to-date information without measurable overhead.
* It achieves the goals of maintaining low scheduling latency for high buckets and starvation avoidance for low buckets efficiently.
* Since the bucket level scheduler deals with a fixed small number of runnable buckets in the worst case, it is easy to configure in terms of defining deadlines, warps etc.

### Thread Group Level

The second level is the “thread group” level which decides which thread group within a bucket should be selected next for execution. Thread groups are a mechanism introduced with the AMP scheduler which represent a collection of threads working on behalf of a specific workload. Each thread group with runnable threads within a bucket is represented as an entry at this level. These entries are known as *clutch buckets* throughout the implementation. The goal of this level is to share the CPU among various user workloads with preference to interactive applications over compute-intensive batch workloads.

**Implementation**

The thread group level implements a variation of the FreeBSD ULE scheduler to decide which clutch bucket should be selected next for execution. Each clutch bucket with runnable threads is represented as an entry in a runqueue which is ordered by clutch bucket priorities. The clutch bucket selection algorithm simply selects the clutch bucket with the highest priority in the clutch bucket runqueue. The priority calculation for the clutch buckets is based on the following factors:

* **Highest runnable thread in the clutch bucket**: The clutch bucket maintains a priority queue which contains threads ordered by their promoted or base priority (whichever property made the thread eligible to be part of that clutch bucket). It uses the highest of these threads to calculate the base priority of the clutch bucket. The use of both base and sched priority allows the scheduler to honor priority differences specified from userspace via SPIs, priority boosts due to priority inheritance mechanisms like turnstiles and other priority affecting mechanisms outside the core scheduler.
* **Interactivity score**: The scheduler calculates an interactivity score based on the ratio of voluntary blocking time and CPU usage time for the clutch bucket as a whole. This score allows the scheduler to prefer highly interactive thread groups over batch processing compute intensive thread groups.
* **Thread Group Type**: In order to improve battery life on AMP devices, the OS marks daemon thread groups as “Efficient”. These thread groups typically represent work that is not directly related to the user requested workload. The scheduler de-prioritizes these thread groups over others by factoring this into the priority calculation.

The interactivity score based algorithm is well suited for this level due to the following reasons:

* It allows for a fair sharing of CPU among thread groups based on their recent behavior. Since the algorithm only looks at recent CPU usage history, it also adapts to changing behavior quickly.
* Since the priority calculation is fairly cheap, the scheduler is able to maintain up-to-date information about all thread groups which leads to more optimal decisions.
* Thread groups provide a convenient abstraction for groups of threads working together for a user workload. Basing scheduling decisions on this abstraction allows the system to make interesting choices such as preferring Apps over daemons which is typically better for system responsiveness.

The clutch bucket runqueue data structure allows the clutch buckets to be inserted at the head of the queue when threads from that clutch bucket are pre-empted. The runqueues also rotate the clutch bucket to the end of the runqueue at the same priority level when a thread is selected for execution from the clutch bucket. This allows the system to round robin efficiently among clutch buckets at the same priority value especially on highly contended low CPU systems.

### Thread Level

At the lowest level the scheduler decides which thread within a clutch bucket should be selected next for execution. Each runnable thread in the clutch bucket is represented as an entry in a runqueue which is organized based on the schedpri of threads. The thread selection algorithm simply selects the highest priority thread in the runqueue. The schedpri calculation for the threads is based on the traditional Mach scheduling algorithm which uses load & CPU usage to decay priority for a thread. The thread decay model is more suited at this level as compared to the global scheduler because the load calculation only accounts for threads in the same clutch bucket. Since all threads in the same clutch bucket belong to the same thread group and scheduling bucket, this algorithm provides quick CPU access for latency sensitive threads within the clutch bucket without impacting other non-related threads in the system.

**Implementation**

The thread level scheduler implements the Mach timesharing algorithm to decide which thread within the clutch bucket should be selected next for execution. All runnable threads in a clutch bucket are inserted into the runqueue based on the schedpri. The scheduler calculates the schedpri of the threads in a clutch bucket based on the number of runnable threads in the clutch bucket and the CPU usage of individual threads. The load information is updated every scheduler tick and the threads use this information for priority decay calculation as they use CPU. The priority decay algorithm attempts to reward bursty interactive threads and penalize CPU intensive threads. Once a thread is selected for running, it is assigned a quantum which is based on the scheduling bucket it belongs to. The quanta for various buckets are defined statically as:

```
static uint32_t sched_clutch_thread_quantum_us[TH_BUCKET_SCHED_MAX] = {
        10000,                                          /* FIXPRI (10ms) */
        10000,                                          /* FG (10ms) */
        8000,                                           /* IN (8ms) */
        6000,                                           /* DF (6ms) */
        4000,                                           /* UT (4ms) */
        2000                                            /* BG (2ms) */
};
```

The per-bucket thread quantum allows the scheduler to bound the worst case execution latency for a low priority thread which has been starved by higher priority threads.

##Scheduler Priority Calculations

###Root Priority Calculation

The scheduler maintains a root level priority for the hierarchy in order to make decisions regarding pre-emptions and thread selection. The root priority is updated as threads are inserted/removed from the hierarchy. The root level also maintains the urgency bits to help with pre-emption decisions. Since the root level priority/urgency is used for pre-emption decisions, it is based on the threads in the hierarchy and is calculated as follows:

```
Root Priority Calculation:
* If AboveUI bucket is runnable, 
*     Compare priority of AboveUI highest clutch bucket (CBUI) with Timeshare FG highest clutch bucket (CBFG)
*     If pri(CBUI) >= pri(CBFG), select CBUI
* Otherwise find the (non-AboveUI) highest priority root bucket that is runnable and select its highest clutch bucket
* Find the highest priority (promoted or base pri) thread within that clutch bucket and assign that as root priority

Root Urgency Calculation:
* On thread insertion into the hierarchy, increment the root level urgency based on thread's sched_pri
* On thread removal from the hierarchy, decrement the root level urgency based on thread's sched_pri

```

###Root Bucket Priority Calculation

The root bucket priority is simply the deadline of the root bucket which is calculated by adding the WCEL of the bucket to the timestamp of the root bucket becoming runnable.

```
root-bucket priority = now + WCEL[bucket]
```

###Clutch Bucket Priority Calculation

As mentioned earlier, the priority value of a clutch bucket is calculated based on the highest runnable thread, interactivity score and the thread group type. The actual calculation algorithm is as follows:

```
* Find the highest runnable thread (promoted or basepri) in the clutch bucket (maxpri)
* Check if the thread group for this clutch bucket is marked Efficient. 
*      If not, assign a positive boost value (clutch_boost)
* Calculate the ratio of CPU blocked and CPU used for the clutch bucket.
*      If blocked > used, assign a score (interactivity_score) in the higher range.
*      Else, assign a score (interactivity_score) in the lower range.
* clutch-bucket priority = maxpri + clutch_boost + interactivity_score
```

###Thread Priority Calculation

The thread priority calculation is based on the Mach timesharing algorithm. It is calculated in the following manner:

```
* Every scheduler tick, snapshot the load for the clutch bucket
* Use the load value to calculate the priority shift values for all threads in the clutch bucket
* thread priority = base priority - (thread CPU usage >> priority shift)
```
