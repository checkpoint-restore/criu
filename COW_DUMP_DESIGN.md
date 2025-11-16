# COW-Based Live Migration Design Document


## Introduction
This feature implements COW (Copy-On-Write) based live migration for CRIU, enabling process duplication to remote instances to achieve the goal of: 
1. Minimized downtime at the source. 
2. Making the destination alive ASAP like in the current design of lazy dump.
3. Transfer the data in high speed to complete the process soon and reduce the amount of COW operations.
   
   
The approach uses userfaultfd write-protection to track memory modifications while the process continues running at the source and the destination is loaded same as in the lazy dump implementation. It overcomes the main issue with the lazy dump where the source is frozen during the dump.

## Architecture Overview

### Data Flow Source


**Phase 1: Setup via Parasite RPC**
  - Create userfaultfd in target process
  - Register VMAs with UFFDIO_REGISTER_MODE_WP
  - Apply write-protection (UFFDIO_WRITEPROTECT)
  - Send userfaultfd back to CRIU
  - Create Monitor thread to get write faults events
  - Process resumes with COW protection active

**Phase 2: Monitor Thread (Background)**
  - read() from userfaultfd (blocking)
  - On write fault:
    1. Read page from /proc/pid/mem (before modification)
    2. Copy the page and store it in hash table
    3. Unprotect page
    4. Wake faulting thread at the source process

**Phase 3: Page Transfer (page_server_get_pages)**
  - Lookup COW pages in hash table
  - Fast path: No COW → splice (zero-copy)
  - Slow path: COW present → buffer + overlay
  - Bulk unprotect after transfer

#### Detailed design source

##### 1. cow-dump.c (CRIU-side Coordinator)

Main coordinator for COW tracking on the CRIU side. Manages the lifecycle of COW dump operations.

*Key Data Structures*

```c
/* Per-process COW dump state */
struct cow_dump_info {
    struct pstree_item *item;
    int uffd;                      /* userfaultfd from target */
    int proc_mem_fd;               /* /proc/pid/mem handle */
    unsigned long total_pages;     /* Total pages tracked */
    unsigned long dirty_pages;     /* Modified pages count */
    
    /* Hash table: 65K buckets for O(1) lookup */
    struct hlist_head cow_hash[COW_HASH_SIZE];  /* 2^16 buckets */
    pthread_spinlock_t cow_hash_locks[COW_HASH_SIZE]; //Lock for each hash entry to have fine grain locking.
};

/* Hash table entry for copied pages */
struct cow_page {
    unsigned long vaddr;           /* Virtual address */
    void *data;                    /* 4KB page content */
    struct hlist_node hash;        /* Hash linkage */
};

#define COW_HASH_SIZE (1 << 16)    /* 65536 buckets */
```

*Key Functions*

**Init- Initialize COW tracking**
- Opens `/proc/pid/mem` for reading page contents
- Calls parasite RPC to setup userfaultfd
- Receives userfaultfd from parasite
- Initializes hash table and spinlocks
- Init COW monitoring thread


**cow_monitor_thread()** - Background monitoring
- Continuously reads from userfaultfd
- Processes write fault events

**cow_handle_write_fault()** - Handle write fault event
```
Input: fault address
1. Allocate cow_page structure
2. Read page from /proc/pid/mem (BEFORE modification)
3. Add to hash table (thread-safe)
4. Unprotect page (UFFDIO_WRITEPROTECT mode=0)
5. Wake faulting thread (UFFDIO_WAKE)
```


**cow_lookup_and_remove_page()** - Thread-safe page lookup
- Hash-based O(1) lookup
- Removes from hash table atomically

##### 2. pie/parasite.c (In-Process Setup)

Runs inside the target process to setup userfaultfd with write-protection.

**Purpose:** The parasite code is injected into the target process and executes in its context to create and configure the userfaultfd.

*Key Function: parasite_cow_dump_init()*


**Why Parasite-Based?**
1. **Context Requirement:** userfaultfd must be created in target process context
2. **Inheritance:** Automatically inherited by all threads
3. **Permissions:** Avoids ptrace permission issues
4. **Atomic Setup:** All VMAs protected before process resumes


##### 3. page-xfer.c (Page Server Integration)

Integrates COW tracking with page transfer, overlaying modified pages during transfer.

Key Function: page_server_get_pages()

Step 1: Read pages from page_pipe
  page_pipe_read(pp, &pipe_read_dest, vaddr, &nr_pages)

Step 2: Check for COW pages at the hash table, recall each modified page is stored in the hash table (single pass)              
 for each page:                                         
    cow_pages[i] = cow_lookup_and_remove_page(addr)     
    cow_count = number of non-NULL entries 

Fast path: (cow_count is zero, same as done today at the current lazy implementation)
Zero-copy splice: splice(pipe -> sock) 
 No memory copies!  


Slow path:  (cow_count is above zero)
1. read(pipe -> buffer)
2. overlay COW pages 

Step 3: Bulk unprotect         
wp.range.start = vaddr       
wp.range.len = len            
wp.mode = 0                   
ioctl(uffd, UFFDIO_WRITEPROTECT)


### Data Flow Destination

No changes where made at the destination and it is almost the same as in the original code. I implemented a single perf improvement that handles lazy page requests from destination with aggressive pipelining.

```
┌─────────────────────────────────────────────────────────┐
│ Traditional: Sequential (1 request at a time)           │
│                                                         │
│  Request → Wait → Response → Request → Wait → Response  │
│                                                         │
│  Throughput: Limited by RTT                             │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ Aggressive: Pipeline (256 requests in-flight)           │
│                                                         │
│  Request ─┐                                             │
│  Request ─┤                                             │
│  Request ─┤                                             │
│    ...    ├─► In Flight (256 concurrent)                │
│  Request ─┤                                             │
│  Request ─┤                                             │
│  Request ─┘                                             │
│                                                         │
│  Response → IMMEDIATELY refill pipeline                 │
│                                                         │
│  Throughput: Near maximum network bandwidth             │
└─────────────────────────────────────────────────────────┘
```


## Kernel Requirements

### Minimum Kernel Version
**Linux 5.7+** (released May 2020)

### Required Features

| Feature | Flag | Purpose | Since |
|---------|------|---------|-------|
| WP Flag | `UFFD_FEATURE_PAGEFAULT_FLAG_WP` | Identify write faults | 5.7 |


### System Configuration

**Unprivileged Access:**
```bash
# Allow unprivileged userfaultfd
echo 1 > /proc/sys/vm/unprivileged_userfaultfd

# Or require CAP_SYS_PTRACE
```



---

##  Future Work

### 1. | Write-Protect | `UFFD_FEATURE_WP_ASYNC` | Async write-protect mode | 5.7 |

We should explore how to use this feature it should only mark the page as touched and then we can do a second path to copy only the touched pages. I will dive deeper to see if it is more efficient. 


#### 2. Reduce the communication overhead between the source and destination.

Currently the communication is derived by the destination which sends request, we can improve to make the source send the data and make the destination to ask only if there is a read page fault. That way, we reduce the amount of work from the source.

#### 3. Make the source multithreaded.
Can we make the source multithreaded to reduce the overall time? Should be explored.


#### 4. Non-Registerable VMAs
**Issue:** Some VMAs cannot be write-protected
I will be happy to get advice.



### Next Steps

For maintainers reviewing this code:

1. **Testing:** Extensive testing with various workloads
2. **Documentation:** Update user-facing documentation
3. **Performance Tuning:** Profile and optimize hot paths
4. **Feature Completion:** Address known limitations
5. **Kernel Integration:** Work with kernel developers on enhancements

### Usage
```bash
criu dump --cow-dump --lazy-pages ...
```

## Appendix - Statistics and Monitoring

### COW Tracking Statistics

**Per-Second Logging:**
```
[COW_STATS] events: wr=1234 fork=0 remap=0 unk=0 | 
            ops: copied=1234 unprot=1234 woken=1234 | 
            errs: alloc=0 read=0 unprot_err=0 wake_err=0 
                  read_err=0 eagain_err=0
```

**Metrics:**

| Metric | Description | Good Value | Alert If |
|--------|-------------|------------|----------|
| `wr` | Write faults | Varies | - |
| `copied` | Pages copied | = wr | < wr |
| `unprot` | Pages unprotected | = wr | < wr |
| `woken` | Threads woken | = wr | < wr |
| `alloc_failures` | Allocation failures | 0 | > 0 |
| `read_failures` | Read failures | 0 | > 0 |
| `eagain_errors` | EAGAIN on read | Low | High |

### Page Server Statistics

**Per-Second Logging:**
```
[PAGE_SERVER_STATS] get_pages: reqs=500 with_cow=50 no_cow=450 
                               pages=8000 cow=400 errs=0 | 
                    serve: open2=1 parent=0 add_f=7950 get=500 
                          close=1
```

**Metrics:**

| Metric | Description | Indicates |
|--------|-------------|-----------|
| `reqs` | Total requests | Transfer activity |
| `with_cow` | Slow path taken | COW overlay needed |
| `no_cow` | Fast path taken | Zero-copy efficiency |
| `pages` | Total pages transferred | Bandwidth |
| `cow` | COW pages overlaid | Write activity |

### UFFD Daemon Statistics

**Per-Second Logging:**
```
[UFFD_STATS] reqs=1000(pf:50,bg:950) pages=8000 pipe_avg=180
  PF:  4K=30 64K=15 128K=5
  BG:  4K=100 64K=500 128K=200 256K=100 512K=50
```

**Histograms:**
- **PF (Page Fault):** Destination-initiated requests
- **BG (Background):** Proactive prefetch

**Pipeline Depth:**
- `pipe_avg`: Average in-flight requests
- Target: Close to `max_pipeline_depth` (256)

