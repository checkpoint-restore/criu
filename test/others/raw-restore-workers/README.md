Build CRIU first, then run `make -C test/others/raw-restore-workers check` on
x86-64 Linux with clone3 available. No checkpoint, root privileges, or user
namespace is needed.

The test includes the production restore-reader code. It uses real CLONE_VM
helpers, stacks and reaping, with instrumented reads to verify disjoint image
and destination ranges. Fault injection checks partial startup, read errors,
short reads, parent-death races and cleanup ordering. The fixture does not
establish end-to-end checkpoint/restore correctness or performance.
