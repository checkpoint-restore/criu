## criu-image-streamer

### Overview
criu-image-streamer is an optional helper component used with CRIU to
stream checkpoint images instead of writing them entirely to disk
before transfer.

It is built and installed separately from CRIU and is typically used
in workflows where reducing downtime or disk I/O is important.

### When is criu-image-streamer used?
criu-image-streamer can be used when checkpoint images need to be
transferred efficiently, for example during migration scenarios where
writing full image sets to disk may be slow or undesirable.

### Difference from live migration
Unlike traditional live migration, criu-image-streamer does not
continuously synchronize memory pages. Instead, it focuses on streaming
CRIU checkpoint images during the checkpoint/restore process.

### Installation

The CRIU repository provides a helper script that is primarily used in
tests. The script clones the criu-image-streamer repository and builds
the project, but it does not install it system-wide:

scripts/install-criu-image-streamer.sh

For actual installation and usage instructions, refer to the
criu-image-streamer repository documentation:
https://github.com/checkpoint-restore/criu-image-streamer#installation

### References
- scripts/install-criu-image-streamer.sh
- https://github.com/checkpoint-restore/criu-image-streamer

Internally, CRIU and criu-image-streamer communicate using a simple
request-reply protocol to coordinate image transfer during dump and
restore.
