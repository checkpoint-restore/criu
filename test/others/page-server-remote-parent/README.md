# Page-server remote-parent regression

This test covers [issue #2503](https://github.com/checkpoint-restore/criu/issues/2503): one or more page-server pre-dumps followed by a local final dump.

A remote pre-dump writes page payload to the page-server image chain and keeps a standard CRIU pagemap on the source. The source pagemap records parent coverage but has no local pages image. A later local dump accepts a parent reference only when the corresponding range is present in that pagemap. The assembled destination chain must restore successfully.

## Run

```sh
make -C test/others/page-server-remote-parent check
```

The targets can also be run separately:

```sh
make -C test/others/page-server-remote-parent PRE_DUMP_MODE=splice regression
make -C test/others/page-server-remote-parent PRE_DUMP_MODE=read regression
make -C test/others/page-server-remote-parent shared-regression
```

Set `KEEP_WORK_DIR=1` to keep images and logs from the regression.

The regression covers a local incremental control, one- and two-round remote pre-dumps, page-generation placement, restore, metadata rollback after image-write failures, and page-server disconnects.

The shared-memory regression verifies restored bytes and aliasing with `CRIU_TRACK_SHMEM` unset, so shared contents follow the default conservative copy path.

Coverage files are source-side dump metadata, not restorable destination
parents. The suite also checks that accidentally configuring a page server
with such a parent fails without publishing the next round's coverage.
The ordinary payload reader rejects their reserved `pages_id = 0` marker.
This change retains the existing operational requirement to assemble the
correct parent chain; cryptographic or generation-identity binding is outside
this feature's scope.
