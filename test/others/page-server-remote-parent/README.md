# Page-server remote-parent regression

This test covers [issue #2503](https://github.com/checkpoint-restore/criu/issues/2503): one or more page-server pre-dumps followed by a local final dump.

A remote pre-dump writes page payload to the page-server image chain and keeps compact `remote-parent-*.img` range metadata in the source image directory. A later local dump accepts a parent reference only when the corresponding range is present in that metadata. The assembled destination chain must restore successfully.

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
