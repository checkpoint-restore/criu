# Clone Unit Tests

## Build & Run

```bash
cd test/unit/clone
make
make check
```

## Run a Single Test

```bash
make test_page_pool
./test_page_pool
```

## Notes

- Tests run without root, without CRIU, and without kernel userfaultfd
- Header-only tests (bitmaps, queues) are portable (macOS/Linux)
- Tests linking real source files (page-pool, trackers) require Linux
- The `shims/` directory provides stub headers for CRIU internals
