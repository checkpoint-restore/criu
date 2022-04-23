[![X86_64 GCC Test](https://github.com/checkpoint-restore/criu/workflows/X86_64%20GCC%20Test/badge.svg)](
    https://github.com/checkpoint-restore/criu/actions/workflows/x86-64-gcc-test.yml)
[![Docker Test](https://github.com/checkpoint-restore/criu/actions/workflows/docker-test.yml/badge.svg)](
    https://github.com/checkpoint-restore/criu/actions/workflows/docker-test.yml)
[![Podman Test](https://github.com/checkpoint-restore/criu/actions/workflows/podman-test.yml/badge.svg)](
    https://github.com/checkpoint-restore/criu/actions/workflows/podman-test.yml)
[![CircleCI](https://circleci.com/gh/checkpoint-restore/criu.svg?style=svg)](
    https://circleci.com/gh/checkpoint-restore/criu)

<p align="center"><img src="https://criu.org/w/images/1/1c/CRIU.svg" width="256px"/></p>

## CRIU -- A project to implement checkpoint/restore functionality for Linux

CRIU (stands for Checkpoint and Restore in Userspace) is a utility to checkpoint/restore Linux tasks.

Using this tool, you can freeze a running application (or part of it) and checkpoint
it to a hard drive as a collection of files. You can then use the files to restore and run the
application from the point it was frozen at. The distinctive feature of the CRIU
project is that it is mainly implemented in user space. There are some more projects
doing C/R for Linux, and so far CRIU [appears to be](https://criu.org/Comparison_to_other_CR_projects)
the most feature-rich and up-to-date with the kernel.

CRIU project is (almost) the never-ending story, because we have to always keep up with the
Linux kernel supporting checkpoint and restore for all the features it provides. Thus we're
looking for contributors of all kinds -- feedback, bug reports, testing, coding, writing, etc.
Please refer to [CONTRIBUTING.md](CONTRIBUTING.md) if you would like to get involved.

The project [started](https://criu.org/History) as the way to do live migration for OpenVZ
Linux containers, but later grew to more sophisticated and flexible tool. It is currently
used by (integrated into) OpenVZ, LXC/LXD, Docker, and other software, project gets tremendous
help from the community, and its packages are included into many Linux distributions.

The project home is at http://criu.org. This wiki contains all the knowledge base for CRIU we have.
Pages worth starting with are:
- [Installation instructions](http://criu.org/Installation)
- [A simple example of usage](http://criu.org/Simple_loop)
- [Examples of more advanced usage](https://criu.org/Category:HOWTO)
- Troubleshooting can be hard, some help can be found [here](https://criu.org/When_C/R_fails), [here](https://criu.org/What_cannot_be_checkpointed) and [here](https://criu.org/FAQ)

### Checkpoint and restore of simple loop process
[<p align="center"><img src="https://asciinema.org/a/232445.png" width="572px" height="412px"/></p>](https://asciinema.org/a/232445)

## Advanced features

As main usage for CRIU is live migration, there's a library for it called P.Haul. Also the
project exposes two cool core features as standalone libraries. These are libcompel for parasite code
injection and libsoccr for TCP connections checkpoint-restore.

### Live migration

True [live migration](https://criu.org/Live_migration) using CRIU is possible, but doing
all the steps by hands might be complicated. The [phaul sub-project](https://criu.org/P.Haul)
provides a Go library that encapsulates most of the complexity. This library and the Go bindings
for CRIU are stored in the [go-criu](https://github.com/checkpoint-restore/go-criu) repository.


### Parasite code injection

In order to get state of the running process CRIU needs to make this process execute
some code, that would fetch the required information. To make this happen without
killing the application itself, CRIU uses the [parasite code injection](https://criu.org/Parasite_code)
technique, which is also available as a standalone library called [libcompel](https://criu.org/Compel).

### TCP sockets checkpoint-restore

One of the CRIU features is the ability to save and restore state of a TCP socket
without breaking the connection. This functionality is considered to be useful by
itself, and we have it available as the [libsoccr library](https://criu.org/Libsoccr).

## Licence

The project is licensed under GPLv2 (though files sitting in the lib/ directory are LGPLv2.1).

All files in the images/ directory are licensed under the Expat license (so-called MIT).
See the images/LICENSE file.
