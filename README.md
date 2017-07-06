<p align="center"><img src="https://criu.org/w/images/1/1c/CRIU.svg" width="256px"/></p>

## CRIU (Checkpoint and Restore in Userspace)

An utility to checkpoint/restore tasks. Using this tool, you can freeze a
running application (or part of it) and checkpoint it to a hard drive as a
collection of files. You can then use the files to restore and run the
application from the point it was frozen at. The distinctive feature of the CRIU
project is that it is mainly implemented in user space.

Also, CRIU provides a library for Live migration, and exposes two low-level
core features as standalone libraries. Thes are libcompel for parasite code 
injection and libsoccr for TCP connections checkpoint-restore.

The project home is at http://criu.org.

Pages worth starting with are:
- [Kernel configuration, compilation, etc](http://criu.org/Installation)
- [A simple example of usage](http://criu.org/Simple_loop)
- [More sophisticated example with graphical app](http://criu.org/VNC)

### A video tour on basic CRIU features
[![CRIU introduction](https://asciinema.org/a/7fnt2prsumvxiwf3ng61fgct3.png)](https://asciinema.org/a/7fnt2prsumvxiwf3ng61fgct3)

## Live migration

True [live migration](https://criu.org/Live_migration) using CRIU is possible, but doing
all the steps by hands might be complicated. The [phaul sub-project](https://criu.org/P.Haul)
provides a Go library that incapsulates most of the complexity.

## Parasite code ijection

In order to get state of the running process CRIU needs to make this process execute
some code, that would fetch the required information. To make this happen without
killing the application itself, CRIU uses the [parasite code injection](https://criu.org/Parasite_code)
technique, which is also available as a standalone library called [libcompel](https://criu.org/Compel).

## TCP sockets checkpoint-restore

One of the CRIu features is the ability to save and restore state of a TCP socket
without breaking the connection. This functionality is considered to be useful by
tiself, and we have it available as the [libsoccr library](https://criu.org/Libsoccr).

## How to contribute

* [How to submit patches](http://criu.org/How_to_submit_patches);
* Send all bug reports to [mailing
list](https://lists.openvz.org/mailman/listinfo/criu);
* Spread the word about CRIU in [social networks](http://criu.org/Contacts);

## Licence

The project is licensed under GPLv2 (though files sitting in the lib/ directory are LGPLv2.1).
