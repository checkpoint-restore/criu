[![master](https://travis-ci.org/checkpoint-restore/criu.svg?branch=master)](https://travis-ci.org/checkpoint-restore/criu)
[![development](https://travis-ci.org/checkpoint-restore/criu.svg?branch=criu-dev)](https://travis-ci.org/checkpoint-restore/criu)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/55251ec7db28421da4481fc7c1cb0cee)](https://www.codacy.com/app/xemul/criu?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=xemul/criu&amp;utm_campaign=Badge_Grade)
<p align="center"><img src="https://criu.org/w/images/1/1c/CRIU.svg" width="256px"/></p>

## CRIU -- A project to implement checkpoint/restore functionality for Linux

CRIU (stands for Checkpoint and Restore in Userspace) is a utility to checkpoint/restore Linux tasks.

Using this tool, you can freeze a running application (or part of it) and checkpoint 
it to a hard drive as a collection of files. You can then use the files to restore and run the
application from the point it was frozen at. The distinctive feature of the CRIU
project is that it is mainly implemented in user space. There are some more projects
doing C/R for Linux, and so far CRIU [appears to be](https://criu.org/Comparison_to_other_CR_projects) 
the most feature-rich and up-to-date with the kernel.

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

## How to contribute

CRIU project is (almost) the never-ending story, because we have to always keep up with the
Linux kernel supporting checkpoint and restore for all the features it provides. Thus we're
looking for contributors of all kinds -- feedback, bug reports, testing, coding, writing, etc.
Here are some useful hints to get involved.

* We have both -- [very simple](https://github.com/xemul/criu/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement) and [more sophisticated](https://github.com/xemul/criu/issues?q=is%3Aissue+is%3Aopen+label%3A%22new+feature%22) coding tasks;
* CRIU does need [extensive testing](https://github.com/xemul/criu/issues?q=is%3Aissue+is%3Aopen+label%3Atesting);
* Documentation is always hard, we have [some information](https://criu.org/Category:Empty_articles) that is to be extracted from people's heads into wiki pages as well as [some texts](https://criu.org/Category:Editor_help_needed) that all need to be converted into useful articles;
* Feedback is expected on the github issues page and on the [mailing list](https://lists.openvz.org/mailman/listinfo/criu);
* For historical reasons we do not accept PRs, instead [patches are welcome](http://criu.org/How_to_submit_patches);
* Spread the word about CRIU in [social networks](http://criu.org/Contacts);
* If you're giving a talk about CRIU -- let us know, we'll mention it on the [wiki main page](https://criu.org/News/events);

## Licence

The project is licensed under GPLv2 (though files sitting in the lib/ directory are LGPLv2.1).
