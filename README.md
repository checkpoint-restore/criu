## CRIU (Checkpoint and Restore in Userspace)

An utility to checkpoint/restore tasks. Using this tool, you can freeze a
running application (or part of it) and checkpoint it to a hard drive as a
collection of files. You can then use the files to restore and run the
application from the point it was frozen at. The distinctive feature of the CRIU
project is that it is mainly implemented in user space.

The project home is at http://criu.org.

Pages worth starting with are:
- [Kernel configuration, compilation, etc](http://criu.org/Installation)
- [A simple example of usage](http://criu.org/Simple_loop)
- [More sophisticated example with graphical app](http://criu.org/VNC)

### A video tour on basic CRIU features
[![CRIU introduction](https://asciinema.org/a/7fnt2prsumvxiwf3ng61fgct3.png)](https://asciinema.org/a/7fnt2prsumvxiwf3ng61fgct3)

### How to contribute

* [How to submit patches](http://criu.org/How_to_submit_patches);
* Send all bug reports to [mailing
list](https://lists.openvz.org/mailman/listinfo/criu);
* Spread the word about CRIU in [social networks](http://criu.org/Contacts);
