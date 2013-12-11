/* stripped down version */

#ifndef foosddaemonhfoo
#define foosddaemonhfoo

/***
  Copyright 2010 Lennart Poettering

  Permission is hereby granted, free of charge, to any person
  obtaining a copy of this software and associated documentation files
  (the "Software"), to deal in the Software without restriction,
  including without limitation the rights to use, copy, modify, merge,
  publish, distribute, sublicense, and/or sell copies of the Software,
  and to permit persons to whom the Software is furnished to do so,
  subject to the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
  BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
  ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
  CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
***/

#ifdef __cplusplus
extern "C" {
#endif

/*
  Reference implementation of a few systemd related interfaces for
  writing daemons. These interfaces are trivial to implement. To
  simplify porting we provide this reference implementation.
  Applications are welcome to reimplement the algorithms described
  here if they do not want to include these two source files.

  The following functionality is provided:

  - Support for logging with log levels on stderr
  - File descriptor passing for socket-based activation
  - Daemon startup and status notification
  - Detection of systemd boots

  You may compile this with -DDISABLE_SYSTEMD to disable systemd
  support. This makes all those calls NOPs that are directly related to
  systemd (i.e. only sd_is_xxx() will stay useful).

  Since this is drop-in code we don't want any of our symbols to be
  exported in any case. Hence we declare hidden visibility for all of
  them.

  You may find an up-to-date version of these source files online:

  http://cgit.freedesktop.org/systemd/systemd/plain/src/systemd/sd-daemon.h
  http://cgit.freedesktop.org/systemd/systemd/plain/src/libsystemd-daemon/sd-daemon.c

  This should compile on non-Linux systems, too, but with the
  exception of the sd_is_xxx() calls all functions will become NOPs.

  See sd-daemon(3) for more information.
*/

/* The first passed file descriptor is fd 3 */
#define SD_LISTEN_FDS_START 3

/*
  Returns how many file descriptors have been passed, or a negative
  errno code on failure. Optionally, removes the $LISTEN_FDS and
  $LISTEN_PID file descriptors from the environment (recommended, but
  problematic in threaded environments). If r is the return value of
  this function you'll find the file descriptors passed as fds
  SD_LISTEN_FDS_START to SD_LISTEN_FDS_START+r-1. Returns a negative
  errno style error code on failure. This function call ensures that
  the FD_CLOEXEC flag is set for the passed file descriptors, to make
  sure they are not passed on to child processes. If FD_CLOEXEC shall
  not be set, the caller needs to unset it after this call for all file
  descriptors that are used.

  See sd_listen_fds(3) for more information.
*/
int sd_listen_fds(int unset_environment);

#ifdef __cplusplus
}
#endif

#endif
