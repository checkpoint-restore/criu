## Installing CRIU from source code

Once CRIU is built one can easily setup the complete CRIU package
(which includes executable itself, CRIT tool, libraries, manual
and etc) simply typing

    make install

this command accepts the following variables:

 * **DESTDIR**, to specify global root where all components will be placed under (empty by default);
 * **PREFIX**, to specify additional prefix for path of every component installed (`/usr/local` by default);
 * **BINDIR**, to specify where to put CRIT tool (`$(PREFIX)/bin` by default);
 * **SBINDIR**, to specify where to put CRIU executable (`$(PREFIX)/sbin` by default);
 * **MANDIR**, to specify directory for manual pages (`$(PREFIX)/share/man` by default);
 * **SYSTEMDUNITDIR**, to specify place where systemd units are living (`$(PREFIX)/lib/systemd/system` by default);
 * **LIBDIR**, to specify directory where to put libraries (`$(PREFIX)/lib` by default).

Thus one can type

    make DESTDIR=/some/new/place install

and get everything installed under `/some/new/place`.

## Uninstalling CRIU

To clean up previously installed CRIU instance one can type

    make uninstall

and everything should be removed. Note though that if some variable (**DESTDIR**, **BINDIR**
and such) has been used during installation procedure, the same *must* be passed with
uninstall action.
