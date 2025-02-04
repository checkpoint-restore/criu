## Building CRIU from source code

First, you need to install compile-time dependencies. Check [Installation dependencies](https://criu.org/Installation#Dependencies) for more info.

To compile CRIU, run:
```
make
```
This should create the `./criu/criu` executable.

To change the default behaviour of CRIU, the following variables can be passed
to the make command:

 * **NETWORK_LOCK_DEFAULT**, can be set to one of the following
   values: `NETWORK_LOCK_IPTABLES`, `NETWORK_LOCK_NFTABLES`,
   `NETWORK_LOCK_SKIP`. CRIU defaults to `NETWORK_LOCK_IPTABLES`
   if nothing is specified. If another network locking backend is
   needed, `make` can be called like this:
   `make NETWORK_LOCK_DEFAULT=NETWORK_LOCK_NFTABLES`

## Installing CRIU from source code

Once CRIU is built one can easily setup the complete CRIU package
(which includes executable itself, CRIT tool, libraries, manual
and etc) simply typing
```
make install
```
this command accepts the following variables:

 * **DESTDIR**, to specify global root where all components will be placed under (empty by default);
 * **PREFIX**, to specify additional prefix for path of every component installed (`/usr/local` by default);
 * **BINDIR**, to specify where to put CRIT tool (`$(PREFIX)/bin` by default);
 * **SBINDIR**, to specify where to put CRIU executable (`$(PREFIX)/sbin` by default);
 * **MANDIR**, to specify directory for manual pages (`$(PREFIX)/share/man` by default);
 * **LIBDIR**, to specify directory where to put libraries (guess the correct path  by default).

Thus one can type
```
make DESTDIR=/some/new/place install
```
and get everything installed under `/some/new/place`.

## Uninstalling CRIU

To clean up previously installed CRIU instance one can type
```
make uninstall
```
and everything should be removed. Note though that if some variable (**DESTDIR**, **BINDIR**
and such) has been used during installation procedure, the same *must* be passed with
uninstall action.
