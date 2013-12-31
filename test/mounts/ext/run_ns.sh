#!/bin/bash

set -x
set -e

odir="mexold"
# finf & outf came from parent
cur="$(pwd)"

function fail {
	echo $@
	exit 1
}

# Don't mirror further bind mounts in the original namespace
mount --make-rprivate "/"

# Clean previous stuff
rm -rf "$tempd" "$finf" "$outf" "/$odir"
mkdir "$tempd"
touch "$tdir/$cur/$tdir/$dfile"

# Create source file. Make it on a new mountpoint to "hide"
# it in the target mount tree (see below)
mount -t tmpfs none "$tempd"
echo "$mesg" > "$tempd/$sfile"

# Create destination file. It's a bind mount to the source one.
mount --bind "$tempd/$sfile" "$tdir/$cur/$tdir/$dfile"

# Make clean and small mounts set
cd "$tdir"
mkdir "$odir"
pivot_root "." "./$odir"
mount -t proc none "/proc"
umount -lif "/$odir"

# This would show root, proc and the bind mount to some "unknown"
# file. Unknown, since it's on a tempfs mount that is not seen
cat "/proc/self/mountinfo"

set +e

cd "$cur"

# Will be in "logs" so that caller can do "sanity eye-check"
ls
cat "$tempd/$sfile"
cat "$tdir/$dfile"

# Start waiting for C/R on us
# Exec also fixes the maps/exe/fd links relative to new mounts
exec setsid "./run_wait.sh" "$tdir/$dfile" "$mesg" < /dev/null > "$outf" 2>&1 &
