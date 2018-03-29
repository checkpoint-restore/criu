# Check lazy-pages
set -e
source `dirname $0`/criu-lib.sh
prep

KERN_MAJ=`uname -r | cut -d. -f1`
KERN_MIN=`uname -r | cut -d. -f2`
if [ $KERN_MAJ -ge "4" ] && [ $KERN_MIN -ge "11" ]; then
	LAZY_EXCLUDE="-x cmdlinenv00 -x maps007"
else
	LAZY_EXCLUDE="-x maps007 -x fork -x fork2 -x uffd-events -x cgroupns
		      -x socket_listen -x socket_listen6 -x cmdlinenv00
		      -x socket_close_data01 -x file_read"
fi

# These tests seem to require complete separation of dump and restore namespaces
LAZY_MIGRATE_EXCLUDE="-x fifo_loop -x file_locks -x ptrace_sig -x overmount_file  -x file_lease -x cr_veth -x fifo -x overmount_sock -x unlink_largefile -x socket_udp-corked -x netns_sub_veth"

# lazy restore from images
./test/zdtm.py run --all --keep-going --report report --parallel 4 -f uns \
	       --lazy-pages $LAZY_EXCLUDE $LAZY_MIGRATE_EXCLUDE || fail

# During pre-dump + lazy-pages we leave VM_NOHUGEPAGE set
LAZY_EXCLUDE="$LAZY_EXCLUDE -x maps02"

# lazy restore from images with pre-dumps
./test/zdtm.py run --all --keep-going --report report --parallel 4 -f uns \
	       --lazy-pages --pre 2 $LAZY_EXCLUDE $LAZY_MIGRATE_EXCLUDE || fail
