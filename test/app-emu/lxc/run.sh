#!/bin/bash

[ -z "$CR_IP_TOOL" ] && CR_IP_TOOL=ip

cd `dirname $0`

crtools="../../../crtools"

name=$1
[ -z "$name" ] && { cat <<EOF
Usage: $0 NAME [PID]"
	NAME - a container name
	PID  - PID of the container's "init". It's required, if CT is dumped
               in a second time, because LXC tools don't work in this case.
EOF
	exit 1;
}

pid=$2

[ -z "$pid" ] && {
	lxc-info --name $name || exit 1

	pid=$(lxc-info --name $name | awk '/pid:/ { print $2 }')
}

echo "The CT's \"init\" process has PID of $pid"
kill -0 $pid || exit 1

mkdir -p /var/run/netns/
ln -sf /proc/$pid/ns/net /var/run/netns/$name
$CR_IP_TOOL netns exec $name ip a || exit 1

mkdir data

echo "Dump the CT $name ($pid)"
${crtools} dump --evasive-devices						\
		--tcp-established						\
		--file-locks							\
		-n net -n mnt -n ipc -n pid					\
		--action-script "`pwd`/network-script.sh dump $pid $name"	\
		-vvvv -D data -o dump.log -t $pid || exit 1
echo "The CT $name was dumped successfully"

echo Press Enter for restoring CT
read

echo "Restore the CT $name"
${crtools} restore 	--evasive-devices					\
			--tcp-established					\
			--file-locks						\
			-n net -n mnt -n ipc -n pid				\
			--action-script "`pwd`/network-script.sh restore $name.0" \
			--veth-pair eth0=$name.0				\
			--root /root/test-lxc-root				\
			--pidfile newpid.log					\
			-vvvv -D data -d -o restore.log || exit 1
echo "The CT $name was restored successfully"

pid=`cat data/newpid.log`;
echo "The CT's \"init\" process has PID of $pid"
kill -0 $pid || exit 1
ln -sf /proc/$pid/ns/net /var/run/netns/$name
$CR_IP_TOOL netns exec $name ip a || exit 1
