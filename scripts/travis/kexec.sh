#!/bin/bash
set -x

if [ "$1" = 'prep' ]; then
	time git clone --depth 1 $KGIT linux
	modprobe tun
	modprobe macvlan
	modprobe veth

	cp scripts/linux-next-config linux/.config
	cd linux
	make olddefconfig
	exit 0
fi

uname -a
cat /proc/cpuinfo
ip a
ip r

ppid=""
pid=$$
while :; do
	p=`cat /proc/$pid/status | grep PPid | awk '{ print $2 }'`
	if [ "$p" -eq 1 ]; then
		break;
	fi
	ppid=$pid
	pid=$p
	echo $pid
done

true && {
	cd linux
	yes "" | make localyesconfig
	make olddefconfig
	time make -j 4
	make kernelrelease
	cd ..
}

# Disable Docker daemon start after reboot; upstart way
echo manual > /etc/init/docker.override

setsid bash -c "setsid ./scripts/travis/kexec-dump.sh $ppid < /dev/null &> /travis.log &"
for i in `seq 10`; do
	sleep 15
	tail -n 30 /travis.log
#	tail -n 30 /imgs/dump.log
#	tail -n 30 /imgs/restore.log
	uname -a
	uptime
	ps axf
	if [ -f /rebooted ]; then
		uname -a
		exit 0;
	fi
	if [ -f /reboot.failed ]; then
		uname -a
		exit 1;
	fi
done
