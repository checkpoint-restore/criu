#!/bin/bash

set -x

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
	modprobe tun
	modprobe macvlan
	modprobe veth

	git clone --depth 1 $KGIT linux
#	git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git linux
	cp scripts/linux-next-config linux/.config
	cd linux
#	git checkout -f 93a205ee98a4881e8bf608e65562c19d45930a93
#	git clean -dxf
	make olddefconfig
	yes "" | make localmodconfig
	make olddefconfig
	make -j 4
	make modules_install
	make install
	make kernelrelease
	cd ..
}


ls -l /boot/

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
