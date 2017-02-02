#!/bin/bash
set -e -x

sleep 1

mkdir -p /imgs
rm -rf /imgs/*
f=`lsof -p $1 | grep /run/systemd/sessions | awk '{ print $9 }'`
echo $f
./criu/criu dump -D /imgs -o dump.log -t $1 -j --tcp-established --ext-unix-sk -v4 -l --ghost-limit 10485760 || {
	./scripts/dropbox_upload.py /imgs/dump.log
	touch /reboot.failed
	exit 1
}
./scripts/dropbox_upload.py /imgs/dump.log || true

./crit/crit show /imgs/tty-info.img  | sed 's/"index": \([0-9]*\)/"index": 1\1/' | ./crit/crit encode > /imgs/tty-info.img.new
./crit/crit show /imgs/reg-files.img  | sed 's|/dev/pts/\([0-9]*\)|/dev/pts/1\1|' | ./crit/crit encode > /imgs/reg-files.img.new
mv /imgs/tty-info.img.new /imgs/tty-info.img
mv /imgs/reg-files.img.new /imgs/reg-files.img
./crit/crit show /imgs/tty-info.img


d=`pwd`
[ -f /etc/init/criu.conf ] && unlink /etc/init/criu.conf
cat > /etc/init/criu.conf << EOF
start on runlevel [2345]
stop on runlevel [016]
exec /$d/scripts/travis/kexec-restore.sh $d $f
EOF

cat > /etc/network/if-pre-up.d/iptablesload << EOF
#!/bin/sh
iptables-restore < /etc/iptables.rules
unlink /etc/network/if-pre-up.d/iptablesload
unlink /etc/iptables.rules
exit 0
EOF

chmod +x /etc/network/if-pre-up.d/iptablesload
iptables-save -c > /etc/iptables.rules

uname -a
lsmod
ps axf

ip a
ip r
iptables -L

set +x
echo $DROPBOX_TOKEN > /dropbox
echo $TRAVIS_BUILD_ID > /travis_id
set -x

kernel=`ls -c /boot/vmlinuz* | head -n 1 | sed 's/.*vmlinuz-\(.*\)/\1/'`
echo $kernel
kexec -l /boot/vmlinuz-$kernel --initrd=/boot/initrd.img-$kernel --reuse-cmdline
kexec -e
