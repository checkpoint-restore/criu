#!/bin/bash -x

pid=$1
vpid=$2
sig=$3
comm=$4

exec &>> /tmp/zdtm-core.log

expr match "$comm" zombie00 && {
	cat > /dev/null
	exit 0
}

expr match "$comm" seccomp_filter && {
	cat > /dev/null
	exit 0
}

report="/tmp/zdtm-core-$pid-$comm"
exec &> ${report}.txt

ps axf
ps -p $pid

cat /proc/$pid/status
ls -l /proc/$pid/fd
cat /proc/$pid/maps
exec 33< /proc/$pid/exe
cat > $report.core

echo 'bt
i r
disassemble $rip-0x10,$rip + 0x10
' | gdb -c $report.core /proc/self/fd/33
