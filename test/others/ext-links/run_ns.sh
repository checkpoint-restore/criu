#!/bin/bash
set -x
echo "NS: $$" >> $outf
echo "Links before:" >> $outf
$ip link list >> $outf 2>&1
# Detach from session, terminal and parent
setsid ./run_wait.sh < /dev/null >> $outf 2>&1 &
# Keep pid for future reference :)
echo "$!" > $pidf
exit 0
