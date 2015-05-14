#!/bin/bash

echo $$ > $1.int
mv $1.int $1

if [ "$2" == "--chgrp" ]; then
	grps=( $(groups) )
	newgrp ${grps[2]}
fi

while :; do
	sleep 1
done
