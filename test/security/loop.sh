#!/bin/bash

echo $$

if [ "$1" == "--chgrp" ]; then
	grps=( $(groups) )
	newgrp ${grps[1]}
fi

while :; do
	sleep 1
done
