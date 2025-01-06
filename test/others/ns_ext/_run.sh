ip link set up dev lo
echo $$ > $1
while :; do
	sleep 1
done
