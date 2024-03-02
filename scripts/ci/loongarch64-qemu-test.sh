#!/bin/bash

set -o nounset
set -o errexit
set -x

./apt-install \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common \
    sshpass \
    openssh-client

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable test"

./apt-install docker-ce

# shellcheck source=/dev/null
. /etc/lsb-release

# docker checkpoint and restore is an experimental feature
echo '{ "experimental": true }' > /etc/docker/daemon.json
service docker restart

docker info

# run a loongarch64 vm

PORT='2222'
USER='root'
PASSWORD='loongarch64'
NAME='vm'

docker run \
    -d \
    --net host \
    --name $NAME \
    merore/archlinux-loongarch64

run() {
    if [ -z "$1" ]; then
        echo "Command cannot be empty."
        exit 1
    fi
    sshpass -p $PASSWORD ssh -o StrictHostKeyChecking=no -p $PORT $USER@127.0.0.1 "$1"
}

# wait vm to start
while (! run "uname -a")
do
    echo "Wait vm to start..."
    sleep 1
done
echo "The loongarch64 vm is started!"

# Tar criu and send to vm
tar -cf criu.tar ../../../criu
sshpass -p $PASSWORD scp -o StrictHostKeyChecking=no -P $PORT criu.tar $USER@127.0.0.1:/root

# build and test
run 'cd /root; tar -xf criu.tar'
run 'cd /root/criu; make -j4 && make -j4 -C test/zdtm'
run "cd /root/criu; ./test/zdtm.py run -t zdtm/static/maps02 -t zdtm/static/maps05 -t zdtm/static/maps06 -t zdtm/static/maps10 -t zdtm/static/maps_file_prot -t zdtm/static/memfd00 -t zdtm/transition/fork -t zdtm/transition/fork2 -t zdtm/transition/shmem -f h"
