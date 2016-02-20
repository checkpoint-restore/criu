#!/bin/bash
# $1 -- link name
# $2 -- pid of task in namespace
set -x
$ip link add link eth0 name $1 type macvlan || exit 1
$ip link set $1 netns $2
