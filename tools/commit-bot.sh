#!/bin/sh

remote="git://github.com/cyrillos/crtools.git"

id=$1
if [ -z "$id" ]; then
	id=`exec git reflog -n1 | cut -f1 -d ' '`
	branch=`exec git branch | grep '*' | cut -f2 -d ' '`
	commitmsg=`exec git log $branch -p --stat -n1 $id`
	subject=`exec git log $branch --stat -n1 $id | sed -e '5! D' | sed -e 's/^\s*//g'`
	author=`exec git log $branch --stat -n1 $id | grep "Author" | sed -e 's/Author\: //g'`
else
	branch=`exec git branch | grep '*' | cut -f2 -d ' '`
	commitmsg=`exec git log -p --stat -n1 $id`
	subject=`exec git log --stat -n1 $id | sed -e '5! D' | sed -e 's/^\s*//g'`
	author=`exec git log --stat -n1 $id | grep "Author" | sed -e 's/Author\: //g'`
fi
	name=`exec echo $author | sed -e 's/<.*>//g'`

	echo "From: Cyrill Gorcunov <gorcunov@openvz.org>"			>  /tmp/crtools.bot
	echo "To: $author"							>> /tmp/crtools.bot
	echo "Cc: CriuML <criu@openvz.org>"					>> /tmp/crtools.bot
	echo "Subject: [crtools-bot for $name] $subject"			>> /tmp/crtools.bot
	echo ""									>> /tmp/crtools.bot
	echo "The commit is pushed to \"$branch\" and will appear on $remote"	>> /tmp/crtools.bot
	echo "------>"								>> /tmp/crtools.bot
	echo "$commitmsg"							>> /tmp/crtools.bot

	exec cat /tmp/crtools.bot | /usr/sbin/sendmail -t "$author"
	#cat /tmp/crtools.bot
