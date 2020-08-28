#!/bin/sh

clang-format -style=file -output-replacements-xml $1 |
grep "<replacement " >/dev/null
if [ $? -ne 1 ]; then
	echo "File $1 did not match clang-format"
	exit 1
fi

exit 0
