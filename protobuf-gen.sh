for x in $(cat include/protobuf-desc.h | \
		sed -n '/PB_AUTOGEN_START/,/PB_AUTOGEN_STOP/p' | \
		fgrep -v 'PB_AUTOGEN_S' | sed -e 's/,//' -e 's/PB_//'); do
	x_la=$(echo $x | tr 'A-Z' 'a-z')
	x_uf=$(echo $x_la | sed -e 's/^./\u&/' -e 's/_./\U&/g' -e 's/_//g')
	echo "CR_PB_DESC($x, $x_uf, $x_la);"
done
