TR="y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/"

for x in $(sed -n '/PB_AUTOGEN_START/,/PB_AUTOGEN_STOP/ {
		/PB_AUTOGEN_ST/d;
		s/,.*$//;
		s/\tPB_//;
		p;
	   }' criu/include/protobuf-desc.h); do
	x_la=$(echo $x | sed $TR)
	x_uf=$(echo $x | sed -nr 's/^./&#\\\
/;
		s/_(.)/\\\
\1#\\\
/g;
		p;' | \
		sed -r "/^[A-Z]#\\\\\$/!{ $TR; }" | \
		sed -r ':loop; N; s/#?\\\n//; t loop')
	echo "CR_PB_DESC($x, $x_uf, $x_la);"
done
