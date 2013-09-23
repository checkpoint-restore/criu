import sys
start = 0;
end = 0;

for l in sys.stdin:
	l = l.split()[0]
	s, e = l.split('-')
	s = int("0x" + s, 0)
	e = int("0x" + e, 0)
	if end == s:
		end = e;
	else:
		print "%x-%x" % (start, end)
		start = s
		end = e
print "%x-%x" % (start, end)
