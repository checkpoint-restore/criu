# This script is used to read a single character from CRIU's status FD.
# That way we know when the CRIU service is ready. CRIU writes a \0 to
# the status FD.
# In theory this could be easily done using 'read -n 1' from bash, but
# but the bash version on Ubuntu has probably the following bug:
# https://lists.gnu.org/archive/html/bug-bash/2017-07/msg00039.html

import sys

f = open(sys.argv[1])
r = f.read(1)
f.close()

if r == '\0':
	sys.exit(0)

sys.exit(-1)
