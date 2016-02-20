all:
	stap -g -d ../../../criu/criu parasite.stp $$RANDOM -c 'bash -x ../zdtm.sh -d -x socket-tcp'
