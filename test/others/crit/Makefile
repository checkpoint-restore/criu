images: clean
	setsid ./loop.sh < /dev/null &> /dev/null & \
	../../criu dump -v4 -o dump.log -D ./ -t $${!} --shell-job

run: images
	./test.sh

clean:
	rm -f *.img *.log *.txt stats-* *.json
