DIR	:= $(shell pwd)/data
LOOP	:= $(DIR)/loop.sh
PIDFILE := $(DIR)/loop.pid
IMGS	:= $(DIR)/imgs
CRIU	:= $(DIR)/criu

ROOT	:=root
USR1	:=criu-test-user1
USR2	:=criu-test-user2

export DIR LOOP PIDFILE IMGS CRIU ROOT USR1 USR2

run: testdir users
	./run.sh

testdir: ../../../criu/criu
	mkdir -p $(DIR)
	mkdir -p $(IMGS)
	cp ../../../criu/criu $(CRIU)
	chmod u+s $(CRIU)
	cp loop.sh $(LOOP)
	chmod 777 $(DIR)

users:
	-userdel -f $(USR1)
	-userdel -f $(USR2)
	useradd -M -U $(USR1)
	useradd -M -U $(USR2)
	usermod -a -G $(USR2) $(USR1)

clean:
	rm -rf $(DIR)
	-userdel -f $(USR1)
	-userdel -f $(USR2)
