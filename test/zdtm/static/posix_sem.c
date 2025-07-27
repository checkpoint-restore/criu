#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <semaphore.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/stat.h>

#include "zdtmtst.h"

const char *test_doc = "Test POSIX semaphore migration with --posix-sem-migration";
const char *test_author = "CRIU community";

static sem_t *test_sem;
static char sem_name[64];
static int initial_value = 3;

static int setup_posix_semaphore(void)
{
	struct stat st;
	
	/* Host mode is needed for /dev/shm access */
	if (stat("/dev/shm", &st) < 0) {
		pr_perror("stat /dev/shm");
		test_msg("ERROR: /dev/shm is not accessible\n");
		return -1;
	}
	
	if (!S_ISDIR(st.st_mode)) {
		test_msg("ERROR: /dev/shm is not a directory\n");
		return -1;
	}
	
	test_msg("/dev/shm is accessible (mode: %o)\n", st.st_mode);
	
	snprintf(sem_name, sizeof(sem_name), "/test_posix_sem_%d", getpid());
	
	test_msg("Attempting to create semaphore: %s\n", sem_name);
	
	/* Create the semaphore with initial value */
	test_sem = sem_open(sem_name, O_CREAT | O_EXCL, 0644, initial_value);
	if (test_sem == SEM_FAILED) {
		if (errno == EEXIST) {
			test_msg("Semaphore already exists, trying to open existing one\n");
			test_sem = sem_open(sem_name, 0);
			if (test_sem == SEM_FAILED) {
				pr_perror("sem_open (existing semaphore)");
				return -1;
			}
		} else {
			pr_perror("sem_open (create)");
			test_msg("Failed to create semaphore %s (errno=%d: %s)\n", 
				 sem_name, errno, strerror(errno));
			return -1;
		}
	}
	
	test_msg("Created POSIX semaphore %s with initial value %d\n", sem_name, initial_value);
	return 0;
}

/* lol this is fun it works ig */
static int test_semaphore_operations(void)
{
	int sem_value;
	
	if (sem_getvalue(test_sem, &sem_value) < 0) {
		pr_perror("sem_getvalue");
		return -1;
	}
	
	test_msg("Semaphore value before operations: %d\n", sem_value);
	
	if (sem_wait(test_sem) < 0) {
		pr_perror("sem_wait");
		return -1;
	}
	
	if (sem_getvalue(test_sem, &sem_value) < 0) {
		pr_perror("sem_getvalue after wait");
		return -1;
	}
	
	test_msg("Semaphore value after wait: %d\n", sem_value);
	
	if (sem_post(test_sem) < 0) {
		pr_perror("sem_post");
		return -1;
	}
	
	if (sem_getvalue(test_sem, &sem_value) < 0) {
		pr_perror("sem_getvalue after post");
		return -1;
	}
	
	test_msg("Semaphore value after post: %d\n", sem_value);
	
	return 0;
}

static int verify_semaphore_state(int expected_value)
{
	int sem_value;
	
	if (sem_getvalue(test_sem, &sem_value) < 0) {
		pr_perror("sem_getvalue in verify");
		return -1;
	}
	
	if (sem_value != expected_value) {
		fail("Semaphore value mismatch: expected %d, got %d", expected_value, sem_value);
		return -1;
	}
	
	test_msg("Semaphore value verified: %d\n", sem_value);
	return 0;
}

static void cleanup_semaphore(void)
{
	if (test_sem != SEM_FAILED) {
		sem_close(test_sem);
		sem_unlink(sem_name);
		test_msg("Cleaned up semaphore %s\n", sem_name);
	}
}

int main(int argc, char **argv)
{
	int expected_final_value;
	
	test_init(argc, argv);
	
	/* Setup POSIX semaphore */
	if (setup_posix_semaphore() < 0) {
		return 1;
	}
	
	/* Perform some operations to change semaphore state */
	if (test_semaphore_operations() < 0) {
		cleanup_semaphore();
		return 1;
	}
	
	/* Record expected value which should be same as initial after wait+post */
	expected_final_value = initial_value;
	
	/* Enter daemon mode */
	test_daemon();
    /* Checkpoint and restore */
	test_waitsig();
	
    /* Verify semaphore state after restore */
	if (verify_semaphore_state(expected_final_value) < 0) {
		cleanup_semaphore();
		return 1;
	}
	
	if (test_semaphore_operations() < 0) {
		cleanup_semaphore();
		return 1;
	}
	
	cleanup_semaphore();
	
	pass();
	return 0;
} 
