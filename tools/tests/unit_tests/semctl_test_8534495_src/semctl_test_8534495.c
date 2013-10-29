#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/stat.h>

int main(void) {
	key_t key;

	if ((key = ftok(".", 1)) == (key_t)-1) {
		perror("ftok");
		exit(EXIT_FAILURE);
	}

	int semid;
	if ((semid = semget(key, 1, IPC_CREAT | S_IRUSR | S_IWUSR)) == -1) {
		perror("semget");
		exit(EXIT_FAILURE);
	}

	union semun arg;

	/* Test for sem value > SEMVMX */
	arg.val = 32768;
	if (semctl(semid, 0, SETVAL, arg) == 0) {
		printf("semctl should have failed for SETVAL 32768\n");
		exit(EXIT_FAILURE);
	}

	/* Test for sem value < 0 */
	arg.val = -1;
	if (semctl(semid, 0, SETVAL, arg) == 0) {
		printf("semctl should have failed for SETVAL -1\n");
		exit(EXIT_FAILURE);
	}

	return 0;
}
