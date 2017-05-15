#include <stdio.h>

/*
 *  Open a benign file for reading by an untrusted process
 *
 *  Expected Result: Action Allowed
 */
int main(int argc, char **argv) {
	FILE *fp;
	if ((fp = fopen("./files/benign-file.txt","r")) == NULL) {
		printf("Error opening file.");
		exit(1);
	}
	printf("File opened for reading successfully!");
}