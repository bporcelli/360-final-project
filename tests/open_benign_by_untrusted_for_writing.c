#include <stdio.h>

/*
 *  Open a benign file for writing by an untrusted process
 *
 *  Expected Result: Action Denied
 */
int main(int argc, char **argv) {
	FILE *fp;
	if ((fp = fopen("./files/benign-file.txt","w")) == NULL) {
		printf("Error opening file.");
		exit(1);
	}
	printf("File opened for writing successfully!");
}