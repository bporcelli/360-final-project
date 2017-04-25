/* * Portable Integrity Protection (PIP) System -
 * Copyright (C) 2012 Secure Systems Laboratory, Stony Brook University
 *
 * This file is part of Portable Integrity Protection (PIP) System.
 *
 * Portable Integrity Protection (PIP) System is free software: you can redistribute it
 * and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Portable Integrity Protection (PIP) System is distributed in the hope that it will
 * be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Portable Integrity Protection (PIP) System.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include "lwip_level.h"
#include "lwip_utils.h"

int main( int argc, char *argv[]) {
	if (argc < 2) {
		printf("Please give a file path as input\n");
		return -1;
	}

	int fileCount = argc - 1;
	int fileIndex = 1;
	char *filename;

	do {
		filename = argv[fileIndex];

		if (!lwip_util_fileExist(filename)) {
			printf("File %s does not exist\n", filename);
			goto next;
		}

		printf("Level of the file %s is ", filename);
		if (lwip_level_isLow(lwip_file2Lv_read(filename)))
			printf("low\n");
		else if (lwip_level_isHigh(lwip_file2Lv_read(filename)))
			printf("high\n");
next:
		fileIndex++;
	} while (fileIndex < fileCount);

	return 0; 
}
