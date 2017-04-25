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

#include <limits.h>
#include <pthread.h>
#include <sys/mman.h>
#include <execinfo.h>


#include "lwip_debug.h"
#include "lwip_common.h"

static void *lwip_bm_spacePool = NULL;

#define LWIP_BM_MAX_COUNT (32*4)

#define LWIP_BM_ELEMENTSIZE PATH_MAX

#ifdef LWIP_OS_BSD
#define LWIP_BM_ELEMENTBITSHIFT 10
#elif defined LWIP_OS_LINUX
#define LWIP_BM_ELEMENTBITSHIFT 12
#endif

//#define NOT_USING_BM


#define SET_BIT(bitVector, id) (bitVector[id/32] |= (1 << (id % 32)))
#define UNSET_BIT(bitVector, id) (bitVector[id/32] &= ~(1 << (id % 32)))
#define TEST_BIT(bitVector, id) (bitVector[id/32] & ( 1 << (id %32)))


#define RESET_BITVECTOR(bitVector) \
        do { \
                int tmp; \
                for (tmp = 0; tmp < sizeof(bitVector)/sizeof(int); tmp++) \
                        bitVector[tmp] = 0; \
        } while (0);


//#define LWIP_BM_DEBUG


     void
     print_trace (void)
     {
       void *array[10];
       size_t size;
       char **strings;
       size_t i;
     
       size = backtrace (array, 10);
       strings = backtrace_symbols (array, size);
     
       LWIP_CRITICAL("Obtained %zd stack frames.\n", size);
     
       for (i = 0; i < size; i++)
          LWIP_CRITICAL("%s\n", strings[i]);
     
       free (strings);
     }








static int lwip_bm_usage[LWIP_BM_MAX_COUNT/(sizeof(int)*8)];
static pthread_mutex_t lwip_bm_usage_lock = PTHREAD_MUTEX_INITIALIZER;

static int lwip_bm_nextSearchIdx = 0;

#ifdef LWIP_BM_DEBUG
static int lwip_bm_activeCount = 0;
static int lwip_bm_lastactiveCount = 0;
static int lwip_bm_totalCount = 0;
#endif


void *lwip_bm_initSpacePool() {
#ifdef NOT_USING_BM
	return NULL;
#endif
	if (lwip_bm_spacePool == NULL) {
		//mmap/brk/sbrk will cause programs break
		lwip_bm_spacePool = malloc(LWIP_BM_ELEMENTSIZE * LWIP_BM_MAX_COUNT); //sbrk(LWIP_BM_ELEMENTSIZE * LWIP_BM_MAX_COUNT);
				//mmap(NULL, LWIP_BM_ELEMENTSIZE * LWIP_BM_MAX_COUNT, PROT_READ|PROT_WRITE, 
				//	MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

		if (lwip_bm_spacePool == (void *) -1 || lwip_bm_spacePool == NULL) {
			lwip_bm_spacePool = NULL;
			LWIP_CRITICAL("Not enough space for buffer manager.");
		}
		RESET_BITVECTOR(lwip_bm_usage);
	}

	return lwip_bm_spacePool;
}


void *lwip_bm_malloc(int size) {

#ifdef NOT_USING_BM
	return malloc(size);
#endif

//	if (size < (PATH_MAX >> 1) || size > PATH_MAX) {
	if (size != PATH_MAX) {
		return malloc(size);
	}

	void *rv = NULL;
	if ((lwip_bm_spacePool == NULL) && (lwip_bm_initSpacePool() == NULL)) {
		LWIP_CRITICAL("Failed to allocate memory for space pool: errno: %d", errno);
		goto out;
	}

	int count = 0, _idx = lwip_bm_nextSearchIdx;
	pthread_mutex_lock(&lwip_bm_usage_lock);
	while (count < LWIP_BM_MAX_COUNT) {
		if (!TEST_BIT(lwip_bm_usage, (_idx+count)%LWIP_BM_MAX_COUNT) && SET_BIT(lwip_bm_usage, (_idx+count)%LWIP_BM_MAX_COUNT)) {
			rv = lwip_bm_spacePool + ((_idx+count)%LWIP_BM_MAX_COUNT) * LWIP_BM_ELEMENTSIZE;
			pthread_mutex_unlock(&lwip_bm_usage_lock);
			lwip_bm_nextSearchIdx = (_idx+count+1)%LWIP_BM_MAX_COUNT;

#ifdef LWIP_BM_DEBUG
			lwip_bm_activeCount++;
			if (lwip_bm_activeCount > lwip_bm_lastactiveCount) {
				LWIP_INFO("Count now is %d, was %d", lwip_bm_activeCount, lwip_bm_lastactiveCount);
				lwip_bm_lastactiveCount = lwip_bm_activeCount;
				print_trace();
			}

			lwip_bm_totalCount++;

			

//			LWIP_INFO("Active count: %d", lwip_bm_activeCount);
//			LWIP_INFO("Total count: %d", lwip_bm_totalCount);
//			LWIP_INFO("Returning: %d, %p", _idx+count, rv);
//			LWIP_ASSERT1(TEST_BIT(lwip_bm_usage, (_idx+count)%LWIP_BM_MAX_COUNT));
#endif

			goto out;
		}
		count++;
	}
	pthread_mutex_unlock(&lwip_bm_usage_lock);
	LWIP_CRITICAL("All allocated spaces are occuiped!! No free space left!!!");
//	print_trace();

/*	for (count = 0; count < LWIP_BM_MAX_COUNT; count++) {
		LWIP_CRITICAL("%d: %s", count, (char *)lwip_bm_spacePool + count*PATH_MAX);
	}
*/
	
out:
	return rv;
}


void lwip_bm_free(void *addr) {
#ifdef NOT_USING_BM
	return free(addr);
#endif

	int idx = (addr - lwip_bm_spacePool) >> LWIP_BM_ELEMENTBITSHIFT;

	if (idx < 0 || idx > LWIP_BM_MAX_COUNT)
		return free(addr);

	LWIP_ASSERT1(TEST_BIT(lwip_bm_usage, idx));

	pthread_mutex_lock(&lwip_bm_usage_lock);
	UNSET_BIT(lwip_bm_usage, idx);
	pthread_mutex_unlock(&lwip_bm_usage_lock);

#ifdef LWIP_BM_DEBUG
	lwip_bm_activeCount--;
//	LWIP_INFO("Active count: %d", lwip_bm_activeCount);
//	LWIP_INFO("Tofree: %d, %p", idx, addr);
#endif

	LWIP_ASSERT1(TEST_BIT(lwip_bm_usage, idx) == 0);
}


void *lwip_bm_realloc(void *addr, int newSize) {
#ifdef NOT_USING_BM
	return realloc(addr, newSize);
#endif

	int idx = (addr - lwip_bm_spacePool) >> LWIP_BM_ELEMENTBITSHIFT;

        if (idx < 0 || idx > LWIP_BM_MAX_COUNT)
                return realloc(addr, newSize);

	if (newSize <= LWIP_BM_ELEMENTSIZE)
		return addr;
	else {
		void *rv = malloc(newSize);
		memcpy(rv, addr, LWIP_BM_ELEMENTSIZE);
		lwip_bm_free(addr);
		return rv;
	}
}

