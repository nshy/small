#include <small/small.h>
#include <small/quota.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include "unit.h"

enum {
	OBJSIZE_MIN = 3 * sizeof(int),
	OBJECTS_MAX = 1000
};

struct slab_arena arena;
struct slab_cache cache;
struct small_alloc alloc;
struct quota quota;
/* Streak type - allocating or freeing */
bool allocating = true;
/** Keep global to easily inspect the core. */
unsigned int seed;

static int *ptrs[OBJECTS_MAX];

static inline void
free_checked(int *ptr)
{
	fail_unless(ptr[0] < OBJECTS_MAX &&
		    ptr[ptr[1]/sizeof(int)-1] == ptr[0]);
	int pos = ptr[0];
	fail_unless(ptrs[pos] == ptr);
	ptrs[pos][0] = ptrs[pos][ptr[1]/sizeof(int)-1] = INT_MAX;
	smfree(&alloc, ptrs[pos], ptrs[pos][1]);
	ptrs[pos] = NULL;
}

static inline void *
alloc_checked(int pos, int size_min, int size_max)
{
	assert(size_max > size_min);
	int size = size_min + rand() % (size_max - size_min);

	if (ptrs[pos]) {
		assert(ptrs[pos][0] == pos);
		free_checked(ptrs[pos]);
	}
	if (! allocating)
		return NULL;
	void *ptr = smalloc(&alloc, size);
	fail_unless(ptr != NULL);
	fail_unless_asan((uintptr_t)ptr % SMALL_ASAN_ALIGNMENT == 0);
	fail_unless_asan((uintptr_t)ptr % (2 * SMALL_ASAN_ALIGNMENT) != 0);
	ptrs[pos] = ptr;
	ptrs[pos][0] = pos;
	ptrs[pos][1] = size;
	ptrs[pos][size/sizeof(int)-1] = pos;
	return ptrs[pos];
}

static int
small_is_unused_cb(const void *stats, void *arg)
{
	const struct mempool_stats *mempool_stats =
		(const struct mempool_stats *)stats;
	unsigned long *slab_total = arg;
	*slab_total += mempool_stats->slabsize * mempool_stats->slabcount;
	(void)stats;
	(void)arg;
	return 0;
}

static void
small_check_unused(void)
{
	struct small_stats totals;
	unsigned long slab_total = 0;
	small_stats(&alloc, &totals, small_is_unused_cb, &slab_total);
	fail_if(totals.used > 0);
	fail_if_no_asan(slab_cache_used(&cache) > slab_total);
}

static void
small_alloc_test(int size_min, int size_max, int objects_max,
		 int oscillation_max, int iterations_max)
{
	float actual_alloc_factor;
	small_alloc_create(&alloc, &cache, OBJSIZE_MIN,
			   sizeof(intptr_t), 1.3,
			   &actual_alloc_factor);

	for (int i = 0; i < iterations_max; i++) {
		int oscillation = rand() % oscillation_max;
		for (int j = 0; j < oscillation; ++j) {
			int pos = rand() % objects_max;
			alloc_checked(pos, size_min, size_max);
		}
		allocating = ! allocating;
	}

	for (int pos = 0; pos < OBJECTS_MAX; pos++) {
		if (ptrs[pos] != NULL)
			free_checked(ptrs[pos]);
	}

	small_check_unused();

	small_alloc_destroy(&alloc);
}

static void
small_alloc_basic(void)
{
	plan(1);
	header();

	small_alloc_test(OBJSIZE_MIN, 5000, 1000, 1024, 5000);
	ok(true);

	footer();
	check_plan();
}

#ifndef ENABLE_ASAN

static void
small_alloc_large(void)
{
	plan(1);
	header();

	size_t large_size_min = mempool_objsize_max(cache.arena->slab_size);
	size_t large_size_max = 2 * cache.arena->slab_size;
	small_alloc_test(large_size_min, large_size_max, 50, 10, 100);
	ok(true);

	footer();
	check_plan();
}

static inline void
check_small_alloc_info(struct small_alloc *alloc, size_t size, bool is_large,
		       size_t real_size)
{
	struct small_alloc_info info;
	small_alloc_info(alloc, NULL, size, &info);
	fail_unless(info.is_large == is_large);
	fail_unless(info.real_size == real_size);
}

static void
test_small_alloc_info(void)
{
	plan(1);
	header();
	/*
	 * Create the following groups of mempools.
	 * The table is valid for SLAB_MIN_ORDER0_SIZE = [4096, 8192, 16384].
	 * For 32768 and 65536 the first groups are merged.
	 *
	 *  slab  |  mempool
	 *  size  |  objsize
	 * -------|----------------------------------------------------------
	 *  16 KB | 64, 128
	 *  32 KB | 192, 256
	 *  64 KB | 384, 512
	 * 128 KB | 768, 1024
	 * 256 KB | 1536, 2048
	 * 512 KB | 3072, 4096
	 *   1 MB | 6144, 8192
	 *   2 MB | 12288, 16384
	 *   4 MB | 24576, 32768, 49152, 65536, 98304, 131072, 196608, 262144
	 */
	float actual_alloc_factor;
	small_alloc_create(&alloc, &cache, 64, 64, 1.5f, &actual_alloc_factor);

	check_small_alloc_info(&alloc, 257, false, 512);
	check_small_alloc_info(&alloc, 512, false, 512);
	check_small_alloc_info(&alloc, 16385, false, 262144);
	check_small_alloc_info(&alloc, 262144, false, 262144);
	check_small_alloc_info(&alloc, 262145, true, 262145);
	ok(true);

	small_alloc_destroy(&alloc);
	footer();
	check_plan();
}

/**
 * Make sure allocator works with low alloc_factor and high memory
 * pressure.
 *
 * See https://github.com/tarantool/tarantool/issues/10148
 */
static void
small_alloc_low_alloc_factor()
{
	plan(1);
	header();

	struct slab_arena arena1;
	struct slab_cache cache1;
	struct quota quota1;

	quota_init(&quota1, 1024 * 1024);
	slab_arena_create(&arena1, &quota1, 0, 4000000, MAP_PRIVATE);
	slab_cache_create(&cache1, &arena1);

	float actual_alloc_factor;
	small_alloc_create(&alloc, &cache1, OBJSIZE_MIN,
			   sizeof(intptr_t), 1.001,
			   &actual_alloc_factor);
	const unsigned alloc_size = 1024;
	const int alloc_count = 1024;
	/* Make sure we in mode when all mempools are used. */
	fail_unless(alloc.small_mempool_cache_size == SMALL_MEMPOOL_MAX);
	/* Make sure we allocate from pools. */
	fail_unless(alloc_size <= alloc.objsize_max);

	void **allocations = calloc(alloc_count, sizeof(void *));
	fail_unless(allocations != NULL);

	for (int i = 0; i < alloc_count; i++) {
		void *ptr = smalloc(&alloc, alloc_size);
		if (ptr == NULL)
			break;
		allocations[i] = ptr;
	}
	for (int i = 0; i < alloc_count; i++) {
		if (allocations[i] == NULL)
			break;
		smfree(&alloc, allocations[i], alloc_size);
	}

	small_alloc_destroy(&alloc);
	slab_cache_destroy(&cache1);
	slab_arena_destroy(&arena1);

	ok(true);

	footer();
	check_plan();
}

#else /* ifdef ENABLE_ASAN */

static char assert_msg_buf[128];

static void
on_assert_failure(const char *filename, int line, const char *funcname,
		  const char *expr)
{
	(void)filename;
	(void)line;
	snprintf(assert_msg_buf, sizeof(assert_msg_buf), "%s in %s",
		 expr, funcname);
	small_on_assert_failure = small_on_assert_failure_default;
}

static void
small_wrong_size_in_free(void)
{
	plan(1);
	header();

	float actual_alloc_factor;
	small_alloc_create(&alloc, &cache, OBJSIZE_MIN,
			   sizeof(intptr_t), 1.3,
			   &actual_alloc_factor);
	for (int i = 0; i < 117; i++) {
		int size = 100 + rand() % 900;
		void *ptr = smalloc(&alloc, size);
		fail_unless(ptr != NULL);
		small_on_assert_failure = on_assert_failure;
		assert_msg_buf[0] = '\0';
		smfree(&alloc, ptr, size + 1);
		small_on_assert_failure = small_on_assert_failure_default;
		fail_unless(strstr(assert_msg_buf,
				   "invalid object size\" in smfree") != NULL);
	}
	small_alloc_destroy(&alloc);
	ok(true);

	footer();
	check_plan();
}

static void
small_membership(void)
{
	plan(1);
	header();

	struct small_alloc alloc1;
	struct small_alloc alloc2;
	float dummy;

	small_alloc_create(&alloc1, &cache, OBJSIZE_MIN, sizeof(intptr_t),
			   1.3, &dummy);
	small_alloc_create(&alloc2, &cache, OBJSIZE_MIN, sizeof(intptr_t),
			   1.3, &dummy);
	void *ptr = smalloc(&alloc1, OBJSIZE_MIN);
	fail_unless(ptr != NULL);
	small_on_assert_failure = on_assert_failure;
	smfree(&alloc2, ptr, OBJSIZE_MIN);
	small_on_assert_failure = small_on_assert_failure_default;
	ok(strstr(assert_msg_buf,
		  "object and allocator id mismatch\" in smfree") != NULL);

	footer();
	check_plan();
}

#endif /* ifdef ENABLE_ASAN */

int main()
{
#ifdef ENABLE_ASAN
	plan(3);
#else
	plan(4);
#endif
	header();

	seed = time(NULL);
	note("random seed is %u", seed);
	srand(seed);

	quota_init(&quota, UINT_MAX);
	slab_arena_create(&arena, &quota, 0, 4000000,
			  MAP_PRIVATE);
	slab_cache_create(&cache, &arena);

	small_alloc_basic();
#ifndef ENABLE_ASAN
	small_alloc_large();
	test_small_alloc_info();
	small_alloc_low_alloc_factor();
#else
	small_wrong_size_in_free();
	small_membership();
#endif

	slab_cache_destroy(&cache);

	footer();
	return check_plan();
}
