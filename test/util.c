#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>
#include "util.h"
#include "unit.h"

#ifdef ENABLE_ASAN

static char assert_msg_buf[128];

static void
on_assert_failure(const char *msg)
{
	strlcpy(assert_msg_buf, msg, lengthof(assert_msg_buf));
	small_on_assert_failure = NULL;
}

static void
test_asan_poison_precise(const char *buf, int size, int start, int end)
{
	for (int i = 0; i < size; i++) {
		int p = __asan_address_is_poisoned(buf + i);
		if (i < start || i >= end) {
			fail_if(p);
		} else {
			fail_unless(p);
		}
	}
}

/**
 * Check assumptions about ASAN poison/unpoison alignment. Poison/unpoison
 * is precise if range end is 8-aligned or range end is end of memory allocated
 * with malloc().
 */
static void
test_asan_poison_assumptions(void)
{
	plan(1);
	header();

	/* Test poison when range begin is arbitrary and end is 8-aligned. */
	int size = SMALL_POISON_ALIGNMENT * 17;
	char *buf = (char *)malloc(size);
	for (int n = 0; n < 100; n++) {
		int start = rand() % 17 * SMALL_POISON_ALIGNMENT;
		int end = start + (1 + rand() % (17 - start));
		end *= SMALL_POISON_ALIGNMENT;
		for (int i = 0; i < SMALL_POISON_ALIGNMENT; i++) {
			ASAN_POISON_MEMORY_REGION(buf + start + i,
						  end - start - i);
			test_asan_poison_precise(buf, size, start + i, end);
			ASAN_UNPOISON_MEMORY_REGION(buf + start + i,
						    end - start - i);
		}
	}
	free(buf);

	/* Test poison range end is end of memory allocated with malloc. */
	for (int n = 0; n < 1000; n++) {
		int size = 1 + rand() % 333;
		buf = malloc(size);
		int start = rand() % size;
		ASAN_POISON_MEMORY_REGION(buf + start, size - start);
		test_asan_poison_precise(buf, size, start, size);
		ASAN_UNPOISON_MEMORY_REGION(buf + start, size - start);
		free(buf);
	}
	ok(true);

	footer();
	check_plan();
}

static void
test_wrapper_run(size_t obj_size, size_t alignment, size_t header_size)
{
	struct small_wrapper w;
	small_wrapper_alloc(&w, obj_size, alignment, header_size);
	fail_unless(w.ptr != NULL);
	fail_unless(w.header != NULL);
	fail_unless(w.payload != NULL);
	fail_unless(w.ptr <= (char *)w.header);
	fail_unless(w.payload - (char *)w.header >= (ptrdiff_t)header_size);
	fail_unless((uintptr_t)w.payload % alignment == 0);
	fail_unless((uintptr_t)w.payload % (2 * alignment) != 0);
	memset((char *)w.header + sizeof(struct small_header), 0,
	       header_size - sizeof(struct small_header));
	char *payload_end = w.payload + obj_size;
	char *wrapper_end =
		w.ptr + small_wrapper_size(header_size, obj_size, alignment);
	fail_unless(payload_end <= wrapper_end);
	for (char *p = payload_end; p < wrapper_end; p++)
		fail_unless(__asan_address_is_poisoned(p));
	memset(w.payload, 0, obj_size);

	small_wrapper_poison(&w);
	char *magic_begin = (char *)small_align_down((uintptr_t)w.payload,
						     SMALL_POISON_ALIGNMENT);
	fail_unless(w.ptr <= magic_begin);
	for (char *p = w.ptr; p < magic_begin; p++)
		fail_unless(__asan_address_is_poisoned(p));

	struct small_wrapper wh;
	small_wrapper_from_header(&wh, w.header, obj_size, alignment,
				  header_size);
	fail_unless(wh.payload = w.payload);
	fail_unless(wh.header = w.header);
	fail_unless(wh.ptr = w.ptr);

	for (char *p = magic_begin; p < w.payload; p++) {
		char s = *p;
		fail_unless(*p != 0);
		*p = '\0';
		struct small_wrapper wp;
		small_on_assert_failure = on_assert_failure;
		assert_msg_buf[0] = '\0';
		small_wrapper_from_payload(&wp, w.payload, header_size);
		small_on_assert_failure = NULL;
		fail_unless(strstr(assert_msg_buf,
				   "wrapper magic check") != NULL);
		*p = s;
	}

	struct small_wrapper wp;
	small_wrapper_from_payload(&wp, w.payload, header_size);
	fail_unless(wp.payload = w.payload);
	fail_unless(wp.header = w.header);
	fail_unless(wp.ptr = w.ptr);
	for (char *p = (char *)w.header; p < magic_begin; p++)
		fail_if(__asan_address_is_poisoned(p));

	if (magic_begin < w.payload) {
		*magic_begin = '\0';
		small_on_assert_failure = on_assert_failure;
		assert_msg_buf[0] = '\0';
	}
	small_wrapper_free(&w);
	small_on_assert_failure = NULL;
	if (magic_begin < w.payload)
		fail_unless(strstr(assert_msg_buf,
				   "wrapper magic check") != NULL);
}

static void
test_wrapper(void)
{
	plan(1);
	header();

	for (int k = 0; k < 3; k++) {
		size_t header_size = sizeof(struct small_header) * (k + 1);
		for (int j = 0; j < 5; j++) {
			size_t alignment = 1 << j;
			for (int k = 0; k < 11; k++) {
				size_t obj_size = alignment * k;
				test_wrapper_run(obj_size, alignment,
						 header_size);
			}
		}
	}
	ok(true);

	footer();
	check_plan();
}

#endif /* ifdef ENABLE_ASAN */

static void
test_align_down(void)
{
	plan(1);
	header();

	for (int i = 0; i < 6; i++) {
		size_t alignment = 1 << i;
		for (size_t size = 0; size < 117; size++) {
			size_t r = small_align_down(size, alignment);
			fail_unless(r % alignment == 0);
			fail_unless(r <= size);
			fail_unless(size - r < alignment);
		}
	}
	ok(true);

	footer();
	check_plan();
}

int
main(void)
{
#ifdef ENABLE_ASAN
	plan(3);
#else
	plan(1);
#endif

	long seed = time(0);
	srand(seed);

#ifdef ENABLE_ASAN
	test_asan_poison_assumptions();
	test_wrapper();
#endif
	test_align_down();

	return check_plan();
}
