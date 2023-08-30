#pragma once
/*
 * Copyright 2022, Tarantool AUTHORS, please see AUTHORS file.
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <unistd.h>
#include <stddef.h>
#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "small_config.h"
#ifdef ENABLE_ASAN
#  include <sanitizer/asan_interface.h>
#endif

#ifndef __has_builtin
#  define __has_builtin(x) 0
#endif

/**
 * Helpers to provide the compiler with branch prediction information.
 */
#if __has_builtin(__builtin_expect) || defined(__GNUC__)
#  define small_likely(x)    __builtin_expect(!! (x),1)
#  define small_unlikely(x)  __builtin_expect(!! (x),0)
#else
#  define small_likely(x)    (x)
#  define small_unlikely(x)  (x)
#endif

#if !defined(__cplusplus) && !defined(static_assert)
# define static_assert _Static_assert
#endif

#ifndef lengthof
#define lengthof(array) (sizeof (array) / sizeof ((array)[0]))
#endif

/**
 * Assertion for small library. Similarly to assert() aborts if expression is
 * false but does not depend on NDEBUG (because we currently do not run
 * only ASAN release build in CI).
 *
 * Additionally it can be used in tests. If small_on_assert_failure callback
 * is not NULL then the callback is called with the stringified assert
 * expression as argument if assertion is failed. Note that this mode should
 * be used only to test cases when program can continue to run as
 * there is no abort in this case.
 */
#define small_assert(expr) do {							\
	if (small_likely(expr))							\
		break;								\
	if (small_on_assert_failure == NULL) {					\
		fprintf(stderr, "%s:%d: Memory check `%s' failed.\n",		\
			__FILE__, __LINE__, #expr);				\
		abort();							\
	} else {								\
		small_on_assert_failure(#expr);					\
	}									\
} while (0)

#define small_xmalloc(size)							\
	({									\
		void *ret = malloc(size);					\
		if (small_unlikely(ret == NULL)) {				\
			fprintf(stderr, "Can't allocate %zu bytes at %s:%d",	\
				(size_t)(size), __FILE__, __LINE__);		\
			exit(EXIT_FAILURE);					\
		}								\
		ret;								\
	})

typedef void (*small_on_assert_failure_f)(const char *msg);

/** Callback to be called if set and small_assert is failed. */
extern small_on_assert_failure_f small_on_assert_failure;

/**
 * Return size of a memory page in bytes.
 */
static inline long
small_getpagesize(void)
{
	/* sysconf() returns -1 on error, or page_size >= 1 otherwise. */
	long page_size = sysconf(_SC_PAGESIZE);
	if (small_unlikely(page_size < 1))
		return 4096;
	return page_size;
}

/**
 * Align a size - round up to nearest divisible by the given alignment.
 * Alignment must be a power of 2
 */
static inline size_t
small_align(size_t size, size_t alignment)
{
	/* Must be a power of two */
	assert((alignment & (alignment - 1)) == 0);
	/* Bit arithmetics won't work for a large size */
	assert(size <= SIZE_MAX - alignment);
	return (size - 1 + alignment) & ~(alignment - 1);
}

/**
 * Align value to the nearest divisible by the given alignment which is
 * not greater than value. Alignment must be a power of 2.
 */
static inline size_t
small_align_down(size_t value, size_t alignment)
{
	assert((alignment & (alignment - 1)) == 0);
	return value & ~(alignment - 1);
}

/** Round up a number to the nearest power of two. */
static inline size_t
small_round(size_t size)
{
	if (size < 2)
		return size;
	assert(size <= SIZE_MAX / 2 + 1);
	assert(size - 1 <= ULONG_MAX);
	size_t r = 1;
	return r << (sizeof(unsigned long) * CHAR_BIT -
		     __builtin_clzl((unsigned long) (size - 1)));
}

/** Binary logarithm of a size. */
static inline size_t
small_lb(size_t size)
{
	assert(size <= ULONG_MAX);
	return sizeof(unsigned long) * CHAR_BIT -
		__builtin_clzl((unsigned long) size) - 1;
}

#ifdef ENABLE_ASAN

#define SMALL_NO_SANITIZE_ADDRESS __attribute__((no_sanitize_address))

/**
 * Small wrapper allows to hold extra information (header) for every user
 * memory allocation. For this purpose we allocate more memory then requested
 * and keep a header and user data in a same chunk of memory. So wrapper memory
 * layout is next:
 *
 *     UUU HHHHHHH AAA PPPPPPPP UUUU
 *
 * Where
 *    P - user payload
 *    H - header
 *    A - memory used for alignment
 *    U - unused memory (because of header and payload alignments)
 *
 * Header has SMALL_HEADER_ALIGNMENT (large alignment to allow any
 * types in header). User payload is aligned to given alignment A.
 * Additionally payload is not aligned on 2 * A. This improves unaligned
 * access check. Header should be inherited from struct small_header.
 *
 * Wrapper is used with ASAN builds. Thus to check buffer underflows/overflows
 * wrapper memory is poisoned except for user payload of course. Note that
 * due to poison alignment restrictions we may not be able to poison
 * part of alignment area before payload. In this case we write magic to
 * the area which cannot be poisoned and check it is not changed when memory
 * is freed.
 */

enum {
	/* Alignment of header in wrapper. */
	SMALL_HEADER_ALIGNMENT = sizeof(long long),
	/*
	 * ASAN does not allow to precisely poison arbitrary ranges of memory.
	 * However if range end is 8-aligned or range end is end of memory
	 * allocated with malloc() then poison is precise.
	 */
	SMALL_POISON_ALIGNMENT = 8,
};

/** Random magic to be used for memory that cannot be poisoned. */
extern uint64_t small_magic;

/** Wrapper header base. Should be used as first member of actual header. */
struct small_header {
	/** Distance from header to wrapper begin in bytes. */
	size_t alloc_offset;
};

/**
 * Wrapper pointers.
 */
struct small_wrapper {
	/* Pointer to the wrapper itself. */
	char *ptr;
	/* Pointer to the header inside the wrapper. */
	struct small_header *header;
	/* Pointer to the payload inside the wrapper. */
	char *payload;
};

/** Calculate wrapper header pointer from wrapper payload pointer. */
static inline struct small_header *
small_wrapper_header(char *payload, size_t header_size)
{
	return (struct small_header *)
		small_align_down((uintptr_t)(payload - header_size),
				 SMALL_HEADER_ALIGNMENT);
}

/** Calculate wrapper size. Here alignment is desired user payload alignment. */
static inline size_t
small_wrapper_size(size_t header_size, size_t payload_size, size_t alignment)
{
	/*
	 * 2 * A - 1 padding is required to align object on A and
	 * at the same time make sure object is not 2 * A aligned.
	 */
	return header_size + 2 * alignment - 1 + payload_size;
}

/**
 * Calculate user payload pointer given wrapper pointer. Alignment argument
 * is payload alignment.
 */
static inline char *
small_wrapper_payload(char *ptr, size_t header_size, size_t payload_size,
		      size_t alignment)
{
	size_t wrapper_size = small_wrapper_size(header_size, payload_size,
						 alignment);
	char *payload = ptr + wrapper_size - payload_size;
	payload = (char *)small_align_down((uintptr_t)payload, alignment);
	if (((uintptr_t)payload % (2 * alignment)) == 0)
		payload -= alignment;
	small_assert(payload >= ptr);
	return payload;
}

/**
 * Allocate wrapper memory and initialize wrapper pointers. Alignment
 * argument is payload alignment.
 *
 * Also memory after payload is poisoned.
 */
static inline void
small_wrapper_alloc(struct small_wrapper *wrapper, size_t payload_size,
		    size_t alignment, size_t header_size)
{
	size_t wrapper_size = small_wrapper_size(header_size, payload_size,
						 alignment);
	wrapper->ptr = (char *)small_xmalloc(wrapper_size);
	wrapper->payload = small_wrapper_payload(wrapper->ptr, header_size,
						 payload_size, alignment);
	wrapper->header = small_wrapper_header(wrapper->payload, header_size);
	small_assert((char *)wrapper->header >= wrapper->ptr);
	wrapper->header->alloc_offset = (char *)wrapper->header - wrapper->ptr;
	/*
	 * This poison is expected to be precise (without alignment issues)
	 * because we poison to the end of the allocated block.
	 */
	char *begin = wrapper->payload + payload_size;
	char *end = wrapper->ptr + wrapper_size;
	ASAN_POISON_MEMORY_REGION(begin, end - begin);
}

/**
 * Unpoison wrapper header memory. Unpoison is intended to be used
 * on freeing memory so we don't need to unpoison what we poisoned
 * before entirely. We need to unpoison only header to be able to
 * read header data to do extra actions before freeing memory.
 */
static inline void
small_wrapper_unpoison(char *payload, void *header)
{
	/* Check unpoison actually unpoison from the beginning of the header. */
	static_assert(SMALL_HEADER_ALIGNMENT % SMALL_POISON_ALIGNMENT == 0,
		      "header should be aligned on ASAN alignment");
	/* Unpoison both header and magic area if the latter exists. */
	ASAN_UNPOISON_MEMORY_REGION(header, payload - (char *)header);
	char *magic_begin = (char *)small_align_down((uintptr_t)payload,
						     SMALL_POISON_ALIGNMENT);
	small_assert(memcmp(magic_begin, &small_magic,
		     payload - magic_begin) == 0 && "wrapper magic check");
}

/**
 * Free wrapper memory.
 */
static inline void
small_wrapper_free(struct small_wrapper *wrapper)
{
	/* Call unpoison to check that magic is not changed. */
	small_wrapper_unpoison(wrapper->payload, wrapper->header);
	free(wrapper->ptr);
}

/**
 * Initialize wrapper pointers given header pointer. Alignment argument
 * is payload alignment.
 *
 * Use SMALL_NO_SANITIZE_ADDRESS to access poisoned metadata.
 */
SMALL_NO_SANITIZE_ADDRESS
static inline void
small_wrapper_from_header(struct small_wrapper *wrapper, void *header,
			  size_t payload_size, size_t alignment,
			  size_t header_size)
{
	wrapper->header = (struct small_header *)header;
	wrapper->ptr = (char *)header - wrapper->header->alloc_offset;
	wrapper->payload =
		small_wrapper_payload(wrapper->ptr, header_size, payload_size,
				      alignment);
}

/**
 * Initialize wrapper pointers given payload pointer. Alignment argument
 * is payload alignment. Additionally header is unpoisoned.
 *
 * Intended usage on freeing memory is:
 *    small_wrapper_from_payload(&wrapper, payload, ..);
 *    Do some actions accessing wrapper.header.
 *    small_wrapper_free(&wrapper);
 *
 * Use SMALL_NO_SANITIZE_ADDRESS to access poisoned metadata.
 */
SMALL_NO_SANITIZE_ADDRESS
static inline void
small_wrapper_from_payload(struct small_wrapper *wrapper, void *payload,
			   size_t header_size)
{
	wrapper->payload = (char *)payload;
	wrapper->header = small_wrapper_header(wrapper->payload, header_size);
	small_wrapper_unpoison(wrapper->payload, wrapper->header);
	wrapper->ptr = (char *)wrapper->header - wrapper->header->alloc_offset;
}

/**
 * Poison memory before the payload. Memory after payload is already poisoned
 * on allocation.
 *
 * Intended usage on allocating memory is:
 *     small_wrapper_alloc(&wrapper, ...);
 *     Do some actions accessing wrapper.header.
 *     small_wrapper_poison(&wrapper);
 *     Return wrapper.payload the user.
 */
static inline void
small_wrapper_poison(struct small_wrapper *wrapper)
{
	static_assert(sizeof(struct small_header) >= SMALL_POISON_ALIGNMENT,
		      "magic should not overwrite header");
	char *magic_begin =
		(char *)small_align_down((uintptr_t)wrapper->payload,
					 SMALL_POISON_ALIGNMENT);
	ASAN_POISON_MEMORY_REGION(wrapper->ptr,
				  magic_begin - wrapper->ptr);
	static_assert(sizeof(small_magic) >= SMALL_POISON_ALIGNMENT,
		      "magic size is not large enough");
	memcpy(magic_begin, &small_magic, wrapper->payload - magic_begin);
}

#endif /* ifdef ENABLE_ASAN */
