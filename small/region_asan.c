/*
 * Copyright 2010-2023, Tarantool AUTHORS, please see AUTHORS file.
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
#include "region.h"

/** Allocate new memory block whether for allocation or reservation. */
static void *
region_prepare_buf(struct region *region, size_t size, size_t alignment,
		   size_t used)
{
	struct small_wrapper wrapper;
	small_wrapper_alloc(&wrapper, size, alignment,
			    sizeof(struct region_allocation));

	struct region_allocation *alloc =
			(struct region_allocation *)wrapper.header;
	alloc->size = size;
	alloc->used = used;
	alloc->alignment = alignment;
	/* Other objects in the list are poisoned. */
	rlist_add_entry_no_asan(&region->allocations, alloc, link);

	small_wrapper_poison(&wrapper);
	return wrapper.payload;
}

void *
region_aligned_reserve(struct region *region, size_t size, size_t alignment)
{
	small_assert(region->reserved == 0);

	/* See explanation for lower limit in the header. */
	size_t pagesize = small_getpagesize();
	if (size < pagesize)
		size = pagesize;

	void *ptr = region_prepare_buf(region, size, alignment, 0);
	region->reserved = size;
	return ptr;
}

/**
 * Allocate memory in case of prior reservation.
 *
 * Use SMALL_NO_SANITIZE_ADDRESS to access poisoned metadata of allocations.
 */
SMALL_NO_SANITIZE_ADDRESS
static inline void *
region_aligned_alloc_reserved(struct region *region, size_t size,
			     size_t alignment)
{
	small_assert(size <= region->reserved);
	struct region_allocation *alloc =
			rlist_first_entry(&region->allocations,
					  struct region_allocation, link);
	small_assert(alignment == alloc->alignment);

	if (small_unlikely(region->on_alloc_cb != NULL))
		region->on_alloc_cb(region, size, region->cb_arg);

	region->used += size;
	alloc->used += size;
	region->reserved = 0;

	/* Poison reserved but not allocated memory. */
	struct small_wrapper wrapper;
	small_wrapper_from_header(&wrapper, alloc, alloc->size,
				  alloc->alignment, sizeof(*alloc));
	ASAN_POISON_MEMORY_REGION((char *)wrapper.payload + size,
				  alloc->size - size);
	return wrapper.payload;
}

void *
region_aligned_alloc(struct region *region, size_t size, size_t alignment)
{
	if (region->reserved != 0)
		return region_aligned_alloc_reserved(region, size, alignment);

	void *ptr = region_prepare_buf(region, size, alignment, size);
	if (small_unlikely(region->on_alloc_cb != NULL))
		region->on_alloc_cb(region, size, region->cb_arg);
	region->used += size;
	return ptr;
}

/**
 * Use SMALL_NO_SANITIZE_ADDRESS to access poisoned metadata of allocations.
 */
SMALL_NO_SANITIZE_ADDRESS
void
region_truncate(struct region *region, size_t used)
{
	small_assert(used <= region->used);
	size_t cut_size = region->used - used;

	struct region_allocation *alloc, *tmp;
	rlist_foreach_entry_safe(alloc, &region->allocations, link, tmp) {
		/* Second check allows to truncate blocks with 0 usage. */
		if (cut_size == 0 && alloc->used != 0)
			break;
		/*
		 * This implementation does not support truncating to the
		 * middle of previously allocated block.
		 */
		small_assert(alloc->used <= cut_size);
		cut_size -= alloc->used;
		rlist_del_entry(alloc, link);

		struct small_wrapper wrapper;
		small_wrapper_from_header(&wrapper, alloc, alloc->size,
					  alloc->alignment, sizeof(*alloc));
		small_wrapper_free(&wrapper);
	}
	region->used = used;
	region->reserved = 0;
	if (small_unlikely(region->on_truncate_cb != NULL))
		region->on_truncate_cb(region, used, region->cb_arg);
}

SMALL_NO_SANITIZE_ADDRESS
void *
region_join(struct region *region, size_t size)
{
	small_assert(size <= region->used);
	small_assert(region->reserved == 0);
	struct region_allocation *alloc =
			rlist_first_entry(&region->allocations,
					  struct region_allocation, link);
	char *ret = (char *)region_alloc(region, size);
	size_t offset = size;
	while (offset > 0) {
		struct small_wrapper wrapper;
		small_wrapper_from_header(&wrapper, alloc, alloc->size,
					  alloc->alignment, sizeof(*alloc));

		size_t copy_size = alloc->used;
		if (offset < copy_size)
			copy_size = offset;
		memcpy(ret + offset - copy_size, wrapper.payload, copy_size);

		offset -= copy_size;
		alloc = rlist_next_entry(alloc, link);
	}
	return ret;
}
