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
#include "small.h"

void
small_alloc_create(struct small_alloc *alloc, struct slab_cache *cache,
		   uint32_t objsize_min, unsigned granularity,
		   float alloc_factor, float *actual_alloc_factor)
{
	(void)objsize_min;
	(void)granularity;
	(void)alloc_factor;
	alloc->quota = &cache->quota;
	rlist_create(&alloc->objects);
	alloc->used = 0;
	alloc->objcount = 0;
	*actual_alloc_factor = alloc_factor;
}

/**
 * Use SMALL_NO_SANITIZE_ADDRESS to access poisoned metadata of objects.
 */
SMALL_NO_SANITIZE_ADDRESS
void
small_alloc_destroy(struct small_alloc *alloc)
{
	struct small_object *obj, *tmp;
	rlist_foreach_entry_safe(obj, &alloc->objects, link, tmp) {
		quota_end_lease(alloc->quota, obj->size);
		struct small_wrapper wrapper;
		small_wrapper_from_header(&wrapper, obj, obj->size,
					  SMALL_ASAN_ALIGNMENT, sizeof(*obj));
		small_wrapper_free(&wrapper);
	}
	rlist_create(&alloc->objects);
}

void *
smalloc(struct small_alloc *alloc, size_t size)
{
	if (quota_lease(alloc->quota, size) < 0)
		return NULL;
	struct small_wrapper wrapper;
	small_wrapper_alloc(&wrapper, size, SMALL_ASAN_ALIGNMENT,
			    sizeof(struct small_object));

	struct small_object *obj = (struct small_object *)wrapper.header;
	obj->size = size;
	/* Other objects in the list are poisoned. */
	rlist_add_entry_no_asan(&alloc->objects, obj, link);
	alloc->used += size;
	alloc->objcount++;

	small_wrapper_poison(&wrapper);
	return wrapper.payload;
}

void
smfree(struct small_alloc *alloc, void *ptr, size_t size)
{
	struct small_wrapper wrapper;
	small_wrapper_from_payload(&wrapper, ptr, sizeof(struct small_object));

	struct small_object *obj = (struct small_object *)wrapper.header;
	small_assert(obj->size == size && "smfree object size check");
	quota_end_lease(alloc->quota, obj->size);
	/* Other objects in the list are poisoned. */
	rlist_del_entry_no_asan(obj, link);
	alloc->used -= obj->size;
	alloc->objcount--;

	small_wrapper_free(&wrapper);
}
