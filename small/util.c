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
#include "util.h"

small_on_assert_failure_f small_on_assert_failure;
uint64_t small_magic = 0x9cb69dbf535347d8;

void *
small_asan_alloc(size_t payload_size, size_t alignment, size_t header_size)
{
	static_assert(sizeof(uint16_t) <= SMALL_ASAN_HEADER_ALIGNMENT,
		      "offset is not fit before header");
	/**
	 * Allocated memory has next structure:
	 *
	 * 1. place for offset from header to payload
	 * 2. header
	 * 3. padding due to payload alignment
	 * 4. place for offset from payload to header
	 * 5. payload
	 * 5. unused space due to payload padding
	 *
	 * Note that although offset is limited to 2 bytes field (1)
	 * has SMALL_ASAN_HEADER_ALIGNMENT size so that header is aligned
	 * to this value.
	 */
	size_t alloc_size = SMALL_ASAN_HEADER_ALIGNMENT +
			    header_size +
			    SMALL_POISON_ALIGNMENT - 1 +
			    sizeof(uint16_t) +
			    2 * alignment - 1 +
			    payload_size;
	char *alloc = (char *)small_xmalloc(alloc_size);

	char *payload = alloc + alloc_size - payload_size;
	payload = (char *)small_align_down((uintptr_t)payload, alignment);
	if (((uintptr_t)payload % (2 * alignment)) == 0)
		payload -= alignment;

	char *header = alloc + SMALL_ASAN_HEADER_ALIGNMENT;
	small_assert(payload - header <= UINT16_MAX);
	uint16_t offset = payload - header;
	char *magic_begin = (char *)
		small_align_down((uintptr_t)payload, SMALL_POISON_ALIGNMENT);
	memcpy(magic_begin - sizeof(offset), &offset, sizeof(offset));
	*(uint16_t *)alloc = offset;

	/* Poison area after the payload. */
	char *payload_end = payload + payload_size;
	char *alloc_end = alloc + alloc_size;
	ASAN_POISON_MEMORY_REGION(payload_end, alloc_end - payload_end);
	/* Poison area before the payload. */
	ASAN_POISON_MEMORY_REGION(alloc, magic_begin - alloc);
	static_assert(sizeof(small_magic) >= SMALL_POISON_ALIGNMENT,
		      "magic size is not large enough");
	/* Write magic to the area that cannot be poisoned. */
	memcpy(magic_begin, &small_magic, payload - magic_begin);

	return header;
}
