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
#include "obuf.h"

void
obuf_create(struct obuf *buf, struct slab_cache *slabc, size_t start_capacity)
{
	buf->slabc = slabc;
	buf->start_capacity = start_capacity;
	size_t size = (SMALL_OBUF_IOV_MAX + 1) * sizeof(*buf->iov);
	buf->iov = small_xmalloc(size);
	memset(buf->iov, 0, size);
	memset(buf->capacity, 0,
	       lengthof(buf->capacity) * sizeof(buf->capacity[0]));
	buf->pos = 0;
	buf->used = 0;
	buf->reserved = 0;
}

/** Allocate new memory block whether for allocation or reservation. */
static void *
obuf_prepare_buf(struct obuf *buf, size_t size)
{
	if (buf->pos >= SMALL_OBUF_IOV_CHECKED_SIZE - 1) {
		int gpos = buf->pos - SMALL_OBUF_IOV_CHECKED_SIZE;
		if (gpos < 0 ||
		    (buf->iov[buf->pos].iov_len + size) > buf->capacity[gpos]) {
			size_t capacity = buf->start_capacity << (gpos + 1);
			while (capacity < size)
				capacity <<= 1;
			buf->pos++;
			small_assert(buf->pos < SMALL_OBUF_IOV_MAX);
			struct iovec *iov = &buf->iov[buf->pos];
			iov->iov_base = small_xmalloc(capacity);
			buf->capacity[gpos + 1] = capacity;
			iov->iov_len = 0;
		}
		struct iovec *iov = &buf->iov[buf->pos];
		void *ptr = iov->iov_base + iov->iov_len;
		return ptr;
	}

	struct small_wrapper wrapper;
	small_wrapper_alloc(&wrapper, size, SMALL_OBUF_ALIGNMENT,
			    sizeof(struct obuf_allocation));

	/* See obuf.pos semantics in struct definition. */
	if (buf->iov[buf->pos].iov_base != NULL)
		buf->pos++;
	buf->iov[buf->pos].iov_base = wrapper.payload;
	buf->iov[buf->pos].iov_len = 0;

	small_wrapper_poison(&wrapper);
	return wrapper.payload;
}

void *
obuf_reserve(struct obuf *buf, size_t size)
{
	small_assert(buf->reserved == 0);

	/* See explanation for lower limit in the header. */
	size_t pagesize = small_getpagesize();
	if (size < pagesize)
		size = pagesize;

	void *ptr = obuf_prepare_buf(buf, size);
	buf->reserved = size;
	return ptr;
}

/** Allocate memory in case of prior reservation. */
void *
obuf_alloc_reserved(struct obuf *buf, size_t size)
{
	small_assert(size <= buf->reserved);

	struct iovec *iov = &buf->iov[buf->pos];
	char *ptr = iov->iov_base + iov->iov_len;
	iov->iov_len += size;
	buf->used += size;
	if (buf->pos < SMALL_OBUF_IOV_CHECKED_SIZE)
		ASAN_POISON_MEMORY_REGION(ptr + size, buf->reserved - size);
	buf->reserved = 0;
	return ptr;
}

void *
obuf_alloc(struct obuf *buf, size_t size)
{
	if (buf->reserved != 0)
		return obuf_alloc_reserved(buf, size);

	void *ptr = obuf_prepare_buf(buf, size);
	buf->iov[buf->pos].iov_len += size;
	buf->used += size;
	return ptr;
}

void
obuf_rollback_to_svp(struct obuf *buf, struct obuf_svp *svp)
{
	small_assert(svp->pos <= (size_t)buf->pos);
	int pos = svp->pos;
	/*
	 * Usually on rollback we start freeing from the position after the
	 * position in svp but in case of rollback to 0 we may want to
	 * free the iov[0]. This is due to inconvinient semantics of
	 * obuf.pos See obuf.pos semantics in struct definition.
	 */
	if (!(svp->pos == 0 &&
	      svp->iov_len == 0 &&
	      buf->iov[0].iov_base != NULL))
		pos++;
	int endpos = buf->pos;
	if (endpos > SMALL_OBUF_IOV_CHECKED_SIZE)
		endpos = SMALL_OBUF_IOV_CHECKED_SIZE;
	for (int i = pos; i < endpos; i++) {
		struct small_wrapper wrapper;
		small_wrapper_from_payload(&wrapper, buf->iov[i].iov_base,
					   sizeof(struct obuf_allocation));
		small_wrapper_free(&wrapper);

	}
	int startpos = pos;
	if (startpos < SMALL_OBUF_IOV_CHECKED_SIZE)
		startpos = SMALL_OBUF_IOV_CHECKED_SIZE;
	for (int i = startpos; i <= buf->pos; i++) {
		free(buf->iov[i].iov_base);
		buf->capacity[i - SMALL_OBUF_IOV_CHECKED_SIZE] = 0;
	}
	memset(&buf->iov[pos], 0, sizeof(*buf->iov) * (buf->pos - pos + 1));
	buf->pos = svp->pos;
	buf->used = svp->used;
	buf->iov[buf->pos].iov_len = svp->iov_len;
	buf->reserved = 0;
}

void
obuf_destroy(struct obuf *buf)
{
	struct obuf_svp svp;
	obuf_svp_reset(&svp);
	obuf_rollback_to_svp(buf, &svp);
	free(buf->iov);
}

void
obuf_reset(struct obuf *buf)
{
	struct obuf_svp svp;
	obuf_svp_reset(&svp);
	obuf_rollback_to_svp(buf, &svp);
}
