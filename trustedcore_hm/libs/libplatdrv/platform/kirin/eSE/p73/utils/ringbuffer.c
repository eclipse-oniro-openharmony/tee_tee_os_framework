/******************************************************************************
 *
 *  Copyright (C) 2017 Google Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

#include <assert.h>
#include <stdlib.h>

#include "ringbuffer.h"

struct ringbuffer_t {
  unsigned int total;
  unsigned int available;
  uint8_t* base;
  uint8_t* head;
  uint8_t* tail;
};

ringbuffer_t* ringbuffer_init(const unsigned int size) {
  ringbuffer_t* p = (ringbuffer_t*)(calloc(1, sizeof(ringbuffer_t)));

  if (p == NULL) return p;

  p->base = (uint8_t*)(calloc(size, sizeof(uint8_t)));
  p->head = p->tail = p->base;
  p->total = p->available = size;

  return p;
}

void ringbuffer_free(ringbuffer_t* rb) {
  if (rb != NULL) free(rb->base);
  free(rb);
}

unsigned int ringbuffer_available(const ringbuffer_t* rb) {
  assert(rb);
  return rb->available;
}

unsigned int ringbuffer_size(const ringbuffer_t* rb) {
  assert(rb);
  return rb->total - rb->available;
}

unsigned int ringbuffer_insert(ringbuffer_t* rb, const uint8_t* p, unsigned int length) {
  assert(rb);
  assert(p);

  if (length > ringbuffer_available(rb)) length = ringbuffer_available(rb);

  for (unsigned int i = 0; i != length; ++i) {
    *rb->tail++ = *p++;
    if (rb->tail >= (rb->base + rb->total)) rb->tail = rb->base;
  }

  rb->available -= length;
  return length;
}

unsigned int ringbuffer_delete(ringbuffer_t* rb, unsigned int length) {
  assert(rb);

  if (length > ringbuffer_size(rb)) length = ringbuffer_size(rb);

  rb->head += length;
  if (rb->head >= (rb->base + rb->total)) rb->head -= rb->total;

  rb->available += length;
  return length;
}
#if 0

unsigned int ringbuffer_peek(const ringbuffer_t* rb, off_t offset, uint8_t* p,
                       unsigned int length) {
  assert(rb);
  assert(p);
  assert(offset >= 0);
  assert((unsigned int)offset <= ringbuffer_size(rb));

  uint8_t* b = ((rb->head - rb->base + offset) % rb->total) + rb->base;
  const unsigned int bytes_to_copy = (offset + length > ringbuffer_size(rb))
                                   ? ringbuffer_size(rb) - offset
                                   : length;

  for (unsigned int copied = 0; copied < bytes_to_copy; ++copied) {
    *p++ = *b++;
    if (b >= (rb->base + rb->total)) b = rb->base;
  }

  return bytes_to_copy;
}

unsigned int ringbuffer_pop(ringbuffer_t* rb, uint8_t* p, unsigned int length) {
  assert(rb);
  assert(p);

  const unsigned int copied = ringbuffer_peek(rb, 0, p, length);
  rb->head += copied;
  if (rb->head >= (rb->base + rb->total)) rb->head -= rb->total;

  rb->available += copied;
  return copied;
}
#endif
