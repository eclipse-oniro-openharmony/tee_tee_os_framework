/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: elfloader uncompress function
 * Create: 2020-12
 */
#define ZLIB_INTERNAL
#include "zlib.h"
#include "stdint.h"
#ifndef NULL
#define NULL 0
#endif

extern int memset(void *dest, int c, unsigned long count);

struct zunzip_stream {
    z_stream __stream;
    void *free_mem_start;
    void *free_mem_end;
    void *free_mem;
};

static void *__malloc(void *_stream, int eltsize, int number)
{
    struct zunzip_stream *stream = (struct zunzip_stream *)_stream;
    int size                     = eltsize * number;
    void *ptr                    = stream->free_mem;

    if ((unsigned long)(uintptr_t)ptr + size >= (unsigned long)(uintptr_t)stream->free_mem_end)
        return NULL;
    stream->free_mem += size;
    return ptr;
}

static void __free(__attribute__((unused)) void *_stream, __attribute__((unused)) void *ptr)
{
    // do nothing
}

int zuncompress(void *compressed_data, unsigned long compressed_sz, void *unpack_data, unsigned long unpack_sz,
                void *free_mem, unsigned long free_mem_sz)
{
    struct zunzip_stream *stream = NULL;
    int err;

    if (compressed_data == NULL || unpack_data == NULL || free_mem == NULL)
        return -1;

    if (!(((unsigned long)(uintptr_t)compressed_data > (unsigned long)(uintptr_t)unpack_data + unpack_sz) ||
          ((unsigned long)(uintptr_t)unpack_data > (unsigned long)(uintptr_t)compressed_data + compressed_sz)))
        return -1;

    stream = (struct zunzip_stream *)free_mem;
    free_mem += sizeof(struct zunzip_stream);
    free_mem_sz -= sizeof(struct zunzip_stream);

    if (memset((char *)free_mem, 0, sizeof(struct zunzip_stream)) != 0)
        return -1;

    stream->free_mem_start = free_mem;
    stream->free_mem_end   = free_mem + free_mem_sz;
    stream->free_mem       = free_mem;

    stream->__stream.zalloc    = (alloc_func)__malloc;
    stream->__stream.zfree     = (free_func)__free;
    stream->__stream.next_in   = compressed_data;
    stream->__stream.avail_in  = compressed_sz;
    stream->__stream.next_out  = unpack_data;
    stream->__stream.avail_out = (unsigned int)(unpack_sz);
    stream->__stream.opaque    = (void *)stream;

    err = inflateInit2(&(stream->__stream), 16 + MAX_WBITS);
    if (err != Z_OK)
        return err;

    err = inflate(&(stream->__stream), Z_FINISH);
    if (err != Z_STREAM_END) {
        inflateEnd(&(stream->__stream));
        if (err == Z_NEED_DICT || (err == Z_BUF_ERROR && stream->__stream.avail_in == 0))
            return Z_DATA_ERROR;
        return err;
    }

    err = inflateEnd(&(stream->__stream));
    return err;
}
