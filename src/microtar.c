/*
 * Copyright (c) 2017 rxi
 * Copyright (c) 2021 Aidan MacDonald
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "microtar.h"
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <string.h>

static int parse_octal(const char* str, size_t len, unsigned* ret)
{
    unsigned n = 0;

    while(len-- > 0 && *str != 0) {
        if(*str < '0' || *str > '9')
            return MTAR_EOVERFLOW;

        if(n > UINT_MAX/8)
            return MTAR_EOVERFLOW;
        else
            n *= 8;

        char r = *str++ - '0';

        if(n > UINT_MAX - r)
            return MTAR_EOVERFLOW;
        else
            n += r;
    }

    *ret = n;
    return MTAR_ESUCCESS;
}

static int print_octal(char* str, size_t len, unsigned value)
{
    /* move backwards over the output string */
    char* ptr = str + len - 1;
    *ptr = 0;

    /* output the significant digits */
    while(value > 0) {
        if(ptr == str)
            return MTAR_EOVERFLOW;

        --ptr;
        *ptr = '0' + (value % 8);
        value /= 8;
    }

    /* pad the remainder of the field with zeros */
    while(ptr != str) {
        --ptr;
        *ptr = '0';
    }

    return MTAR_ESUCCESS;
}

static unsigned round_up(unsigned n, unsigned incr)
{
    return n + (incr - n % incr) % incr;
}

static int tread(mtar_t* tar, void* data, unsigned size)
{
    int err = tar->ops->read(tar->stream, data, size);
    tar->pos += size;
    return err;
}

static int twrite(mtar_t* tar, const void* data, unsigned size)
{
    int err = tar->ops->write(tar->stream, data, size);
    tar->pos += size;
    return err;
}

static int write_null_bytes(mtar_t* tar, size_t count)
{
    int err;
    size_t n;

    memset(tar->buffer, 0, sizeof(tar->buffer));
    while(count > 0) {
        n = count < sizeof(tar->buffer) ? count : sizeof(tar->buffer);
        err = twrite(tar, tar->buffer, n);
        if(err)
            return err;
    }

    return MTAR_ESUCCESS;
}

enum {
    NAME_OFF     = 0,                           NAME_LEN = 100,
    MODE_OFF     = NAME_OFF+NAME_LEN,           MODE_LEN = 8,
    OWNER_OFF    = MODE_OFF+MODE_LEN,           OWNER_LEN = 8,
    GROUP_OFF    = OWNER_OFF+OWNER_LEN,         GROUP_LEN = 8,
    SIZE_OFF     = GROUP_OFF+GROUP_LEN,         SIZE_LEN = 12,
    MTIME_OFF    = SIZE_OFF+SIZE_LEN,           MTIME_LEN = 12,
    CHKSUM_OFF   = MTIME_OFF+MTIME_LEN,         CHKSUM_LEN = 8,
    TYPE_OFF     = CHKSUM_OFF+CHKSUM_LEN,
    LINKNAME_OFF = TYPE_OFF+1,                  LINKNAME_LEN = 100,

    HEADER_LEN   = 512,
};

static unsigned checksum(const char* raw)
{
    unsigned i;
    unsigned char* p = (unsigned char*)raw;
    unsigned res = 256;

    for(i = 0; i < CHKSUM_OFF; i++)
        res += p[i];
    for(i = TYPE_OFF; i < HEADER_LEN; i++)
        res += p[i];

    return res;
}

static int raw_to_header(mtar_header_t* h, const char* raw)
{
    unsigned chksum;
    int rc;

    /* If the checksum starts with a null byte we assume the record is NULL */
    if(raw[CHKSUM_OFF] == '\0')
        return MTAR_ENULLRECORD;

    /* Compare the checksum */
    if((rc = parse_octal(&raw[CHKSUM_OFF], CHKSUM_LEN, &chksum)))
       return rc;
    if(chksum != checksum(raw))
        return MTAR_EBADCHKSUM;

    /* Load raw header into header */
    if((rc = parse_octal(&raw[MODE_OFF], MODE_LEN, &h->mode)))
        return rc;
    if((rc = parse_octal(&raw[OWNER_OFF], OWNER_LEN, &h->owner)))
        return rc;
    if((rc = parse_octal(&raw[GROUP_OFF], GROUP_LEN, &h->group)))
        return rc;
    if((rc = parse_octal(&raw[SIZE_OFF], SIZE_LEN, &h->size)))
        return rc;
    if((rc = parse_octal(&raw[MTIME_OFF], MTIME_LEN, &h->mtime)))
        return rc;

    h->type = raw[TYPE_OFF];

    memcpy(h->name, &raw[NAME_OFF], NAME_LEN);
    h->name[sizeof(h->name) - 1] = 0;

    memcpy(h->linkname, &raw[LINKNAME_OFF], LINKNAME_LEN);
    h->linkname[sizeof(h->linkname) - 1] = 0;

    return MTAR_ESUCCESS;
}

static int header_to_raw(char* raw, const mtar_header_t* h)
{
    unsigned chksum;
    int rc;

    memset(raw, 0, HEADER_LEN);

    /* Load header into raw header */
    if((rc = print_octal(&raw[MODE_OFF], MODE_LEN, h->mode)))
        return rc;
    if((rc = print_octal(&raw[OWNER_OFF], OWNER_LEN, h->owner)))
        return rc;
    if((rc = print_octal(&raw[GROUP_OFF], GROUP_LEN, h->group)))
        return rc;
    if((rc = print_octal(&raw[SIZE_OFF], SIZE_LEN, h->size)))
        return rc;
    if((rc = print_octal(&raw[MTIME_OFF], MTIME_LEN, h->mtime)))
        return rc;

    raw[TYPE_OFF] = h->type ? h->type : MTAR_TREG;
    strncpy(&raw[NAME_OFF], h->name, NAME_LEN);
    strncpy(&raw[LINKNAME_OFF], h->linkname, NAME_LEN);

    /* Calculate and write checksum */
    chksum = checksum(raw);
    if((rc = print_octal(&raw[CHKSUM_OFF], CHKSUM_LEN-1, chksum)))
        return rc;

    raw[CHKSUM_OFF + CHKSUM_LEN - 1] = ' ';

    return MTAR_ESUCCESS;
}

const char* mtar_strerror(int err)
{
    switch(err) {
    case MTAR_ESUCCESS:     return "success";
    case MTAR_EFAILURE:     return "failure";
    case MTAR_EOPENFAIL:    return "could not open";
    case MTAR_EREADFAIL:    return "could not read";
    case MTAR_EWRITEFAIL:   return "could not write";
    case MTAR_ESEEKFAIL:    return "could not seek";
    case MTAR_EBADCHKSUM:   return "bad checksum";
    case MTAR_ENULLRECORD:  return "null record";
    case MTAR_ENOTFOUND:    return "file not found";
    case MTAR_EOVERFLOW:    return "overflow";
    default:                return "unknown error";
    }
}

int mtar_init(mtar_t* tar, const mtar_ops_t* ops, void* stream)
{
    memset(tar, 0, sizeof(mtar_t));
    tar->ops = ops;
    tar->stream = stream;
    return 0;
}

int mtar_close(mtar_t* tar)
{
    int err = tar->ops->close(tar->stream);
    tar->ops = NULL;
    tar->stream = NULL;
    return err;
}

int mtar_seek(mtar_t* tar, unsigned pos)
{
    int err = tar->ops->seek(tar->stream, pos);
    tar->pos = pos;
    return err;
}

int mtar_is_open(mtar_t* tar)
{
    return (tar->ops != NULL) ? 1 : 0;
}

int mtar_rewind(mtar_t* tar)
{
    tar->remaining_data = 0;
    tar->last_header = 0;
    return mtar_seek(tar, 0);
}

int mtar_next(mtar_t* tar)
{
    int err, n;

    /* Load header */
    err = mtar_read_header(tar, &tar->header);
    if(err)
        return err;

    /* Seek to next record */
    n = round_up(tar->header.size, 512) + HEADER_LEN;
    return mtar_seek(tar, tar->pos + n);
}

int mtar_find(mtar_t* tar, const char* name, mtar_header_t* h)
{
    int err;

    /* Start at beginning */
    err = mtar_rewind(tar);
    if(err)
        return err;

    /* Iterate all files until we hit an error or find the file */
    while((err = mtar_read_header(tar, &tar->header)) == MTAR_ESUCCESS) {
        if(!strcmp(tar->header.name, name)) {
            if(h)
                *h = tar->header;
            return MTAR_ESUCCESS;
        }

        err = mtar_next(tar);
        if(err)
            return err;
    }

    /* Return error */
    if(err == MTAR_ENULLRECORD)
        err = MTAR_ENOTFOUND;

    return err;
}

int mtar_read_header(mtar_t* tar, mtar_header_t* h)
{
    int err;

    /* Save header position */
    tar->last_header = tar->pos;

    /* Read raw header */
    err = tread(tar, tar->buffer, HEADER_LEN);
    if(err)
        return err;

    /* Seek back to start of header */
    err = mtar_seek(tar, tar->last_header);
    if(err)
        return err;

    /* Load raw header into header struct and return */
    return raw_to_header(h, tar->buffer);
}

int mtar_read_data(mtar_t* tar, void* ptr, unsigned size)
{
    int err;

    /* If we have no remaining data then this is the first read,
     * we get the size, set the remaining data and seek to the
     * beginning of the data */
    if(tar->remaining_data == 0) {
        /* Read header */
        err = mtar_read_header(tar, &tar->header);
        if(err)
            return err;

        /* Seek past header and init remaining data */
        err = mtar_seek(tar, tar->pos + HEADER_LEN);
        if(err)
            return err;

        tar->remaining_data = tar->header.size;
    }

    /* Ensure caller does not read too much */
    if(size > tar->remaining_data)
        return MTAR_EOVERFLOW;

    /* Read data */
    err = tread(tar, ptr, size);
    if(err)
        return err;

    tar->remaining_data -= size;

    /* If there is no remaining data we've finished reading and
     * seek back to the header */
    if(tar->remaining_data == 0)
        return mtar_seek(tar, tar->last_header);

    return MTAR_ESUCCESS;
}

int mtar_write_header(mtar_t* tar, const mtar_header_t* h)
{
    /* Build raw header and write */
    header_to_raw(tar->buffer, h);
    tar->remaining_data = h->size;
    return twrite(tar, tar->buffer, HEADER_LEN);
}

int mtar_write_file_header(mtar_t* tar, const char* name, unsigned size)
{
    /* Build header */
    memset(&tar->header, 0, sizeof(tar->header));

    /* Ensure name fits within header */
    if(strlen(name) > sizeof(tar->header.name))
        return MTAR_EOVERFLOW;

    strncpy(tar->header.name, name, sizeof(tar->header.name));
    tar->header.size = size;
    tar->header.type = MTAR_TREG;
    tar->header.mode = 0664;

    /* Write header */
    return mtar_write_header(tar, &tar->header);
}

int mtar_write_dir_header(mtar_t* tar, const char* name)
{
    /* Build header */
    memset(&tar->header, 0, sizeof(tar->header));

    /* Ensure name fits within header */
    if(strlen(name) > sizeof(tar->header.name))
        return MTAR_EOVERFLOW;

    strncpy(tar->header.name, name, sizeof(tar->header.name));
    tar->header.type = MTAR_TDIR;
    tar->header.mode = 0775;

    /* Write header */
    return mtar_write_header(tar, &tar->header);
}

int mtar_write_data(mtar_t* tar, const void* data, unsigned size)
{
    int err;

    /* Ensure we are writing the correct amount of data */
    if(size > tar->remaining_data)
        return MTAR_EOVERFLOW;

    /* Write data */
    err = twrite(tar, data, size);
    if(err)
        return err;

    tar->remaining_data -= size;

    /* Write padding if we've written all the data for this file */
    if(tar->remaining_data == 0)
        return write_null_bytes(tar, round_up(tar->pos, 512) - tar->pos);

    return MTAR_ESUCCESS;
}

int mtar_finalize(mtar_t* tar)
{
    /* Write two NULL records */
    return write_null_bytes(tar, HEADER_LEN * 2);
}
