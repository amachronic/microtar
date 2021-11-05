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
#include <limits.h>
#include <string.h>

enum {
    S_HEADER_VALID   = 1 << 0,
    S_WROTE_HEADER   = 1 << 1,
    S_WROTE_DATA     = 1 << 2,
    S_WROTE_DATA_EOF = 1 << 3,
    S_WROTE_FINALIZE = 1 << 4,
};

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

static unsigned round_up_512(unsigned n)
{
    return (n + 511u) & ~511u;
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

static int tseek(mtar_t* tar, unsigned pos)
{
    int err = tar->ops->seek(tar->stream, pos);
    tar->pos = pos;
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
    if(!h->type)
        h->type = MTAR_TREG;

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

static int ensure_header(mtar_t* tar)
{
    int err;

    if(tar->state & S_HEADER_VALID)
        return MTAR_ESUCCESS;

    tar->header_pos = tar->pos;
    err = tread(tar, tar->buffer, HEADER_LEN);
    if(err)
        return err;

    err = raw_to_header(&tar->header, tar->buffer);
    if(err)
        return err;

    tar->state |= S_HEADER_VALID;
    return MTAR_ESUCCESS;
}

static int ensure_eof(mtar_t* tar)
{
    if(!(tar->state & S_WROTE_DATA) || (tar->state & S_WROTE_DATA_EOF))
        return MTAR_ESUCCESS;

    int err = write_null_bytes(tar, round_up_512(tar->pos) - tar->pos);
    if(err)
        return err;

    tar->state |= S_WROTE_DATA_EOF;
    return MTAR_ESUCCESS;
}

static unsigned data_beg_pos(const mtar_t* tar)
{
    return tar->header_pos + HEADER_LEN;
}

static unsigned data_end_pos(const mtar_t* tar)
{
    return data_beg_pos(tar) + tar->header.size;
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
    case MTAR_ESEEKRANGE:   return "seek out of bounds";
    case MTAR_EBADCHKSUM:   return "bad checksum";
    case MTAR_ENULLRECORD:  return "null record";
    case MTAR_ENOTFOUND:    return "file not found";
    case MTAR_EOVERFLOW:    return "overflow";
    case MTAR_EAPI:         return "API usage error";
    case MTAR_ENAMETOOLONG: return "name too long";
    default:                return "unknown error";
    }
}

int mtar_init(mtar_t* tar, int access, const mtar_ops_t* ops, void* stream)
{
    memset(tar, 0, sizeof(mtar_t));
    tar->access = access;
    tar->ops = ops;
    tar->stream = stream;
    return 0;
}

int mtar_close(mtar_t* tar)
{
    int err1 = tar->access == MTAR_WRITE ? mtar_finalize(tar) : MTAR_ESUCCESS;
    int err2 = tar->ops->close(tar->stream);

    tar->ops = NULL;
    tar->stream = NULL;

    if(err1)
        return err1;
    else
        return err2;
}

int mtar_is_open(mtar_t* tar)
{
    return (tar->ops != NULL) ? 1 : 0;
}

const mtar_header_t* mtar_get_header(const mtar_t* tar)
{
    if(tar->state & S_HEADER_VALID)
        return &tar->header;
    else
        return NULL;
}

int mtar_access_mode(const mtar_t* tar)
{
    return tar->access;
}

int mtar_rewind(mtar_t* tar)
{
    if(tar->access != MTAR_READ)
        return MTAR_EAPI;

    int err = tseek(tar, 0);
    tar->state = 0;
    return err;
}

int mtar_next(mtar_t* tar)
{
    if(tar->access != MTAR_READ)
        return MTAR_EAPI;

    if(tar->state & S_HEADER_VALID) {
        tar->state &= ~S_HEADER_VALID;

        /* seek to the next header */
        int err = tseek(tar, round_up_512(data_end_pos(tar)));
        if(err)
            return err;
    }

    return ensure_header(tar);
}

int mtar_foreach(mtar_t* tar, mtar_foreach_cb cb, void* arg)
{
    if(tar->access != MTAR_READ)
        return MTAR_EAPI;

    int err = mtar_rewind(tar);
    if(err)
        return err;

    while((err = mtar_next(tar)) == MTAR_ESUCCESS)
        if((err = cb(tar, &tar->header, arg)) != 0)
            return err;

    if(err == MTAR_ENULLRECORD)
        err = MTAR_ESUCCESS;

    return err;
}

static int find_foreach_cb(mtar_t* tar, const mtar_header_t* h, void* arg)
{
    (void)tar;
    const char* name = (const char*)arg;
    return strcmp(name, h->name) ? 0 : 1;
}

int mtar_find(mtar_t* tar, const char* name)
{
    int err = mtar_foreach(tar, find_foreach_cb, (void*)name);
    if(err == 1)
        err = MTAR_ESUCCESS;
    else if(err == MTAR_ESUCCESS)
        err = MTAR_ENOTFOUND;

    return err;
}

int mtar_read_data(mtar_t* tar, void* ptr, unsigned size)
{
    if(tar->access != MTAR_READ)
        return MTAR_EAPI;
    if(!(tar->state & S_HEADER_VALID))
        return MTAR_EAPI;

    /* have we reached end of file? */
    unsigned data_end = data_end_pos(tar);
    if(tar->pos >= data_end)
        return 0;

    /* truncate the read if it would go beyond EOF */
    unsigned data_left = data_end - tar->pos;
    if(data_left < size)
        size = data_left;

    int err = tread(tar, ptr, size);
    if(err)
        return err;

    return (int)size;
}

int mtar_seek_data(mtar_t* tar, int offset, int whence)
{
    if(tar->access != MTAR_READ)
        return MTAR_EAPI;
    if(!(tar->state & S_HEADER_VALID))
        return MTAR_EAPI;

    unsigned data_beg = data_beg_pos(tar);
    unsigned data_end = data_end_pos(tar);
    unsigned newpos;

    switch(whence) {
    case SEEK_SET:
        if(offset < 0)
            return MTAR_ESEEKRANGE;

        newpos = data_beg + offset;
        break;

    case SEEK_CUR:
        if((offset > 0 && (unsigned) offset > data_end - tar->pos) ||
           (offset < 0 && (unsigned)-offset > tar->pos - data_beg))
            return MTAR_ESEEKRANGE;

        newpos = tar->pos + offset;
        break;

    case SEEK_END:
        if(offset > 0)
            return MTAR_ESEEKRANGE;

        newpos = data_end + offset;
        break;

    default:
        return MTAR_EAPI;
    }

    return tseek(tar, newpos);
}

int mtar_eof_data(mtar_t* tar)
{
    /* API usage errors, but just claim EOF. */
    if(tar->access != MTAR_READ)
        return 1;
    if(!(tar->state & S_HEADER_VALID))
        return 1;

    return tar->pos >= data_end_pos(tar) ? 1 : 0;
}

int mtar_write_header(mtar_t* tar, const mtar_header_t* h)
{
    if(tar->access != MTAR_WRITE)
        return MTAR_EAPI;
    if(tar->state & S_WROTE_FINALIZE)
        return MTAR_EAPI;

    int err = ensure_eof(tar);
    if(err)
        return err;

    tar->state &= ~(S_WROTE_HEADER | S_WROTE_DATA | S_WROTE_DATA_EOF);
    if(h != &tar->header)
        tar->header = *h;

    err = header_to_raw(tar->buffer, h);
    if(err)
        return err;

    err = twrite(tar, tar->buffer, HEADER_LEN);
    if(err)
        return err;

    tar->state |= S_WROTE_HEADER;
    return MTAR_ESUCCESS;
}

int mtar_write_file_header(mtar_t* tar, const char* name, unsigned size)
{
    size_t namelen = strlen(name);
    if(namelen > NAME_LEN)
        return MTAR_ENAMETOOLONG;

    tar->header.mode = 0644;
    tar->header.owner = 0;
    tar->header.group = 0;
    tar->header.size = size;
    tar->header.mtime = 0;
    tar->header.type = MTAR_TREG;
    memcpy(tar->header.name, name, namelen + 1);
    tar->header.linkname[0] = '\0';

    return mtar_write_header(tar, &tar->header);
}

int mtar_write_dir_header(mtar_t* tar, const char* name)
{
    size_t namelen = strlen(name);
    if(namelen > NAME_LEN)
        return MTAR_ENAMETOOLONG;

    tar->header.mode = 0755;
    tar->header.owner = 0;
    tar->header.group = 0;
    tar->header.size = 0;
    tar->header.mtime = 0;
    tar->header.type = MTAR_TDIR;
    memcpy(tar->header.name, name, namelen + 1);
    tar->header.linkname[0] = '\0';

    return mtar_write_header(tar, &tar->header);
}

int mtar_write_data(mtar_t* tar, const void* ptr, unsigned size)
{
    if(!(tar->state & S_WROTE_HEADER) || (tar->state & S_WROTE_FINALIZE))
        return MTAR_EAPI;

    /* don't allow writing more than was specified in the header,
     * as this would require seeking back & updating it */
    unsigned data_end = data_end_pos(tar);
    if(tar->pos >= data_end)
        return 0;

    unsigned data_left = tar->pos - data_end;
    if(size > data_left)
        size = data_left;

    if(size > 0)
        tar->state |= S_WROTE_DATA;
    int err = twrite(tar, ptr, size);
    if(err)
        return err;

    return (int)size;
}

int mtar_finalize(mtar_t* tar)
{
    if(tar->access != MTAR_WRITE)
        return MTAR_EAPI;
    if(tar->state & S_WROTE_FINALIZE)
        return MTAR_ESUCCESS;

    int err = ensure_eof(tar);
    if(err)
        return err;

    tar->state |= S_WROTE_FINALIZE;
    return write_null_bytes(tar, 1024);
}
