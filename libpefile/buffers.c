// Copyright (c) 2006-2008 Nick Harbour, All Rights Reserved.
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <assert.h>
#include "util.h"
#include "buffers.h"

void bufferlist_add(buflist_t **buflist_ptr, char *buf, size_t size)
{
	nASSERT('BU00', buflist_ptr != NULL);

	if (*buflist_ptr != NULL) {
		buflist_t *ptr;
		for (ptr = *buflist_ptr; ptr->next != NULL; ptr = ptr->next)
			;
		buflist_ptr = &ptr->next;
	}
	
	*buflist_ptr = (buflist_t *)ecalloc(sizeof (buflist_t), 1);
	(*buflist_ptr)->next = NULL;
	(*buflist_ptr)->buffer.buf = buf;
	(*buflist_ptr)->buffer.size = size;
}

void bufferlist_add_buffer(buflist_t **buflist_ptr, buffer_t *buffer)
{
	nASSERT('BU10', buflist_ptr != NULL);
	nASSERT('BU11', buffer != NULL);

	bufferlist_add(buflist_ptr, buffer->buf, buffer->size);
}

char *bufferlist_add_new(buflist_t **buflist_ptr, size_t size)
{
	char *buf;

	nASSERT('BU20', buflist_ptr != NULL);
	nASSERT('BU21', size > 0);

	buf = ecalloc(size, 1);
	bufferlist_add(buflist_ptr, buf, size);

	return buf;
}

// this frees only the bufflist structures, not the buffers themselves.
void free_bufferlist(buflist_t **buflist_ptr)
{
	buflist_t *ptr, *ptr_next;

	for (ptr = *buflist_ptr; ptr != NULL; ptr = ptr_next) {
		ptr_next = ptr->next;
		efree(ptr);
	}
	*buflist_ptr = NULL;
}

// take a bufferlist and return a new single buffer containing all the data
buffer_t *bufferlist_to_buffer(buflist_t *buflist)
{
	size_t total_size = 0;
	size_t amount_copied = 0;
	buflist_t *blptr;
	buffer_t *retval;

	retval = (buffer_t *)ecalloc(sizeof *retval, 1);
	
	for (blptr = buflist; blptr; blptr = blptr->next)
		total_size += blptr->buffer.size;

	retval->buf = (char *)emalloc(total_size);
	retval->size = total_size;

	for (blptr = buflist; blptr; blptr = blptr->next) {
		if (blptr->buffer.size > 0) {
			if (blptr->buffer.buf != NULL) {
				memcpy(&retval->buf[amount_copied], blptr->buffer.buf, blptr->buffer.size);
			} else {
				char *padding_buf = (char *)ecalloc(blptr->buffer.size, 1);
				memcpy(&retval->buf[amount_copied], padding_buf, blptr->buffer.size);
			}
			amount_copied += blptr->buffer.size;
		}
	}

	return retval;
}

buffer_t *combine_buffers(buffer_t *a, buffer_t *b)
{
	buffer_t *retval = (buffer_t *)emalloc(sizeof (buffer_t));

	retval->size = a->size + b->size;
	retval->buf = (char *)emalloc(retval->size);
	memcpy(retval->buf, a->buf, a->size);
	memcpy(&retval->buf[a->size], b->buf, b->size);

	return retval;
}

void free_buffer(buffer_t **pbuf)
{
	if ((*pbuf)->buf != NULL)
		efree((*pbuf)->buf);
	efree(*pbuf);
	*pbuf = NULL;
}

void write_buffer_to_file(buffer_t *buffer, const char *fname)
{
	FILE *newfile;
	
	newfile = efopen(fname, "wb");

	fwrite(buffer->buf, buffer->size, 1, newfile);
}

buffer_t *read_file_to_buffer(const char *fname)
{
	off_t size;
	FILE *hostfile;
	struct stat statbuf;
	buffer_t *buffer;

	buffer = (buffer_t *)ecalloc(sizeof *buffer, 1);

	estat(fname, &statbuf);
	
	if (statbuf.st_size == 0) {
		die("Error: File cannot be empty\n");
	}

	size = statbuf.st_size;
	buffer->buf = (char *)emalloc(size);

	hostfile = efopen(fname, "rb");
	
	efread(buffer->buf, 1, size, hostfile);

	buffer->size = size;

	fclose(hostfile);

	return buffer;
}

void write_buflist_to_file(buflist_t *bufferlist, const char *fname)
{
	FILE *newfile;
	buflist_t *blist_ptr;
	void *foo;

	newfile = efopen(fname, "wb");

	for (blist_ptr = bufferlist; blist_ptr != NULL; blist_ptr = blist_ptr->next) {
		if (blist_ptr->buffer.buf != NULL)
			fwrite(blist_ptr->buffer.buf, blist_ptr->buffer.size, 1, newfile);
		else if (blist_ptr->buffer.size > 0) {
			char *padding_buf = (char *)calloc(blist_ptr->buffer.size, 1);
			fwrite(padding_buf, blist_ptr->buffer.size, 1, newfile);
			efree(padding_buf);
		}
	}
	
	fclose(newfile);
}

buffer_t *memory_to_buffer(void *mem, size_t size)
{
	buffer_t *buffer;

	buffer = (buffer_t *)ecalloc(sizeof *buffer, 1);

	buffer->buf = mem;
	buffer->size = size;

	return buffer;
}

buffer_t *new_buffer(size_t size)
{
	buffer_t *buffer;

	buffer = (buffer_t *)ecalloc(sizeof *buffer, 1);

	if (size > 0)
		buffer->buf = ecalloc(size, 1);
	buffer->size = size;

	return buffer;
}

buffer_t *new_placeholder_buffer(size_t size)
{
	buffer_t *buffer;

	buffer = (buffer_t *)ecalloc(sizeof *buffer, 1);

	buffer->size = size;

	return buffer;
}

buffer_t *duplicate_buffer(buffer_t *buf)
{
	buffer_t *newbuf;

	nASSERT('BU40', buf != NULL);

	newbuf = emalloc(sizeof *newbuf);
	newbuf->size = buf->size;
	if (newbuf->size > 0 && newbuf->buf != NULL) {
		newbuf->buf = emalloc(newbuf->size);
		memcpy(newbuf->buf, buf->buf, newbuf->size);
	}

	return newbuf;
}
