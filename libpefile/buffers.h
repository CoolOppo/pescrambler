/* Copyright (C) 2007-2008 Nick Harbour	   

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
	
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifndef BUFFERS_H
#define BUFFERS_H

#include <sys/types.h>

typedef struct buffer {
	char *buf;
	size_t size;
} buffer_t;

typedef struct buflist {
	struct buflist *next;
	buffer_t buffer;
} buflist_t;

extern void bufferlist_add(buflist_t **buflist_ptr, char *buf, size_t size);
extern void bufferlist_add_buffer(buflist_t **buflist_pr, buffer_t *buffer);
extern char *bufferlist_add_new(buflist_t **buflist_ptr, size_t size);
extern void free_bufferlist(buflist_t **buflist_ptr);
extern buffer_t *bufferlist_to_buffer(buflist_t *buflist);
extern buffer_t *combine_buffers(buffer_t *a, buffer_t *b);
extern void free_buffer(buffer_t **pbuf);
extern void write_buffer_to_file(buffer_t *buffer, const char *fname);
extern buffer_t *read_file_to_buffer(const char *fname);
extern void write_buflist_to_file(buflist_t *bufferlist, const char *fname);
extern buffer_t *memory_to_buffer(void *mem, size_t size);
extern buffer_t *new_buffer(size_t size);
extern buffer_t *new_placeholder_buffer(size_t size);
extern buffer_t *duplicate_buffer(buffer_t *buf);

#endif /* BUFFERS_H */
