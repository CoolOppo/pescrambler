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

#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <sys/stat.h>
#include <crtdbg.h>

extern void die(const char *fmt, ...);
extern void *ecalloc(size_t num_elements, size_t element_size);
extern void *emalloc(size_t size);
extern void efree(void *buf);
extern FILE *efopen(const char *fname, const char *mode);
extern size_t efread(void *buf, size_t element_size, size_t count, FILE *stream);
extern void estat(const char *fname, struct stat *statbuf);
extern int assert_failed(int line);

#ifdef NDEBUG
#define nASSERT(tag, _Expression) (void)((!!(_Expression)) || assert_failed((tag)))
#else
#define nASSERT(tag, _Expression) _ASSERT(_Expression)
#endif /* NDEBUG */

#endif /* UTIL_H */
