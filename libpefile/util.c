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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include "util.h"

void die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
    exit(-1);
}

void *ecalloc(size_t num_elements, size_t element_size)
{
	void *retval;

	retval = calloc(num_elements, element_size);
	if (retval == NULL)
		die("Unable to allocate %d bytes of memory", num_elements * element_size);

	return retval;
}

void *emalloc(size_t size)
{
	void *retval;

	retval = malloc(size);
	if (retval == NULL)
		die("Unable to allocate %d bytes of memory", size);

	return retval;
}

void efree(void *buf)
{
	nASSERT('UT00', buf != NULL);

	free(buf);
}

FILE *efopen(const char *fname, const char *mode)
{
	FILE *retval;

	nASSERT('UT10', fname != NULL);
	nASSERT('UT11', mode != NULL);

	retval = fopen(fname, mode);
	if (retval == NULL)
		die("Error opening \"%s\": %s", fname, strerror(errno));
	return retval;
}

size_t efread(void *buf, size_t element_size, size_t count, FILE *stream)
{
	size_t retval;

	nASSERT('UT20', buf != NULL);
	nASSERT('UT21', stream != NULL);

	retval = fread(buf, element_size, count, stream);
	if (retval != count)
		die("Error reading from file: %s", strerror(errno));
	return retval;
}

void estat(const char *fname, struct stat *statbuf)
{
	nASSERT('UT30', fname != NULL);
	nASSERT('UT31', statbuf != NULL);

	if (stat(fname, statbuf) != 0)
		die("Error getting information for file \"%s\": %s", fname, strerror(errno));
}

int assert_failed(int code)
{
	die("Internal Error 0x%08X, aborting.", code);
	return -1;  // never reached
}
