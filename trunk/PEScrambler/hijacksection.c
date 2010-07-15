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

#include "hijacksection.h"
#include "pefile.h"
#include "util.h"
#include "assert.h"
#include <windows.h>
#include <crtdbg.h>

hijacksection_t *new_hijacksection(pefile_t *pefile)
{
	hijacksection_t *new_sec;

	assert(pefile != NULL);

	new_sec = ecalloc(1, sizeof *new_sec);

	new_sec->VirtualAddress = pefile->image_nt_headers.OptionalHeader.ImageBase;
	new_sec->VirtualAddress += pefile->image_nt_headers.OptionalHeader.SizeOfImage;

	return new_sec;
}

char *hijack_reserve(hijacksection_t *hsec, DWORD cbAmount, DWORD *lpdwVirtualAddress)
{
	char *retval;
	assert(hsec != NULL);
	assert(cbAmount > 0);

	retval = bufferlist_add_new(&hsec->buflist, cbAmount);

	if (lpdwVirtualAddress != NULL)
		*lpdwVirtualAddress = hsec->VirtualAddress + hsec->VirtualSize;

	hsec->VirtualSize += cbAmount;

	return retval;
}

void commit_hijacksection(hijacksection_t *hsec, pefile_t *pefile)
{
	buffer_t *section_buf;

	assert(hsec != NULL);
	assert(pefile != NULL);

	section_buf = bufferlist_to_buffer(hsec->buflist);
	if (section_buf == NULL)
		return;

	add_section_to_pefile(pefile, ".wtf", section_buf, 0xE0000020);
}

char *hijacksection_va_to_ptr(hijacksection_t *hsec, DWORD dwVirtualAddress)
{
	_ASSERT(hsec != NULL);

	if (dwVirtualAddress >= hsec->VirtualAddress
		&& dwVirtualAddress < hsec->VirtualAddress + hsec->VirtualSize)
	{
		DWORD offset = dwVirtualAddress - hsec->VirtualAddress;
		DWORD runningTotal = 0;
		buflist_t *blptr;

		for (blptr = hsec->buflist; blptr != NULL; blptr = blptr->next) {
			if (offset < runningTotal + blptr->buffer.size) {
				return &blptr->buffer.buf[offset - runningTotal];
			} else if (offset < runningTotal) {
				return NULL;
			} else {
				runningTotal += blptr->buffer.size;
			}			
		}
	}

	return NULL;
}