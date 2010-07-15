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

#ifndef HIJACKSECTION_H
#define HIJACKSECTION_H

#ifdef __cplusplus
extern "C" {
#endif

#include "pefile.h"
#include <windows.h>
#include "buffers.h"

typedef struct hijacksection {
	DWORD VirtualAddress;
	DWORD VirtualSize;
	buflist_t *buflist;
} hijacksection_t;

hijacksection_t *new_hijacksection(pefile_t *pefile);
char *hijack_reserve(hijacksection_t *hsec, DWORD cbAmount, DWORD *lpdwVirtualAddress);
char *hijacksection_va_to_ptr(hijacksection_t *hsec, DWORD dwVirtualAddress);
void commit_hijacksection(hijacksection_t *hsec, pefile_t *pefile);

#ifdef __cplusplus
}
#endif

#endif /* !HIJACKSECTION_H */