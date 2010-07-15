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

#ifndef CALLDISPATCH_H
#define CALLDISPATCH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <assert.h>
#include <windows.h>
#include "buffers.h"
#include "pefile.h"
#include "getopt.h"
#include "util.h"
#include "libdis.h"
#include "disasm.h"

struct call_list {
    struct call_list *next;
    disassembly_t *da;
};

struct call_table {
    DWORD ReturnPointer;
    DWORD Target;
};

void call_remap_pefile(pefile_t *pefile, struct call_list *list, DWORD dispatcher_addr, DWORD indirect_ptr);
void call_remap(pefile_t *pefile, disassembly_t *da);
void redispatch(DWORD original_ret_ptr, DWORD new_ret_ptr);

#ifdef __cplusplus
}
#endif

#endif /* !CALLDISPATCH_H */