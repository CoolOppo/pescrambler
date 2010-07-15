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

#ifndef DISASM_QUEUE_H
#define DISASM_QUEUE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include "libdis.h"
#include "pefile.h"

struct disassembly_queue {
	struct disassembly_queue *next;
	DWORD MemoryAddress;
};

void disasm_queue_push(struct disassembly_queue **disassembly_queue, DWORD MemoryAddress);
DWORD disasm_queue_pop(struct disassembly_queue **disassembly_queue);
void disasm_queue_append(struct disassembly_queue **disassembly_queue, DWORD MemoryAddress);
void debug_print_disasm_queue(struct disassembly_queue *disassembly_queue);

#ifdef __cplusplus
}
#endif

#endif