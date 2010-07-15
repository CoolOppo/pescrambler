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

#include <assert.h>
#include <windows.h>
#include "pefile.h"
#include "util.h"
#include "libdis.h"
#include "disasm.h"
#include "disasm_queue.h"

void debug_print_disasm_queue(struct disassembly_queue *disassembly_queue)
{
	struct disassembly_queue *qptr;

	for (qptr = disassembly_queue; qptr != NULL; qptr = qptr->next) {
		printf("%08X ", qptr->MemoryAddress);
	}

	printf("\n\n");
}

void disasm_queue_push(struct disassembly_queue **disassembly_queue, DWORD MemoryAddress)
{
	struct disassembly_queue *node;
	
	assert(disassembly_queue != NULL);

	node = emalloc(sizeof *node);

	node->MemoryAddress = MemoryAddress;

	if (*disassembly_queue == NULL) {
		*disassembly_queue = node;
		node->next = NULL;
	} else {
		node->next = *disassembly_queue;
		*disassembly_queue = node;
	}
}

void disasm_queue_append(struct disassembly_queue **disassembly_queue, DWORD MemoryAddress)
{
	struct disassembly_queue *node;

	assert(disassembly_queue != NULL);

	node = emalloc(sizeof *node);

	node->MemoryAddress = MemoryAddress;

	if (*disassembly_queue == NULL) {
		*disassembly_queue = node;
		node->next = NULL;
	} else {
		struct disassembly_queue *list_ptr;

		for (list_ptr = *disassembly_queue; list_ptr->next != NULL; list_ptr = list_ptr->next)
			;
		
		list_ptr->next = node;
		node->next = NULL;
	}
}

DWORD disasm_queue_pop(struct disassembly_queue **disassembly_queue)
{
	struct disassembly_queue *node;
	DWORD retval;
	assert(disassembly_queue != NULL);

	if (*disassembly_queue == NULL)
		return -1;

	node = *disassembly_queue;
	retval = node->MemoryAddress;
	*disassembly_queue = node->next;
	free(node);
	return retval;
}