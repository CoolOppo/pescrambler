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

#ifndef DISASM_H
#define DISASM_H

//#ifdef PEFILE_H
// these wrapper functions are availible to a program only if it chooses to include libpefile

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include "libdis.h"
#include "pefile.h"

typedef struct disassembly {
	struct disassembly *next;
	struct disassembly *prev;
	struct xref *xrefs_from;
	struct xref *xrefs_to;
    DWORD MemoryAddress;
	DWORD FileOffset;
	x86_insn_t Instruction;
	DWORD InstructionSize;
    BOOL IsNotRelocatable;
} disassembly_t;

struct xref {
	struct xref *next;
	disassembly_t *insn;
};

typedef struct disasm_btree {
	struct disasm_btree *less;
	struct disasm_btree *greater;
	DWORD addr;
	disassembly_t *da;
} disasm_btree_t;

#define MAX_AMOUNT_UNLIMITED (0)

disassembly_t *disassemble_pefile(pefile_t *pefile, BOOL bStatusDisplay, BOOL bGenerateXrefs, DWORD MaxAmount);
DWORD call_target(disassembly_t *da);
DWORD get_flowcontrol_target(disassembly_t *da);
disassembly_t *disasm_list_lookup_addr(disassembly_t *disasm_list, DWORD MemoryAddress, disassembly_t *last_lookup);
void debug_print_disassembly(disassembly_t *da);
void debug_print_instruction(disassembly_t *da);

#ifdef __cplusplus
}
#endif

//#endif /*PEFILE_H*/

#endif /*!DISASM_H*/