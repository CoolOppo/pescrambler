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

#ifndef RELOC_H
#define RELOC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "disasm.h"
#include <windows.h>

typedef struct reloc_insn_list_node {
	struct reloc_insn_list_node *next;
	disassembly_t *insn;
} reloc_insn_list_t;

typedef struct reloc_seq {
	struct reloc_seq *next;
	DWORD start;
	DWORD length;
	reloc_insn_list_t *instructions;
	BOOL relocated;
} reloc_seq_t;

reloc_seq_t *find_relocatable_sequences(disassembly_t *da);
BOOL split_reloc_sequence(reloc_seq_t *seq, DWORD cbLength);
void debug_print_insn_list(reloc_insn_list_t *instructions);
void debug_print_relocatable_sequences(reloc_seq_t *sequences);

#ifdef __cplusplus
}
#endif

#endif /* !RELOC_H */