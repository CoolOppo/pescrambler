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

#include "reloc.h"
#include "disasm.h"
#include "libdis.h"
#include "util.h"
#include "pefile.h"
#include <windows.h>
#include <assert.h>

extern void armoring_swirly(void);

static void finalize_current_seq(reloc_seq_t **sequences, reloc_insn_list_t **current_seq)
{
	reloc_seq_t *new_seq;

	assert(sequences != NULL);
	assert(current_seq != NULL);
	assert(*current_seq != NULL);

    //printf("RELOC SEQUENCE: %08X\n", (*current_seq)->insn->MemoryAddress);

	new_seq = ecalloc(1, sizeof *new_seq);
	new_seq->instructions = *current_seq;
	new_seq->start = (*current_seq)->insn->MemoryAddress;
	
	while (*current_seq != NULL) {
		new_seq->length += (*current_seq)->insn->InstructionSize;
		*current_seq = (*current_seq)->next;
	}
	
	new_seq->next = *sequences;
	*sequences = new_seq;
}

static BOOL insn_follows_sequence(disassembly_t *insn, reloc_insn_list_t *seq)
{
	while (seq != NULL) {
		if (seq->next == NULL && 
			insn->MemoryAddress == seq->insn->MemoryAddress + seq->insn->InstructionSize)
		{
			return TRUE;
		}
		seq = seq->next;
	}
	return FALSE;
}

static void insn_sequence_append(reloc_insn_list_t **seq, disassembly_t *insn)
{
	reloc_insn_list_t *new_node;
	reloc_insn_list_t *list_ptr;

	assert(seq != NULL);
	assert(insn != NULL);

	new_node = ecalloc(1, sizeof *new_node);
	new_node->insn = insn;

	if (*seq == NULL) {
		*seq = new_node;
		return;
	} else {
		for (list_ptr = *seq; list_ptr->next != NULL; list_ptr = list_ptr->next)
			;

		list_ptr->next = new_node;
	}
}

static BOOL insn_is_relocatable_easy(disassembly_t *insn)
{
	assert(insn != NULL);

	if (insn->xrefs_to == NULL && insn->xrefs_from == NULL && !insn->IsNotRelocatable)
		return TRUE;
	else
		return FALSE;
}

reloc_seq_t *find_relocatable_sequences(disassembly_t *da)
{
	reloc_seq_t *sequences = NULL;
	reloc_insn_list_t *current_seq = NULL;

	while (da != NULL) {
		armoring_swirly();
		if (insn_is_relocatable_easy(da)
			&& (insn_follows_sequence(da, current_seq) 
			    || current_seq == NULL)) 
		{
			insn_sequence_append(&current_seq, da);
            if (da->Instruction.type == insn_return)
            {
                finalize_current_seq(&sequences, &current_seq);
            }
		} else {
			if (current_seq != NULL) {
				finalize_current_seq(&sequences, &current_seq);
			}
		}
		da = da->next;
	}

	return sequences;
}

BOOL split_reloc_sequence(reloc_seq_t *seq, DWORD cbLength)
{
	reloc_insn_list_t *ilistptr;
	DWORD runningTotal = 0;

	assert(seq != NULL);

	if (cbLength >= seq->length || cbLength <= 0)
		return FALSE;

	if (seq->instructions->insn->InstructionSize > cbLength)
		return FALSE;

	for (ilistptr = seq->instructions; ilistptr->next != NULL; ilistptr = ilistptr->next) {
		runningTotal += ilistptr->insn->InstructionSize;
		if (runningTotal < cbLength
			&& runningTotal + ilistptr->next->insn->InstructionSize >= cbLength)
		{
			reloc_seq_t *new_seq;

			new_seq = ecalloc(1, sizeof *new_seq);
			new_seq->instructions = ilistptr->next;
			new_seq->length = seq->length - runningTotal;
			new_seq->start = ilistptr->next->insn->MemoryAddress;
			new_seq->next = seq->next;
			seq->next = new_seq;

			seq->length -= new_seq->length;
			ilistptr->next = NULL;

			return TRUE;
		}
	}

	return FALSE;
}

void debug_print_insn_list(reloc_insn_list_t *instructions)
{
	while (instructions != NULL) {
		printf("   ");
		debug_print_instruction(instructions->insn);
		instructions = instructions->next;
	}
}

void debug_print_relocatable_sequences(reloc_seq_t *sequences)
{
	while (sequences != NULL) {
		printf("0x%08X - 0x%08X (%d bytes):\n", 
			sequences->start, 
			sequences->start + sequences->length,
			sequences->length);
		debug_print_insn_list(sequences->instructions);
		sequences = sequences->next;
	}
	printf("\n");
}
