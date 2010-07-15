
// These wrapper functions are availible to a program only if they choose to include libpefile

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


static disassembly_t *disasm_list_lookup_addr_nearest(disassembly_t *disasm_list, DWORD MemoryAddress, disassembly_t *last_lookup);
static BOOL add_to_disasm_list(disassembly_t **disasm_list, disassembly_t *da, disassembly_t *last_lookup);
//static BOOL memory_addr_within_section(pefile_t *pefile, DWORD MemoryAddress, int section_number);
static void add_xref_to_list(struct xref **xl, disassembly_t *insn);
static void add_xref(disassembly_t *from, disassembly_t *to);
static void generate_xrefs(disassembly_t *disasm_list, pefile_t *pefile);
static void generate_insn_xrefs(disassembly_t *insn, disassembly_t *disasm_list, pefile_t *pefile);
static void free_xref_list(struct xref *xl);
static BOOL is_table_jump(disassembly_t *insn);
static DWORD *get_jump_table(disassembly_t *insn, pefile_t *pefile, DWORD *dwNumEntries);
static BOOL insn_is_zeros(disassembly_t *insn);
//static DWORD code_ptr_scan(pefile_t *pefile, struct disassembly_queue **disassembly_queue, DWORD MemoryAddress);
//static DWORD code_ptr_scan(pefile_t *pefile, struct disassembly_queue **disassembly_queue);
static DWORD code_ptr_scan(pefile_t *pefile, struct disassembly_queue **disassembly_queue, DWORD *start);
static DWORD remove_sequence(disassembly_t **da, DWORD beginning, DWORD end);
static DWORD remove_suspicious_sequences(disassembly_t **da);
static disassembly_t *disassemble(disassembly_t **disasm_list, 
						struct disassembly_queue **disassembly_queue, 
						pefile_t *pefile, 
						DWORD MemoryAddress,
						disassembly_t *last_lookup,
						DWORD *lpdwRunningTotal);
static void mark_entry_points(pefile_t *pefile, disassembly_t *da);


static DWORD total;
static DWORD aux;
//BOOL hitme;

disassembly_t *disassemble_pefile(pefile_t *pefile, BOOL bStatusDisplay, BOOL bGenerateXrefs, DWORD MaxAmount)
{
	disassembly_t *da_list = NULL;
	disassembly_t *da_ptr;
	struct disassembly_queue *da_queue = NULL;
	DWORD next_instruction;
	static char *swirly = "|/-\\";
	static int swirly_count;
	disassembly_t *last_lookup = NULL;
	DWORD runningTotal = 0;
	DWORD code_ptr_scan_offset = 0;

	assert(pefile);

	if (pefile->exports != NULL)
	{
		int i;
		for (i = 0; i < pefile->exports->image_export_directory.NumberOfFunctions; i++) 
		{
			if (pefile->exports->exports[i].export_address_type == EXPORT_ADDRESS_TYPE_RVA)
			{
				disasm_queue_push(&da_queue, pefile->exports->exports[i].rva.rva + pefile->image_nt_headers.OptionalHeader.ImageBase);
			}
		}
	}

	next_instruction = pefile->image_nt_headers.OptionalHeader.AddressOfEntryPoint + pefile->image_nt_headers.OptionalHeader.ImageBase;

	while (next_instruction != -1 && (MaxAmount == MAX_AMOUNT_UNLIMITED || runningTotal < MaxAmount)) {
		if (bStatusDisplay)
			fprintf(stderr, "\rDisassembling. %c", swirly[swirly_count++ % 4]);
		last_lookup = disassemble(&da_list, &da_queue, pefile, next_instruction, last_lookup, &runningTotal);
		next_instruction = disasm_queue_pop(&da_queue);
	}

	while ((MaxAmount == MAX_AMOUNT_UNLIMITED || runningTotal < MaxAmount) 
		   && -1 != (next_instruction = code_ptr_scan(pefile, &da_queue, &code_ptr_scan_offset))) 
	{
		runningTotal -= remove_suspicious_sequences(&da_list);
		last_lookup = NULL;
		while (next_instruction != -1 && (MaxAmount == MAX_AMOUNT_UNLIMITED || runningTotal < MaxAmount)) {
			if (bStatusDisplay)
				fprintf(stderr, "\rDisassembling. %c", swirly[swirly_count++ % 4]);
			last_lookup = disassemble(&da_list, &da_queue, pefile, next_instruction, last_lookup, &runningTotal);
			next_instruction = disasm_queue_pop(&da_queue);
		}
	}
	
	
	//next_instruction = code_ptr_scan(pefile, &da_queue);
	//
	//while (next_instruction != -1 && (MaxAmount == MAX_AMOUNT_UNLIMITED || runningTotal < MaxAmount)) {
	//	if (bStatusDisplay)
	//		fprintf(stderr, "\rDisassembling. %c b%d", swirly[swirly_count++ % 4], runningTotal);
	//	last_lookup = disassemble(&da_list, &da_queue, pefile, next_instruction, last_lookup, &runningTotal);
	//	next_instruction = disasm_queue_pop(&da_queue);
	//}

	if (MaxAmount == MAX_AMOUNT_UNLIMITED || runningTotal < MaxAmount)
		remove_suspicious_sequences(&da_list);	

	if (bStatusDisplay)
		fprintf(stderr, "\rDisassembling. (done)\n");

	if (bGenerateXrefs) {
		for (da_ptr = da_list; da_ptr != NULL; da_ptr = da_ptr->next) {
			if (bStatusDisplay)
				fprintf(stderr, "\rGenerating Cross-References. %c", swirly[swirly_count++ % 4]);
			generate_insn_xrefs(da_ptr, da_list, pefile);
		}
	
		if (bStatusDisplay)
			fprintf(stderr, "\rGenerating Cross-References. (done)\n");
	}
	//debug_print_disassembly(da_list);
	mark_entry_points(pefile, da_list);

    return da_list;
}



disassembly_t *disasm_list_lookup_addr(disassembly_t *disasm_list, DWORD MemoryAddress, disassembly_t *last_lookup)
{
	disassembly_t *list_ptr;

	if (last_lookup != NULL) {
		if (MemoryAddress >= last_lookup->MemoryAddress) {
			for (list_ptr = last_lookup; list_ptr != NULL; list_ptr = list_ptr->next)
			{
				if (list_ptr->MemoryAddress == MemoryAddress)
					return list_ptr;
			}
		} else {
			for (list_ptr = last_lookup; list_ptr != NULL; list_ptr = list_ptr->prev)
			{
				if (list_ptr->MemoryAddress == MemoryAddress)
					return list_ptr;
			}
		}
	} else {
		for (list_ptr = disasm_list; list_ptr != NULL; list_ptr = list_ptr->next) {
			if (list_ptr->MemoryAddress == MemoryAddress)
				return list_ptr;
		}
	}

	return NULL;
}

static disassembly_t *disasm_list_lookup_addr_nearest(disassembly_t *disasm_list, DWORD MemoryAddress, disassembly_t *last_lookup)
{
	disassembly_t *list_ptr;

	if (disasm_list == NULL)
		return NULL;
 
	if (disasm_list->MemoryAddress >= MemoryAddress)
		return NULL;

	if (last_lookup != NULL) {
		if (MemoryAddress >= last_lookup->MemoryAddress) {
			for (list_ptr = last_lookup; list_ptr != NULL; list_ptr = list_ptr->next)
			{
				if (list_ptr->next == NULL || list_ptr->next->MemoryAddress > MemoryAddress)
					return list_ptr;
			}
		} else {
			for (list_ptr = last_lookup; list_ptr != NULL; list_ptr = list_ptr->prev)
			{
				if (list_ptr->prev == NULL)
					return NULL;
				if (list_ptr->MemoryAddress > MemoryAddress && list_ptr->prev->MemoryAddress < MemoryAddress)
					return list_ptr->prev;
			}
		}
	} else {
		for (list_ptr = disasm_list; list_ptr != NULL; list_ptr = list_ptr->next) {
			if (list_ptr->next == NULL || list_ptr->next->MemoryAddress > MemoryAddress)
				return list_ptr;
		}
	}

	assert(0);
	return NULL;
}

static BOOL add_to_disasm_list(disassembly_t **disasm_list, disassembly_t *da, disassembly_t *last_lookup)
{
	disassembly_t *dalist_ptr;

	assert(disasm_list != NULL);
	assert(da != NULL);

	da->next = NULL;
	da->prev = NULL;

	if (*disasm_list == NULL) {
		*disasm_list = da;
	} else {
		dalist_ptr = disasm_list_lookup_addr_nearest(*disasm_list, da->MemoryAddress, last_lookup);
		if (dalist_ptr == NULL) {
			if (*disasm_list != NULL
				&& da->MemoryAddress + da->InstructionSize > (*disasm_list)->MemoryAddress)
			{
				return FALSE;
			}
			da->next = *disasm_list;
			da->prev = NULL;
			if (*disasm_list != NULL)
				(*disasm_list)->prev = da;
			*disasm_list = da;
		} else {
			if (dalist_ptr->MemoryAddress + dalist_ptr->InstructionSize > da->MemoryAddress
				|| (dalist_ptr->next != NULL && (da->MemoryAddress + da->InstructionSize > dalist_ptr->next->MemoryAddress)))
			{
				return FALSE;
			}
			if (dalist_ptr->next != NULL && dalist_ptr->next->prev != NULL)
				dalist_ptr->next->prev = da;
			da->next = dalist_ptr->next;
			da->prev = dalist_ptr;
			dalist_ptr->next = da;
		}
	}

	return TRUE;
}

// returns an updated value for last_lookup, if valid
static disassembly_t *disassemble(disassembly_t **disasm_list, 
						struct disassembly_queue **disassembly_queue, 
						pefile_t *pefile, 
						DWORD MemoryAddress,
						disassembly_t *last_lookup,
						DWORD *lpdwRunningTotal)
{
	struct disassembly *da;
	DWORD instruction_offset;
	unsigned int insn_buffer_length;
	char *insn_ptr;
	x86_oplist_t *oplist_ptr;
	disassembly_t *last;

	assert(disasm_list != NULL);
	assert(disassembly_queue != NULL);
	assert(pefile != NULL);

	if (*disasm_list != NULL) {
		if ((last = disasm_list_lookup_addr(*disasm_list, MemoryAddress, last_lookup)) != NULL)
			return last;
	}

	da = ecalloc(1, sizeof *da);

	//if (MemoryAddress == 0x729717D4)
	//	__asm int 3;
	//printf("%08X ", MemoryAddress);

	da->MemoryAddress = MemoryAddress;
	da->FileOffset = ql_rva_to_raw(pefile, va_to_rva(pefile, MemoryAddress));
	if (da->FileOffset == -1 || da->FileOffset < pefile->first_section_offset)
	{
		free(da);
		return last_lookup;
	}

	instruction_offset = ql_raw_to_sections_data_offset(pefile, da->FileOffset);

	if (instruction_offset == -1) {
		free(da);
		return last_lookup;
	}

	insn_buffer_length = pefile->sections_data->size - instruction_offset;

	if (pefile->sections_data->size >= instruction_offset + 4)
	{
		DWORD *dwptr = (DWORD *)&pefile->sections_data->buf[instruction_offset];
		if (ql_va_points_to_code(pefile, *dwptr))
		{
			free(da);
			//printf("LOOKIT: %08X points to %08X\n", MemoryAddress, *dwptr);

			disasm_queue_append(disassembly_queue, *dwptr);
			return last_lookup;
		}
	}

	da->InstructionSize = x86_disasm(&pefile->sections_data->buf[instruction_offset],
		     					    insn_buffer_length,
			    					va_to_rva(pefile, MemoryAddress),
				    			    0,
									&da->Instruction);

	if (!x86_insn_is_valid(&da->Instruction)
		|| insn_is_zeros(&da->Instruction)) 
	{
		free(da);
		return last_lookup;
	}

	if (!add_to_disasm_list(disasm_list, da, last_lookup))
	{
		free(da);
		return last_lookup;
	}
	
	if (lpdwRunningTotal != NULL)
		*lpdwRunningTotal += da->InstructionSize; 

	if (da->Instruction.type == insn_jmp
		|| da->Instruction.type == insn_jcc
		|| da->Instruction.type == insn_call)
	{
		if (is_table_jump(da)) {
			DWORD *table;
			DWORD dwNumEntries = 0;
	
			table = get_jump_table(da, pefile, &dwNumEntries);
			while (dwNumEntries-- > 0) {
				// We append these switch targets because they may be less reliable
				// In the event of conflicts we should favor other targets first.
				disasm_queue_append(disassembly_queue, *table);
				table++;
			}
		} else {
			switch (da->Instruction.operands->op.type) {
			case op_absolute:
				if (da->Instruction.type != insn_call) {
					//if (va_points_to_code(pefile, oplist_ptr->op.data.dword)) {
					if (ql_va_points_to_code(pefile, oplist_ptr->op.data.dword))
					{
						disasm_queue_push(disassembly_queue, oplist_ptr->op.data.dword);
					}
				}
				break;
			case op_relative_near:
			case op_relative_far:
				if (ql_va_points_to_code(pefile, get_flowcontrol_target(da)))
					disasm_queue_push(disassembly_queue, get_flowcontrol_target(da));
				break;
			default:
				break;
			}
		}
	} else if (da->Instruction.operand_count > 0) {
		x86_oplist_t *curr_op = da->Instruction.operands;
		// Push the operands that point to code first so they have priority
		while (curr_op != NULL) {
			if (curr_op->op.type == op_immediate && curr_op->op.datatype == op_dword) {
				if (curr_op->op.data.dword > pefile->image_nt_headers.OptionalHeader.ImageBase
					&& curr_op->op.data.dword < pefile->image_nt_headers.OptionalHeader.ImageBase + pefile->image_nt_headers.OptionalHeader.SizeOfImage)
				{
					if (ql_va_points_to_code(pefile, curr_op->op.data.dword))
						disasm_queue_push(disassembly_queue, curr_op->op.data.dword);
				}
			}
			curr_op = curr_op->next;
		}
	}

	if (da->Instruction.type != insn_return 
		&& da->Instruction.type != insn_jmp
		&& ql_va_points_to_code(pefile, MemoryAddress + da->InstructionSize)) 
	{
		// the next instruction should have slightly less priority (a.k.a. trust) than code pointer operands
		disasm_queue_push(disassembly_queue, MemoryAddress + da->InstructionSize);
	}

	return da;
}

void debug_print_instruction(disassembly_t *da)
{
	struct xref *xr;
	BOOL previous_xrefs = FALSE;
	char *line[512];
	assert(da != NULL);

	x86_format_insn(&da->Instruction, line, sizeof line, intel_syntax);
	printf("%08X: %s", da->MemoryAddress, line);
	
	for (xr = da->xrefs_from; xr != NULL; xr = xr->next) {
		if (previous_xrefs) {
			printf(", ");
		} else {
			printf("\t\t");
			previous_xrefs = TRUE;
		}
		printf("xref_from:%08X", xr->insn->MemoryAddress);
	}
	for (xr = da->xrefs_to; xr != NULL; xr = xr->next) {
		if (previous_xrefs) {
			printf(", ");
		} else {
			printf("\t\t");
			previous_xrefs = TRUE;
		}
		printf("xref_to:%08X", xr->insn->MemoryAddress);
	}
	printf("\n");
}

void debug_print_disassembly(disassembly_t *da)
{
	disassembly_t *daptr;

	assert(da != NULL);

	for (daptr = da; daptr != NULL; daptr = daptr->next) {
		debug_print_instruction(daptr);
	}
}

DWORD call_target(disassembly_t *da)
{
	assert(da != NULL);

	if (da->Instruction.type == insn_call) {
		x86_op_t *op;
		op = &da->Instruction.operands->op;

		if (op->type == op_relative_far) {
			return da->MemoryAddress + (long)op->data.dword + da->InstructionSize;
		} else if (op->type == op_expression && op->data.expression.base.type == 0) {
			return op->data.expression.disp;
		} else {
			return -1;
		}
	} else {
		return -1;
	}
}

DWORD get_flowcontrol_target(disassembly_t *da)
{
	x86_op_t *op;
	
	assert(da != NULL);

	op = &da->Instruction.operands->op;

	switch (da->Instruction.type) {
		case insn_jmp:
		case insn_jcc:
			if (op->datatype == op_byte)
				return da->MemoryAddress + (char)op->data.byte + da->InstructionSize;
			else if (op->datatype == op_word)
				return da->MemoryAddress + (short)op->data.word + da->InstructionSize;
			else if (op->datatype == op_dword)
				return da->MemoryAddress + (long)op->data.dword + da->InstructionSize;
			break;
		case insn_call:
			if (op->type == op_relative_far)
				return da->MemoryAddress + (long)op->data.dword + da->InstructionSize;
			break;
		default:
			break;
	}
	return -1;
}

static void add_xref_to_list(struct xref **xl, disassembly_t *insn)
{
	struct xref *new_xref;

	assert(xl != NULL);
	assert(insn != NULL);

	new_xref = emalloc(sizeof *new_xref);

	new_xref->insn = insn;

	new_xref->next = *xl;
	*xl = new_xref;
}

static void add_xref(disassembly_t *from, disassembly_t *to)
{
	assert(from != NULL);
	assert(to != NULL);

	add_xref_to_list(&to->xrefs_from, from);
	add_xref_to_list(&from->xrefs_to, to);
}

static void add_xref_to_addr(disassembly_t *from, DWORD dwToMemoryAddress, disassembly_t *disasm_list)
{
	disassembly_t *target;

	assert(from != NULL);
	assert(disasm_list != NULL);

	target = disasm_list_lookup_addr(disasm_list, dwToMemoryAddress, from);
	if (target != NULL)
		add_xref(from, target);
}

// I've put the body of this function directly into disassemble_pefile() for the moment
// The reason for this is simply for the pretty output, I don't want to jam an fprintf()
// down here in this function where it doesn't belong.
static void generate_xrefs(disassembly_t *disasm_list, pefile_t *pefile)
{
	disassembly_t *insn;

	assert(disasm_list != NULL);
	assert(pefile != NULL);

	for (insn = disasm_list; insn != NULL; insn = insn->next) {
		generate_insn_xrefs(insn, disasm_list, pefile);
	}
}

static void generate_insn_xrefs(disassembly_t *insn, disassembly_t *disasm_list, pefile_t *pefile)
{
	//if (insn->MemoryAddress == 0x004058B3)
	//	__asm int 3;

	if (insn->Instruction.type == insn_jmp
		|| insn->Instruction.type == insn_jcc
		|| insn->Instruction.type == insn_call)
	{
		struct xref *xref_list = NULL;
	
		if (is_table_jump(insn)) {
			DWORD *table;
			DWORD dwNumEntries = 0;

			table = get_jump_table(insn, pefile, &dwNumEntries);
			while (dwNumEntries-- > 0) {
				add_xref_to_addr(insn, *table, disasm_list);
				table++;
			}
		} else if (insn->Instruction.operands->op.type == op_expression) {
			// Not supported, add stuff here if you ever want to cross reference IAT calls
		} else {
			add_xref_to_addr(insn, get_flowcontrol_target(insn), disasm_list);
		}
	} else if (insn->Instruction.operand_count > 0) {
		x86_oplist_t *curr_op = insn->Instruction.operands;

		while (curr_op != NULL) {
			if (curr_op->op.type == op_immediate && curr_op->op.datatype == op_dword) {
				if (ql_va_points_to_code(pefile, curr_op->op.data.dword)) {
					add_xref_to_addr(insn, curr_op->op.data.dword, disasm_list);
				}
			}
			curr_op = curr_op->next;
		}
	}
}

static void free_xref_list(struct xref *xl)
{
	while (xl != NULL) {
		struct xref *next = xl->next;
		free(xl);
		xl = next;
	}
}

static BOOL is_table_jump(disassembly_t *insn)
{
	assert(insn != NULL);

	if (insn->Instruction.type != insn_jmp)
		return FALSE;
	else if (insn->Instruction.operands->op.type == op_expression
		&& insn->Instruction.operands->op.datatype == op_dword
		&& insn->Instruction.operands->op.flags == op_pointer
		&& insn->Instruction.operands->op.data.expression.disp != 0
		&& insn->Instruction.operands->op.data.expression.scale != 0)
	{
		return TRUE;
	} else {
		return FALSE;
	}
}

static DWORD *get_jump_table(disassembly_t *insn, pefile_t *pefile, DWORD *dwNumEntries)
{
	DWORD dwTableStart;
	DWORD *lpdwJumpTable;

	assert(insn != NULL);
	assert(pefile != NULL);

	if (!is_table_jump(insn))
		return NULL;

	dwTableStart = insn->Instruction.operands->op.data.expression.disp;

	// Sanity check the table start
	if (pefile->image_nt_headers.OptionalHeader.ImageBase > dwTableStart
		|| pefile->image_nt_headers.OptionalHeader.ImageBase + pefile->image_nt_headers.OptionalHeader.SizeOfImage <= dwTableStart)
	{
		return NULL;
	}

	if (!ql_va_points_to_code(pefile, dwTableStart))
		return NULL;

	lpdwJumpTable = (DWORD *)ql_va_to_ptr(pefile, dwTableStart);

	if (lpdwJumpTable == NULL)
		return NULL;

	*dwNumEntries = 0;

	while (1) {
		if (lpdwJumpTable[*dwNumEntries] != 0
			&& ql_va_points_to_code(pefile, lpdwJumpTable[*dwNumEntries]))
		{
			*dwNumEntries += 1;
		} else {
			break;
		}
	}

	return lpdwJumpTable;
}

//static DWORD code_ptr_scan(pefile_t *pefile, struct disassembly_queue **disassembly_queue, DWORD MemoryAddress)
//{
//	DWORD dwNumPointersFound = 0;
//	assert(pefile != NULL);
//	assert(disassembly_queue != NULL);
//	
//	while (ql_va_points_to_code(pefile, MemoryAddress))
//	{
//		DWORD *dwPtr = (DWORD *)ql_va_to_ptr(pefile, MemoryAddress);
//		if (dwPtr == NULL)
//			return;
//		if (va_points_to_code(pefile, *dwPtr))
//		{
//			disasm_queue_push(disassembly_queue, *dwPtr);
//			dwNumPointersFound++;
//		} else {
//			return dwNumPointersFound;
//		}
//		MemoryAddress += 4;
//	}
//}

//static DWORD code_ptr_scan(pefile_t *pefile, struct disassembly_queue **disassembly_queue)
//{
//	DWORD *possible_ptr;
//	BOOL foundSomething = FALSE;
//	int i;
//
//	assert(pefile != NULL);
//
//	possible_ptr = (DWORD *)pefile->sections_data->buf;
//	for (i = 0; i < pefile->sections_data->size / 4; i++)
//	{
//		if (possible_ptr[i] != 0 && ql_va_points_to_code(pefile, possible_ptr[i])) {
//			foundSomething = TRUE;
//			printf("CODE PTR FOUND: va=%08X, points to 0x%08X\n", ptr_to_va(pefile, (char *)&possible_ptr[i]), possible_ptr[i]);
//			disasm_queue_append(disassembly_queue, ptr_to_va(pefile, (char *)&possible_ptr[i]));
//		}
//	}
//	
//	if (foundSomething)
//		return disasm_queue_pop(disassembly_queue);
//	else
//		return -1;
//}

static DWORD code_ptr_scan(pefile_t *pefile, struct disassembly_queue **disassembly_queue, DWORD *start)
{
	DWORD *possible_ptr;
	int i;

	assert(pefile != NULL);
	assert(start != NULL);

	possible_ptr = (DWORD *)pefile->sections_data->buf;
	for (i = *start; i < pefile->sections_data->size / 4; i++)
	{
		if (possible_ptr[i] != 0 && ql_va_points_to_code(pefile, possible_ptr[i])) {
			//static int foo;
			//if (!(foo++))
			//	__asm int 3;
			//printf("CODE PTR FOUND: va=%08X, points to 0x%08X\n", ptr_to_va(pefile, (char *)&possible_ptr[i]), possible_ptr[i]);
			*start = ++i;
			return ptr_to_va(pefile, (char *)&possible_ptr[i]);
		}
	}

	return -1;
}

// This is to check if an instruction has been disassembled 
// as the  
static BOOL insn_is_zeros(x86_insn_t *insn)
{
	assert(insn != NULL);
	
	if (insn->size == 2 && insn->bytes[0] == 0 && insn->bytes[1] == 0)
		return TRUE;
	else
		return FALSE;
}

// Remove any instructions from beginning to end memory addresses which are in the disassembly set
static DWORD remove_sequence(disassembly_t **da, DWORD beginning, DWORD end)
{
	DWORD dwNumBytesRemoved = 0;
	disassembly_t *beginning_insn;
	disassembly_t *ending_insn;
	disassembly_t *curr_insn, *next_insn; // used for freeing

	assert(da != NULL);

	//printf("REMOVING %08X to %08X\n", beginning, end);

	// find the first instruction in the sequence
	for (beginning_insn = *da; beginning_insn != NULL; beginning_insn = beginning_insn->next)
	{
		if (beginning_insn->MemoryAddress == beginning)
			break;
	}

	if (beginning_insn == NULL)
		return 0;

	// find the last instruction in the sequence
	// also, count the number of bytes we're going to remove for return value
	for (ending_insn = beginning_insn; ending_insn != NULL; ending_insn = ending_insn->next)
	{
		dwNumBytesRemoved += ending_insn->InstructionSize;
		if (ending_insn->MemoryAddress + ending_insn->InstructionSize >= end)
			break;
	}

	if (beginning_insn->prev == NULL)
	{
		if (ending_insn == NULL) {
			*da = NULL;
		} else {
			*da = ending_insn->next;
			if (ending_insn->next != NULL) {
				ending_insn->next->prev = NULL;
			}
		}
	} else {
		if (ending_insn == NULL) {
			beginning_insn->prev->next = NULL;
		} else {
			beginning_insn->prev->next = ending_insn->next;
			if (ending_insn->next != NULL) {
				ending_insn->next->prev = beginning_insn->prev;
			}
		}
	}

	beginning_insn->prev = NULL;

	if (ending_insn != NULL)
		ending_insn->next = NULL;

	// now that we've unlinked the instructions from the list, let's free them.
	for (curr_insn = beginning_insn; curr_insn != NULL;  curr_insn = next_insn)
	{
		next_insn = curr_insn->next;
		free(curr_insn);
	}

	return dwNumBytesRemoved;
}

static void debug_print_sequences(disassembly_t *da)
{
	disassembly_t *daPtr = da;

	while (daPtr != NULL)
	{
		DWORD beginning, end;
		beginning = daPtr->MemoryAddress;
		while (daPtr->next != NULL
			   && daPtr->next->MemoryAddress == daPtr->MemoryAddress + daPtr->InstructionSize)
		{
			daPtr = daPtr->next;
		}
		end = daPtr->MemoryAddress + daPtr->InstructionSize;
		printf("0x%08X to 0x%08X (%d bytes) %s\n", beginning, end, end-beginning, daPtr->Instruction.mnemonic);
		daPtr = daPtr->next;
	}
}

// The design of this currently is to remove any contiguous sequence of instructions
// which do not end in a ret or a jmp.  hopefully this should remove a great
// deal of invalid disassembly.
static DWORD remove_suspicious_sequences(disassembly_t **da)
{
	DWORD dwNumBytesRemoved = 0;
	disassembly_t *daPtr;

	assert(da != NULL);

	daPtr = *da;

	while (daPtr != NULL)
	{
		DWORD beginning, end;
		beginning = daPtr->MemoryAddress;

		while (daPtr->next != NULL
			   && daPtr->next->MemoryAddress == daPtr->MemoryAddress + daPtr->InstructionSize)
		{
			daPtr = daPtr->next;
		}
		end = daPtr->MemoryAddress + daPtr->InstructionSize;

		if (daPtr->Instruction.type == insn_return
			|| daPtr->Instruction.type == insn_jmp)
		{
			daPtr = daPtr->next;
		} else {
			daPtr = daPtr->next;
			dwNumBytesRemoved += remove_sequence(da, beginning, end);
		}
	}

	return dwNumBytesRemoved;
}

static void mark_entry_points(pefile_t *pefile, disassembly_t *da)
{
    disassembly_t *dptr;
    DWORD dwOEP;
    assert(pefile);

	if (pefile->exports != NULL)
	{
		int i;
		for (i = 0; i < pefile->exports->image_export_directory.NumberOfFunctions; i++) 
		{
			if (pefile->exports->exports[i].export_address_type == EXPORT_ADDRESS_TYPE_RVA)
			{
				// find the instruction that matches and flag it.
                for (dptr = da; dptr != NULL; dptr = dptr->next)
                {
                    if (dptr->MemoryAddress == rva_to_va(pefile, pefile->exports->exports[i].rva.rva))
                    {
                        dptr->IsNotRelocatable = TRUE;
                        break;
                    }
                }
			}
		}
	}

	dwOEP = pefile->image_nt_headers.OptionalHeader.AddressOfEntryPoint + pefile->image_nt_headers.OptionalHeader.ImageBase;
    for (dptr = da; dptr != NULL ; dptr = dptr->next)
    {
        if (dptr->MemoryAddress == dwOEP)
        {
            dptr->IsNotRelocatable = TRUE;
            break;
        }
    }	   
}

//#endif /*PEFILE_H*/