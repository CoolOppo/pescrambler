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
#include <assert.h>
#include <windows.h>
#include <crtdbg.h>
#include "buffers.h"
#include "pefile.h"
#include "getopt.h"
#include "util.h"
#include "libdis.h"
#include "disasm.h"
#include "reloc.h"
#include "hijacksection.h"
//#include "x86asm.h"
#include "calldispatch.h"

static void perplex_section(pefile_t *pefile, int section_number);

static void call_list_add(struct call_list **list, disassembly_t *da);
static struct call_table *call_list_to_table(pefile_t *pefile, struct call_list *list, int *nElements);
static void call_remap_instruction(pefile_t *pefile, disassembly_t *da, DWORD dispather_addr, DWORD indirect_ptr);
static DWORD add_dispatcher_to_pefile(pefile_t *pefile, struct call_table *ctable, DWORD nElements);

static struct call_table *last_calltable;

// I can't currently find my original asm source code for this, for now please just disassemble.
unsigned char dispatcher_stub[65] = {
	0x50, 0x52, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x05, 0x3A, 0x00, 0x00, 0x00, 0x8B, 0x10, 0x39, 
	0x54, 0x24, 0x08, 0x74, 0x0B, 0x05, 0x08, 0x00, 0x00, 0x00, 0x85, 0xD2, 0x74, 0x0A, 0xEB, 0xED, 
	0x5A, 0x8B, 0x40, 0x04, 0x87, 0x04, 0x24, 0xC3, 0x8B, 0x10, 0x39, 0x54, 0x24, 0x08, 0x74, 0x07, 
	0x05, 0x08, 0x00, 0x00, 0x00, 0xEB, 0xF1, 0x5A, 0x8B, 0x40, 0x04, 0x8B, 0x00, 0x87, 0x04, 0x24, 
	0xC3
};

void call_remap(pefile_t *pefile, disassembly_t *da)
{
    disassembly_t *dptr;
    struct call_list *clist = NULL;
    struct call_table *ctable;
    int nelements = 0;
    DWORD indirect_ptr_address;
    DWORD dispatcher_address;

    assert(pefile != NULL);
    assert(da != NULL);

    for (dptr = da; dptr != NULL; dptr = dptr->next) {
		if (dptr->Instruction.type == insn_call) {
			if (dptr->Instruction.operands->op.type == op_relative_far) {
				call_list_add(&clist, dptr);
			} else if (dptr->Instruction.operands->op.type == op_expression 
				       && dptr->Instruction.operands->op.data.expression.base.type == 0) 
			{
                //printf("Remapping: %08X-%08X\n", dptr->MemoryAddress, dptr->MemoryAddress + dptr->InstructionSize);
				call_list_add(&clist, dptr);
			}
		}
	}

	if (clist == NULL)
		return;

	//debug_print_disassembly(da);

	ctable = call_list_to_table(pefile, clist, &nelements);
    last_calltable = ctable;
	indirect_ptr_address = add_dispatcher_to_pefile(pefile, ctable, nelements);
	dispatcher_address = indirect_ptr_address + sizeof (DWORD);

	call_remap_pefile(pefile, clist, dispatcher_address, indirect_ptr_address);
}

void redispatch(DWORD original_ret_ptr, DWORD new_ret_ptr)
{
    struct call_table *ctptr;
    BOOL bSeperatorHit = FALSE;    

    assert(last_calltable != NULL);

  
    for (ctptr = last_calltable; !bSeperatorHit || ctptr->ReturnPointer != 0; ctptr++)
    {
        if (ctptr->ReturnPointer == 0)
            bSeperatorHit = TRUE;

        if (ctptr->ReturnPointer == original_ret_ptr)
        {
            //printf("Redispatching: %08X to %08X\n", original_ret_ptr, new_ret_ptr);
            ctptr->ReturnPointer = new_ret_ptr;
            break;
        }
    }
}

void perplex_section(pefile_t *pefile, int section_number)
{
	char *data;
	size_t size;
	x86_insn_t insn;
	int pos = 0;
	int section_start;

	assert(pefile != NULL);
	
	section_start = pefile->pimage_section_headers[section_number].VirtualAddress + pefile->image_nt_headers.OptionalHeader.ImageBase;

	data = get_section_data(pefile, section_number, &size);
	if (data == NULL)
		return;

	x86_init(opt_none, 0);
	
	while (pos < size) {
		char line[512];
		int insn_size = x86_disasm(data, size, 0, pos, &insn);

		if (insn_size > 0) {
			x86_format_insn(&insn, line, sizeof line, intel_syntax);
			//printf("%08X: %s\n", pos + section_start, line);
			pos += insn_size;
		} else {
			//printf("%08X: Invalid Instruction\n", pos + section_start);
			pos++;
		}
	}

	x86_cleanup();
}

static void call_list_add(struct call_list **list, disassembly_t *da)
{
	assert(list != NULL);
	assert(da != NULL);

	if (*list == NULL) {
		*list = emalloc(sizeof *list);
		(*list)->next = NULL;
		(*list)->da = da;
	} else {
		struct call_list *new_cl_node = emalloc(sizeof *new_cl_node);
		new_cl_node->next = *list;
		new_cl_node->da = da;
		*list = new_cl_node;
	}
}

static struct call_table *call_list_to_table(pefile_t *pefile, struct call_list *list, int *nElements)
{
	int i = 0;
	struct call_list *lptr;
	struct call_table *table;

	assert(pefile != NULL);
	assert(list != NULL);

	for (lptr = list; lptr != NULL; lptr = lptr->next)
		i++;

	if (nElements != NULL)
		*nElements = i + 1;   // We add one because there is a null-element separator between direct and indirect

	table = ecalloc(i + 2, sizeof *table);

	i = 0;
	// we iterate through first and add the direct calls
	for (lptr = list; lptr != NULL; lptr = lptr->next) {
		if (lptr->da->Instruction.operands->op.type == op_relative_far) {
			table[i].ReturnPointer = lptr->da->MemoryAddress + lptr->da->InstructionSize;
			table[i].Target = call_target(lptr->da);
			i++;
		}
	}

	i++;  // Leave a single element of zero's to seperate the direct from the indirect

	// now we add the indirect calls
	for (lptr = list; lptr != NULL; lptr = lptr->next) {
		if (lptr->da->Instruction.operands->op.type == op_expression
			&& lptr->da->Instruction.operands->op.data.expression.base.type == 0)
		{
			table[i].ReturnPointer = lptr->da->MemoryAddress + lptr->da->InstructionSize;
			table[i].Target = call_target(lptr->da);
			i++;
		}
	}

	return table;
}

static void call_remap_pefile(pefile_t *pefile, struct call_list *list, DWORD dispatcher_addr, DWORD indirect_ptr)
{
	struct call_list *lptr;

	assert(pefile != NULL);
	assert(list != NULL);

	for (lptr = list; lptr != NULL; lptr = lptr->next) {
		static char *swirly = "|/-\\";
		static int swirly_count;

		fprintf(stderr, "\rRemapping CALL Instructions. %c", swirly[swirly_count++ % 4]);
        //printf("Remapping: %08X\n", lptr->da->MemoryAddress);
		call_remap_instruction(pefile, lptr->da, dispatcher_addr, indirect_ptr);
	}
	fprintf(stderr, "\rRemapping CALL Instructions. (done)\n");
}

static void call_remap_instruction(pefile_t *pefile, disassembly_t *da, DWORD dispatcher_addr, DWORD indirect_ptr)
{
	DWORD sections_data_offset;
	DWORD old_operand, new_operand;
	DWORD *operand_ptr;
	x86_op_t *op;

	assert(pefile != NULL);
	assert(da != NULL);

	assert(da->Instruction.operands != NULL);

	op = &da->Instruction.operands->op;

	sections_data_offset = raw_to_sections_data_offset(pefile, da->FileOffset);
	if (sections_data_offset + da->InstructionSize > pefile->sections_data->size)
		return;

	if (pefile->sections_data->buf[sections_data_offset] != (char)0xE8
		&& pefile->sections_data->buf[sections_data_offset] != (char)0xFF)
	{
		return;
	}

	if (op->type == op_expression && op->data.expression.base.type == 0) {
		operand_ptr = (DWORD *)&pefile->sections_data->buf[sections_data_offset + 2];
		
		old_operand = *operand_ptr;
		*operand_ptr = indirect_ptr;

		da->Instruction.operands->op.data.expression.disp = indirect_ptr;
		//printf("%08X: I[%08X -> %08X]\n", da->MemoryAddress, old_operand, indirect_ptr);
	} else if (op->type == op_relative_far) {
		new_operand = dispatcher_addr - (da->MemoryAddress + da->InstructionSize);
	
		operand_ptr = (DWORD *)&pefile->sections_data->buf[sections_data_offset + 1];

		old_operand = *operand_ptr;
		*operand_ptr = new_operand;

		da->Instruction.operands->op.data.dword = new_operand;
		//printf("%08X: D[%08X -> %08X]\n", da->MemoryAddress, old_operand, new_operand);
	} 
}

static DWORD add_dispatcher_to_pefile(pefile_t *pefile, struct call_table *ctable, DWORD nElements)
{
	buffer_t *section_data_buf;
	char *dispatcher;
    //char *new_ctable;

	assert(pefile != NULL);
	assert(ctable != NULL);

	section_data_buf = new_buffer(sizeof (DWORD) + sizeof dispatcher_stub + nElements * sizeof (struct call_table));

	memcpy(&section_data_buf->buf[sizeof (DWORD)], dispatcher_stub, sizeof dispatcher_stub);
    memcpy(&section_data_buf->buf[sizeof (DWORD) + sizeof dispatcher_stub], ctable, nElements * sizeof (struct call_table));

    //last_calltable = (struct call_table *)new_ctable;

	dispatcher = add_section_to_pefile(pefile, ".disp", section_data_buf, 0xE0000020);
	if (dispatcher != NULL) {
		DWORD *lpdwIndirectPtr = (DWORD *) dispatcher;
		*lpdwIndirectPtr = ptr_to_va(pefile, dispatcher + sizeof (DWORD));
        last_calltable = (struct call_table *)(dispatcher + sizeof (DWORD) + sizeof dispatcher_stub);
		return *lpdwIndirectPtr - sizeof (DWORD);
	} else {
		return -1;
	}
}
