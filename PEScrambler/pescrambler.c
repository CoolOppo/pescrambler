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

#ifndef PROGRAM_NAME
#define PROGRAM_NAME "PE-Scrambler"
#endif

#ifndef PROGRAM_VERSION
#define PROGRAM_VERSION "v0.1 (Alpha)"
#endif

static void armor_pefile(pefile_t *pefile);
static void disasm(const char *filename);
static void hijack(const char *original_loc, DWORD original_addr, const char *new_loc, DWORD new_addr, reloc_seq_t *seq);

static void usage(const char *progname, FILE *stream)
{
	fprintf(stream, "Usage: %s -i <INPUT.exe> -o <OUTPUT.exe>\n", progname);
}

void armoring_swirly(void)
{
	static char *swirly = "|/-\\";
	static int swirly_count;

	fprintf(stderr, "\rArmoring Code. %c", swirly[swirly_count++ % 4]);
}

int main(int argc, char *argv[])
{
	int c;
	char *input_filename = NULL;
	char *output_filename = NULL;
	buffer_t *input_buffer;
	pefile_t *original_pefile;
    int disasm_mode = 0;
    int sequences_mode = 0;

    printf("%s %s\nCopyright (C) 2007-2008 Nick Harbour, All Rights Reserved\n\n", PROGRAM_NAME, PROGRAM_VERSION);

	while (1) {
		static struct option long_options[] =
		{
			{"help", no_argument, 0, 'h'},
			{"input", required_argument, 0, 'i'},
			{"output", required_argument, 0, 'o'},
            {"disasm", no_argument, 0, 'd'},
            {"sequences", no_argument, 0, 's'},
			{0,0,0,0}
		};

		int option_index = 0;

		c = getopt_long(argc, argv, "hi:o:d", long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
			case 'h':
				usage(argv[0], stdout);
				printf("\n"
					   " -i FILE, --input=FILE     Specify an input executable FILE\n"
					   " -o FILE, --output=FILE    Specify an output executable FILE\n"
					   " -h, --help                Display this help information\n");
				return 0;
			case 'i':
				input_filename = optarg;
				break;
			case 'o':
				output_filename = optarg;
				break;
            case 'd':
                disasm_mode++;
                break;
            case 's':
                sequences_mode++;
                break;
			default:
				usage(argv[0], stderr);
				exit(-1);
		}
	}

    if (disasm_mode && sequences_mode && input_filename)
    {
    }
    if (disasm_mode && input_filename)
    {
        disasm(input_filename);
        if (!output_filename && !sequences_mode)
            return 0;
    }

    if (sequences_mode && input_filename)
    {
    }
	if (optind < argc || !input_filename || !output_filename) {
		usage(argv[0], stderr);		
		exit(-1);
	}

	
	fprintf(stderr, "Loading and Parsing Input File...\r");

	input_buffer = read_file_to_buffer(input_filename);
	original_pefile = parse_pefile(input_buffer);
	free_buffer(&input_buffer);

	if (original_pefile == NULL) {
		die("%s does not appear to be a valid PE executable", input_filename);
	}

	fprintf(stderr, "Loading and Parsing Input File. (done)\n");

	armoring_swirly();
	armor_pefile(original_pefile);
	fprintf(stderr, "\rArmoring Code. (done)\n");

	fprintf(stderr, "Writing Output File. ");
	dump_pefile(original_pefile, output_filename);
	fprintf(stderr, "(done)\n");

	return 0;
}

static void disasm(const char *filename)
{
    buffer_t *input_buf;
    pefile_t *pefile;
    disassembly_t *da;

    
    input_buf = read_file_to_buffer(filename);
    pefile = parse_pefile(input_buf);
    free_buffer(&input_buf);

	assert(pefile != NULL);

	da = disassemble_pefile(pefile, TRUE, TRUE, 0);

	debug_print_disassembly(da);
}
    

static void hijack_with_jmp(reloc_seq_t *seq, hijacksection_t *hijacksection, pefile_t *pefile)
{
	char *old_buf;
	char *new_buf;
	DWORD newMemoryAddress = 0;
	DWORD dwOperand = 0;

	assert(seq != NULL);
	assert(hijacksection != NULL);

	if (seq->relocated)
		return;

	old_buf = va_to_ptr(pefile, seq->start);
	
	if (old_buf == NULL) {
		old_buf = hijacksection_va_to_ptr(hijacksection, seq->start);
		if (old_buf == NULL)
			return;
	}

	new_buf = hijack_reserve(hijacksection, seq->length + 5, &newMemoryAddress); 
	
	//memcpy(new_buf, old_buf, seq->length);
    hijack(old_buf, seq->start, new_buf, newMemoryAddress, seq);

	new_buf[seq->length] = 0xe9;
	dwOperand = (seq->start + seq->length) - (newMemoryAddress + seq->length + 5);
	memcpy(&new_buf[seq->length + 1], &dwOperand, sizeof dwOperand);
	
	old_buf[0] = 0xe9;
	dwOperand = newMemoryAddress - (seq->start + 5);
    
	memcpy(&old_buf[1], &dwOperand, sizeof dwOperand);

	//printf("Reloc: %d bytes from 0x%08X to 0x%08X\n", seq->length, seq->start, newMemoryAddress);
	//debug_print_insn_list(seq->instructions);
	//printf("\n");
}

static void hijack(const char *original_loc, DWORD original_addr, const char *new_loc, DWORD new_addr, reloc_seq_t *seq)
{
    reloc_insn_list_t *reloc_list_ptr;
    assert(original_loc != NULL);
    assert(new_loc != NULL);
    assert(seq != NULL);

    //if (original_addr == 0x01012470)
    //    __asm int 3;

    memcpy(new_loc, original_loc, seq->length);
    memset(original_loc, 0, seq->length);
    
    for (reloc_list_ptr = seq->instructions; reloc_list_ptr != NULL; reloc_list_ptr = reloc_list_ptr->next)
    {
        if (reloc_list_ptr->insn->Instruction.type == insn_call
            && reloc_list_ptr->insn->Instruction.operands->op.type == op_expression)
        {
            DWORD delta = new_addr - original_addr;
            DWORD original_ret_ptr = reloc_list_ptr->insn->MemoryAddress + reloc_list_ptr->insn->InstructionSize;

            /*if (original_ret_ptr == 0x01004719)
                __asm int 3;*/
            redispatch(original_ret_ptr, original_ret_ptr + delta);
        }
    }
}

static void hijack_sequences_with_jmp(reloc_seq_t *seq, hijacksection_t *hijacksection, pefile_t *pefile, int number)
{
	reloc_seq_t *seq_ptr;
	static count;
	_ASSERT(seq != NULL);
	_ASSERT(hijacksection != NULL);
	_ASSERT(pefile != NULL);

	for (seq_ptr = seq; seq_ptr != NULL; seq_ptr = seq_ptr->next) {

		armoring_swirly();
		if (seq_ptr->length >= 5) {
			//printf("%d ", count);
		
			if (count++ == number)
				return;
			hijack_with_jmp(seq_ptr, hijacksection, pefile);
		}
	}
}
	//for (seq_ptr = sequences; seq_ptr != NULL; seq_ptr = seq_ptr->next) {
	//	armoring_swirly();
	//	if (seq_ptr->length >= 5) {
	//		hijack_with_jmp(seq_ptr, hijacksection, pefile);
	//	}
	//}


// return true if instruction has 2 operands which are identical (usually registers)
static BOOL operands_match(disassembly_t *insn)
{
	x86_op_t *src, *dst;
	
	assert(insn != NULL);

	if (insn->Instruction.operand_count != 2)
		return FALSE;

	dst = &insn->Instruction.operands->op;
	src = &insn->Instruction.operands->next->op;

	if (src->type == dst->type
		&& src->datatype == dst->datatype
		&& memcmp(&src->data, &dst->data, sizeof src->data) == 0)
	{
		return TRUE;
	} else
		return FALSE;
}

static void hijack_xor_seq(reloc_seq_t *seq, hijacksection_t *hijacksection, pefile_t *pefile)
{
	char *old_buf;
	char *new_buf;
	DWORD newMemoryAddress = 0;
	DWORD dwOperand = 0;
	DWORD xorInsnSize = 0;

	assert(seq != NULL);
	assert(hijacksection != NULL);
	assert(pefile != NULL);

	if (seq->relocated)
		return;

	if (seq->instructions->insn->Instruction.type != insn_xor
		|| !operands_match(seq->instructions->insn))
	{
		return;
	}

	xorInsnSize = seq->instructions->insn->InstructionSize;

    seq->instructions = seq->instructions->next;
    seq->length -= xorInsnSize;
    seq->start += xorInsnSize;

	// See if we have enough room to plant the 6 byte "JZ rel32" instruction
	if (seq->length < 6)
		return;

	old_buf = va_to_ptr(pefile, seq->start);

	if (old_buf == NULL) {
		old_buf = hijacksection_va_to_ptr(hijacksection, seq->start);
		if (old_buf == NULL)
			return;
	}

	new_buf = hijack_reserve(hijacksection, seq->length + 6, &newMemoryAddress);

	new_buf[0] = 0xEB;   // 8-bit relative JMP prefix

    newMemoryAddress++;  // lets bypass the fake 0xEB we put in for future reference.

    hijack(old_buf, seq->start, &new_buf[1], newMemoryAddress, seq);

	// finish off the new hijack area with a jmp back to the original.
	new_buf[seq->length + 1] = 0xE9;  // 32-bit JMP prefix
	dwOperand = (seq->start + seq->length) - (newMemoryAddress + seq->length + 5);
	memcpy(&new_buf[(seq->length) + 2], &dwOperand, sizeof dwOperand);

	// Put in a jz prefix to the new "real" code chunk
	old_buf[0] = 0x0F;
	old_buf[1] = 0x84;

	dwOperand = newMemoryAddress - (seq->start + 6);

	memcpy(&old_buf[2], &dwOperand, sizeof dwOperand);

	// if we have enough room left, put in a fake jmp or call to before the "real" code
	// This will throw off disassembly, especially if we put a valid instruction prefix there.
	if (seq->length >= xorInsnSize + 6 + 5) {  // call <offset> is 5 bytes
		old_buf[6] = 0xE8;   // 32-bit relative CALL prefix
		dwOperand = (newMemoryAddress - 1) - (seq->start + 6 + 5);
		memcpy(&old_buf[7], &dwOperand, sizeof dwOperand);
	}

	//printf("XOR Hijack: %d bytes from 0x%08X to 0x%08X\n", seq->length, seq->start, newMemoryAddress+1);
	//debug_print_insn_list(seq->instructions);
	//printf("\n");

	seq->relocated = TRUE;

	// make a new relocatable sequence out of what has been moved so that another algorithm
	// may play with it further... (evil laughter)
	//    ...This could turn out to be a dumb idea...
	
 //   if (seq->length > xorInsnSize) {
	//	reloc_seq_t *new_seq;
	//	DWORD dwSeqOffset = 0;
	//	reloc_insn_list_t *insn;

	//	new_seq = ecalloc(1, sizeof *new_seq);
	//	new_seq->instructions = seq->instructions;
	//	new_seq->length = seq->length;
	//	new_seq->start = newMemoryAddress + 1;  // Add 1 to bypass the fake prefix we added.
	//	
	//	// just in case it might bite us later on, lets adjust all the addresses for the instructions
	//	for (insn = new_seq->instructions; insn != NULL; insn = insn->next) {
	//		insn->insn->MemoryAddress = newMemoryAddress + dwSeqOffset + 1;
	//		dwSeqOffset += insn->insn->InstructionSize;
	//	}
	//	
	//	new_seq->next = seq->next;
	//	seq->next = new_seq;
	//}
}

static void hijack_xor_sequences(reloc_seq_t *seq, hijacksection_t *hijacksection, pefile_t *pefile)
{
	reloc_seq_t *seq_ptr;

	assert(seq != NULL);
	assert(hijacksection != NULL);
	assert(pefile != NULL);

	for (seq_ptr = seq; seq_ptr != NULL; seq_ptr = seq_ptr->next) {
		reloc_insn_list_t *ilistptr;

		if (seq_ptr->relocated)
			continue;

		// See if there is a guaranteed ZF=1 instruction like xor eax, eax in the seq.
		for (ilistptr = seq_ptr->instructions; ilistptr != NULL; ilistptr = ilistptr->next) {
			disassembly_t *in = ilistptr->insn;
			armoring_swirly();
			if (in->Instruction.type == insn_xor) {
				if (operands_match(in)) {
					if (split_reloc_sequence(seq_ptr, in->MemoryAddress - seq_ptr->start) != FALSE) {
						hijack_xor_seq(seq_ptr->next, hijacksection, pefile);
						seq_ptr = seq_ptr->next;
					} else {
						hijack_xor_seq(seq_ptr, hijacksection, pefile);
					}
					break;
				}
			}
		}
	}
}

//static void armor_pefile(pefile_t *pefile)
//{
//	disassembly_t *da;
//	reloc_seq_t *sequences;
//	reloc_seq_t *seq_ptr;
//	hijacksection_t *hijacksection;
//
//	assert(pefile != NULL);
//
//	da = disassemble_pefile(pefile, TRUE, TRUE, 0);
//
//	//debug_print_disassembly(da);
//
//	sequences = find_relocatable_sequences(da);
//	//debug_print_relocatable_sequences(sequences);
//
//	hijacksection = new_hijacksection(pefile);
//	
//	hijack_xor_sequences(sequences, hijacksection, pefile);
//	hijack_sequences_with_jmp(sequences, hijacksection, pefile, 900);
//	
//	if (hijacksection->VirtualSize > 0)
//		commit_hijacksection(hijacksection, pefile);
//}

static void armor_pefile(pefile_t *pefile)
{
	disassembly_t *da;
	reloc_seq_t *sequences;
	reloc_seq_t *seq_ptr;
	hijacksection_t *hijacksection;

	assert(pefile != NULL);

	da = disassemble_pefile(pefile, TRUE, TRUE, 0);

    call_remap(pefile, da);
	//debug_print_disassembly(da);

	sequences = find_relocatable_sequences(da);
	//debug_print_relocatable_sequences(sequences);

	hijacksection = new_hijacksection(pefile);
	
	hijack_xor_sequences(sequences, hijacksection, pefile);
	hijack_sequences_with_jmp(sequences, hijacksection, pefile, 900);
	
	if (hijacksection->VirtualSize > 0)
		commit_hijacksection(hijacksection, pefile);
}


