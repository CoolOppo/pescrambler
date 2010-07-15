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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pefile.h"
#include "util.h"

#ifndef snprintf 
#define snprintf _snprintf
#endif

static DWORD get_header_size(pefile_t *pefile);
static DWORD pad_to_alignment(DWORD offset, DWORD alignment);
static char *inner_add_section_to_pefile(pefile_t *pefile, char *name, buffer_t *data, DWORD virtual_size, DWORD characteristics);
static void build_sections_quicklook(pefile_t *pefile);
static exports_t *parse_exports(pefile_t *pefile);
static imported_dll_t *parse_imports(pefile_t *pefile);
static DWORD get_eof_size(pefile_t *pefile);

BOOL mz_quick_check(char *filename)
{
	FILE *fptr;
	int first, second;

	fptr = fopen(filename, "rb");

	if (fptr == NULL)
		return FALSE;

	first = fgetc(fptr);
	second = fgetc(fptr);

	if (first == 'M' &&
		second == 'Z')
	{
		fclose(fptr);
		return TRUE;
	}

	fclose(fptr);
	return FALSE;
}	

pefile_t *parse_pefile(buffer_t *input)
{
	pefile_t *pefile;
	char *ibuf;
	char *section_table;
	off_t curr_offset = 0;
	int i;
	int header_size;
	PIMAGE_DOS_HEADER ibuf_dos_header;
	PIMAGE_NT_HEADERS ibuf_nt_headers;
	DWORD first_section_offset = 0;

	nASSERT('PE01', input != NULL);
	nASSERT('PE02', input->size > 0);
	nASSERT('PE03', input->buf != NULL);
	
	ibuf = input->buf;

	pefile = ecalloc(1, sizeof *pefile);
	pefile->boot_stub_data = ecalloc(1, sizeof *pefile->boot_stub_data);
	pefile->header_remainder_data = ecalloc(1, sizeof *pefile->header_remainder_data);
	pefile->sections_data = ecalloc(1, sizeof *pefile->sections_data);
	
	if (input->size < sizeof (IMAGE_DOS_HEADER)) {
		free(pefile);
		return NULL;
	}

	// set input buffer reference pointers
	ibuf_dos_header = (PIMAGE_DOS_HEADER) ibuf;
	if (ibuf_dos_header->e_magic != IMAGE_DOS_SIGNATURE 
		|| ibuf_dos_header->e_lfanew + sizeof (IMAGE_NT_HEADERS) > input->size) 
	{
		free(pefile);
		return NULL;
	}
		
	ibuf_nt_headers = (PIMAGE_NT_HEADERS) &ibuf[ibuf_dos_header->e_lfanew];

	if (ibuf_nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		free(pefile);
		return NULL;
	}

	memcpy(&pefile->image_dos_header, ibuf, sizeof (IMAGE_DOS_HEADER));

	if (pefile->image_dos_header.e_lfanew > sizeof (IMAGE_DOS_HEADER)) {
		pefile->boot_stub_data->size = pefile->image_dos_header.e_lfanew - sizeof (IMAGE_DOS_HEADER);
		pefile->boot_stub_data->buf = (char *)emalloc(pefile->boot_stub_data->size);
		memcpy(pefile->boot_stub_data->buf, &ibuf[sizeof (IMAGE_DOS_HEADER)], pefile->boot_stub_data->size);
	}

	curr_offset = pefile->image_dos_header.e_lfanew;

	memcpy(&pefile->image_nt_headers, &ibuf[curr_offset], sizeof (IMAGE_NT_HEADERS));

	curr_offset += sizeof (IMAGE_NT_HEADERS);

	pefile->pimage_section_headers = ecalloc(pefile->image_nt_headers.FileHeader.NumberOfSections, 
		                                     sizeof (IMAGE_SECTION_HEADER));
	
	section_table = (char *)IMAGE_FIRST_SECTION(ibuf_nt_headers);
	if (section_table == NULL)
		return NULL;
	header_size = pefile->image_dos_header.e_lfanew + sizeof (IMAGE_NT_HEADERS) 
		          + pefile->image_nt_headers.FileHeader.NumberOfSections * sizeof (IMAGE_SECTION_HEADER);
	memcpy((char *)pefile->pimage_section_headers,
		   section_table,
	       pefile->image_nt_headers.FileHeader.NumberOfSections * sizeof (IMAGE_SECTION_HEADER));
	//__asm int 3;
	// Sanity check the section table 
	for (i = 0; i < pefile->image_nt_headers.FileHeader.NumberOfSections; i++)
	{
		IMAGE_SECTION_HEADER *sechdr = &pefile->pimage_section_headers[i];
		if (sechdr->PointerToRawData + sechdr->SizeOfRawData > input->size
			|| sechdr->VirtualAddress + sechdr->Misc.VirtualSize > pefile->image_nt_headers.OptionalHeader.SizeOfImage)
		{
			if (pefile->boot_stub_data != NULL)
				free_buffer(&pefile->boot_stub_data);
			free(pefile);
			return NULL;
		}
	}

	// Determine where the first section data starts.
	for (i = 0; i < pefile->image_nt_headers.FileHeader.NumberOfSections; i++) {
		DWORD ptrd = pefile->pimage_section_headers[i].PointerToRawData;

		if (ptrd != 0) {
			if (first_section_offset == 0 || ptrd < first_section_offset)
				first_section_offset = ptrd;
		}
	}

	// Compute the amount of header remainder data, if any.  
	// I define header remainder data to be anything non-zero that comes
	// after the end of the section headers and before the start of the first section.
	// This area can hold legitimate data such as import tables, tls structures, etc.
	for (i = first_section_offset - 1; i >= header_size && ibuf[i] == 0; i--)
		;
	pefile->header_remainder_data->size = i - header_size + 1;
	pefile->header_remainder_data->buf = (char *)ecalloc(pefile->header_remainder_data->size, 1);
	memcpy(pefile->header_remainder_data->buf, &ibuf[header_size], pefile->header_remainder_data->size);

	pefile->sections_data->size = input->size - first_section_offset;
	pefile->sections_data->buf = (char *)ecalloc(pefile->sections_data->size, 1);
	memcpy(pefile->sections_data->buf, &ibuf[first_section_offset], pefile->sections_data->size);

    pefile->imports = parse_imports(pefile);

    pefile->exports = parse_exports(pefile);

	build_sections_quicklook(pefile);
	pefile->first_section_offset = get_first_section_offset(pefile);

	return pefile;
}

static imported_dll_t *parse_imports(pefile_t *pefile)
{
    imported_dll_t *dll_list = NULL;
    imported_dll_t *curr_dll = NULL;
    IMAGE_IMPORT_DESCRIPTOR *import_descriptor_table;
    IMAGE_DATA_DIRECTORY *import_directory_entry;
    int i = 0;
    
    nASSERT('PE10', pefile != NULL);

    import_directory_entry = (IMAGE_DATA_DIRECTORY *)&pefile->image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    
    if (import_directory_entry->Size == 0)
        return NULL;

    import_descriptor_table = (IMAGE_IMPORT_DESCRIPTOR *)rva_to_ptr(pefile, import_directory_entry->VirtualAddress);
    if (import_descriptor_table == NULL)
        return NULL;

    for (i = 0; import_descriptor_table[i].Name != 0; i++)
    {
        IMAGE_THUNK_DATA *function_thunks;
        import_item_t *item = NULL;
        char *name;
        DWORD current_iat_rva;

        if (dll_list == NULL)
        {
            dll_list = ecalloc(1, sizeof *dll_list);
            curr_dll = dll_list;
        }
        else
        {
            curr_dll->next = ecalloc(1, sizeof *curr_dll);
            curr_dll = curr_dll->next;
        }
        
        name = (char *)rva_to_ptr(pefile, import_descriptor_table[i].Name);
        if (name != NULL)
            curr_dll->name = strdup(name);

        function_thunks = (IMAGE_THUNK_DATA *)rva_to_ptr(pefile, import_descriptor_table[i].OriginalFirstThunk);
        
        current_iat_rva = import_descriptor_table[i].FirstThunk;

        while (function_thunks != NULL && function_thunks->u1.Function != 0)
        {
            if (curr_dll->items == NULL)
            {
                item = ecalloc(1, sizeof *item);
                curr_dll->items = item;
            }
            else
            {
                item->next = ecalloc(1, sizeof *item);
                item = item->next;
            }
            if (function_thunks->u1.Function & 0x80000000)
            {
                item->import_type = IMPORT_TYPE_ORDINAL;
                item->u.ordinal = (WORD)0x0000FFFF & function_thunks->u1.Ordinal;
            }
            else
            {
                IMAGE_IMPORT_BY_NAME *hintNameTablePtr;
                item->import_type = IMPORT_TYPE_NAME;
                hintNameTablePtr = (IMAGE_IMPORT_BY_NAME *)rva_to_ptr(pefile, function_thunks->u1.Function);
                if (hintNameTablePtr != NULL)
                    item->u.name = strdup(hintNameTablePtr->Name);
            }

            item->iat_rva = current_iat_rva;
            current_iat_rva += sizeof (DWORD);
            function_thunks++;
        }
        
    }

    return dll_list;
}

static exports_t *parse_exports(pefile_t *pefile)
{
    exports_t *retval = NULL;

    nASSERT('PE20', pefile != NULL);

   	if (pefile->image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size != 0)
	{
		DWORD export_dir_size = pefile->image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
		DWORD export_dir_rva = pefile->image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

		char *export_dir_ptr = rva_to_ptr(pefile, export_dir_rva);
		
		if (export_dir_ptr != NULL) {
			DWORD i;
			DWORD *functionRvas;
			DWORD *nameRvas;
			WORD *ordinalTable;

			retval = emalloc(sizeof *pefile->exports);
			memcpy(&retval->image_export_directory, export_dir_ptr, sizeof (IMAGE_EXPORT_DIRECTORY));

			retval->exports = ecalloc(retval->image_export_directory.NumberOfFunctions, sizeof (dll_export_t));

			functionRvas = (DWORD *)rva_to_ptr(pefile, retval->image_export_directory.AddressOfFunctions);
			nameRvas = (DWORD *)rva_to_ptr(pefile, retval->image_export_directory.AddressOfNames);
			ordinalTable = (WORD *)rva_to_ptr(pefile, retval->image_export_directory.AddressOfNameOrdinals);

			if (functionRvas !=  NULL) {
				for (i = 0; i < retval->image_export_directory.NumberOfFunctions; i++)
				{
					dll_export_t *exp = &retval->exports[i];
					exp->export_type = EXPORT_TYPE_ORDINAL;
					exp->nameord.ordinal = i;
					if (functionRvas[i] >= export_dir_rva && functionRvas[i] < export_dir_rva + export_dir_size) {
						exp->export_address_type = EXPORT_ADDRESS_TYPE_FORWARDER_RVA;
						exp->rva.forwarder_rva = functionRvas[i];
					} else {
						exp->export_address_type = EXPORT_ADDRESS_TYPE_RVA;
						exp->rva.rva = functionRvas[i];
					}
				}
				if (nameRvas != NULL && ordinalTable != NULL)
				{
					for (i = 0; i < retval->image_export_directory.NumberOfNames; i++)
					{
						char *name = rva_to_ptr(pefile, nameRvas[i]);
						WORD ord = ordinalTable[i];
						dll_export_t *exp;
						if (ord < retval->image_export_directory.NumberOfFunctions)
						{
							exp = &retval->exports[ord];
							exp->export_type = EXPORT_TYPE_NAME;
							exp->nameord.name = name;
						}
					}
				}
			}
		}
	}

    return retval;
}

static void build_sections_quicklook(pefile_t *pefile)
{
	sections_quicklook_t *sql_list = NULL;
	sections_quicklook_t *sql_ptr;
	int i;

	nASSERT('PE30', pefile != NULL);

	for (i = 0; i < pefile->image_nt_headers.FileHeader.NumberOfSections; i++) {
		IMAGE_SECTION_HEADER *sec_hdr = &pefile->pimage_section_headers[i];
		if (sql_list == NULL) {
			sql_list = ecalloc(1, sizeof *sql_list);
			sql_ptr = sql_list;
		} else {
			for (sql_ptr = sql_list; sql_ptr->next != NULL; sql_ptr = sql_ptr->next)
				;
			sql_ptr->next = ecalloc(1, sizeof *sql_list);
			sql_ptr = sql_ptr->next;
		}

		sql_ptr->RVA.Start = sec_hdr->VirtualAddress;
		sql_ptr->RVA.End = sec_hdr->VirtualAddress + sec_hdr->Misc.VirtualSize;
		sql_ptr->VA.Start = sql_ptr->RVA.Start + pefile->image_nt_headers.OptionalHeader.ImageBase;
		sql_ptr->VA.End = sql_ptr->RVA.End + pefile->image_nt_headers.OptionalHeader.ImageBase;
		sql_ptr->Raw.Start = sec_hdr->PointerToRawData;
		sql_ptr->Raw.End = sec_hdr->PointerToRawData + sec_hdr->SizeOfRawData;
		sql_ptr->Ptr.Start = get_section_data(pefile, i, NULL);
		sql_ptr->Ptr.End = sql_ptr->Ptr.Start + sec_hdr->SizeOfRawData;

		sql_ptr->RVA.toVA = pefile->image_nt_headers.OptionalHeader.ImageBase;
		sql_ptr->RVA.toRaw = sql_ptr->Raw.Start - sql_ptr->RVA.Start;
		sql_ptr->RVA.toPtr = sql_ptr->Ptr.Start - sql_ptr->RVA.Start;
		
		sql_ptr->VA.toRVA = sql_ptr->RVA.Start - sql_ptr->VA.Start;
		sql_ptr->VA.toRaw = sql_ptr->Raw.Start - sql_ptr->VA.Start;
		sql_ptr->VA.toPtr = sql_ptr->Ptr.Start - sql_ptr->VA.Start;

		sql_ptr->Raw.toRVA = sql_ptr->RVA.Start - sql_ptr->Raw.Start;
		sql_ptr->Raw.toVA = sql_ptr->VA.Start - sql_ptr->Raw.Start;
		sql_ptr->Raw.toPtr = sql_ptr->Ptr.Start - sql_ptr->Raw.Start;

		sql_ptr->Ptr.toRVA = sql_ptr->RVA.Start - (DWORD) sql_ptr->Ptr.Start;
		sql_ptr->Ptr.toVA = sql_ptr->VA.Start - (DWORD) sql_ptr->Ptr.Start;
		sql_ptr->Ptr.toRaw = sql_ptr->Raw.Start - (DWORD) sql_ptr->Ptr.Start;

		sql_ptr->sectiondata_offset = raw_to_sections_data_offset(pefile, sql_ptr->Raw.Start);

		sql_ptr->isCode = pefile->pimage_section_headers[i].Characteristics & IMAGE_SCN_CNT_CODE;
	}

	pefile->sections_quicklook = sql_list;
}

void dump_pefile(pefile_t *pefile, const char *output_filename)
{
	buflist_t *buflist = NULL;
	DWORD header_size;
	DWORD padding_size;
	void *foo;

	nASSERT('PE40', pefile != NULL);
	nASSERT('PE41', output_filename != NULL);

	bufferlist_add(&buflist, &pefile->image_dos_header, sizeof (IMAGE_DOS_HEADER));

	bufferlist_add(&buflist, pefile->boot_stub_data->buf, pefile->boot_stub_data->size);

	bufferlist_add(&buflist, &pefile->image_nt_headers, sizeof (IMAGE_NT_HEADERS));

	bufferlist_add(&buflist, pefile->pimage_section_headers, 
		pefile->image_nt_headers.FileHeader.NumberOfSections * sizeof (IMAGE_SECTION_HEADER));

	bufferlist_add(&buflist, pefile->header_remainder_data->buf, pefile->header_remainder_data->size);

	header_size = get_header_size(pefile);

	padding_size = pad_to_alignment(header_size, pefile->image_nt_headers.OptionalHeader.FileAlignment)
		           - header_size;

	if (padding_size > 0)
		bufferlist_add(&buflist, NULL, padding_size);

	bufferlist_add(&buflist, pefile->sections_data->buf, pefile->sections_data->size);

	write_buflist_to_file(buflist, output_filename);
}

static DWORD pad_to_alignment(DWORD offset, DWORD alignment)
{
	return (offset / alignment) * alignment + ((offset % alignment ? 1 : 0) * alignment);
}

/* This function returns the size of the header data
 * header data being, the dos header, boot stub, image nt headers
 * section headers, and header remainder data (if any)
 */
static DWORD get_header_size(pefile_t *pefile)
{
	DWORD retval;
	nASSERT('PE50', pefile != NULL);
	
	retval = pefile->image_dos_header.e_lfanew; 
	retval += sizeof (IMAGE_NT_HEADERS);
	retval += sizeof (IMAGE_SECTION_HEADER) * pefile->image_nt_headers.FileHeader.NumberOfSections;
	retval += pefile->header_remainder_data->size;

	return retval;
}

/* This function determines the first offset of section data */
DWORD get_first_section_offset(pefile_t *pefile)
{
	int i;
	DWORD retval = 0;

	nASSERT('PE60', pefile != NULL);

	for (i = 0; i < pefile->image_nt_headers.FileHeader.NumberOfSections; i++) {
		DWORD ptrd = pefile->pimage_section_headers[i].PointerToRawData;
		
		if (ptrd != 0) {
			if (retval == 0 || ptrd < retval)
				retval = ptrd;
		}
	}

	return retval;
}

/* This function determines the first rva of section data */
static DWORD get_first_section_rva(pefile_t *pefile)
{
	int i;
	DWORD retval = 0;

	nASSERT('PE70', pefile != NULL);

	for (i = 0; i < pefile->image_nt_headers.FileHeader.NumberOfSections; i++) {
		DWORD ptrd = pefile->pimage_section_headers[i].VirtualAddress;
		
		if (ptrd != 0) {
			if (retval == 0 || ptrd < retval)
				retval = ptrd;
		}
	}

	return retval;
}

/* this funciton calculates the amount of padding in between the 
 * header and the section data
 */
static int get_header_padding_size(pefile_t *pefile)
{
	int retval;

	nASSERT('PE80', pefile != NULL);

	retval = get_first_section_offset(pefile);
	if (retval == 0)
		retval = pefile->image_nt_headers.OptionalHeader.SizeOfHeaders;
	retval -= get_header_size(pefile);

	return retval;
}

/* this function finds the next availible RVA for a new section */
static DWORD get_next_availible_rva(pefile_t *pefile)
{
	int i;
	DWORD end = 0;
	nASSERT('PE90', pefile != NULL);

	for (i = 0; i < pefile->image_nt_headers.FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER sechdr = &pefile->pimage_section_headers[i];

		if (sechdr->VirtualAddress + sechdr->Misc.VirtualSize > end)
			end = sechdr->VirtualAddress + sechdr->Misc.VirtualSize;
	}

	if (end == 0)
		return pefile->image_nt_headers.OptionalHeader.SectionAlignment;
	else
		return pad_to_alignment(end, pefile->image_nt_headers.OptionalHeader.SectionAlignment);
}

/* this function finds the next availible offset for a new section */
static DWORD get_next_availible_offset(pefile_t *pefile)
{
	int i;
	DWORD end = 0;
	nASSERT('PEA0', pefile != NULL);

	for (i = 0; i < pefile->image_nt_headers.FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER sechdr = &pefile->pimage_section_headers[i];

		if (sechdr->PointerToRawData + sechdr->SizeOfRawData > end)
			end = sechdr->PointerToRawData + sechdr->SizeOfRawData;
	}

	if (end == 0)
		return pefile->image_nt_headers.OptionalHeader.SizeOfHeaders;
	else
		return pad_to_alignment(end, pefile->image_nt_headers.OptionalHeader.FileAlignment);
}

/* this function allocates a new section table and FREEs the old one
 * it returns a pointer to the new section header
 */
static PIMAGE_SECTION_HEADER grow_section_table(pefile_t *pefile)
{
	IMAGE_SECTION_HEADER *new_section_table;
	size_t oldsize, newsize;

	nASSERT('PEB0', pefile != NULL);
	
	oldsize = pefile->image_nt_headers.FileHeader.NumberOfSections * sizeof (IMAGE_SECTION_HEADER);
	newsize = oldsize + sizeof (IMAGE_SECTION_HEADER);

	new_section_table = ecalloc(newsize, 1);
	if (oldsize > 0) {
		memcpy(new_section_table, pefile->pimage_section_headers, oldsize);
		efree(pefile->pimage_section_headers);
	}
	pefile->pimage_section_headers = new_section_table;
	
	return &new_section_table[pefile->image_nt_headers.FileHeader.NumberOfSections++];
}

/* This function will add the new section data to the pefile.
 * It will allocate a new data buffer and free the old one.
 * it will add padding to the end of the old data if needed, because
 * the new data needs to start at a file alignment.
 */
static char *grow_sections_data(pefile_t *pefile, buffer_t *newdata, DWORD eof_size)
{
	buflist_t *buflist = NULL;
	DWORD pre_padding_size, post_padding_size;
	buffer_t *newbuf;
	buffer_t *eofdatabuf;
	char *retval;

	nASSERT('PEC0', pefile != NULL);
	nASSERT('PEC1', newdata != NULL);

	if (pefile->sections_data == NULL) 
	{
		DWORD newsize = pad_to_alignment(newdata->size, pefile->image_nt_headers.OptionalHeader.FileAlignment);
		pefile->sections_data = new_buffer(newsize);
		memcpy(pefile->sections_data->buf, newdata->buf, newdata->size);
		return pefile->sections_data->buf;
	}

	if (eof_size != 0)
	{
		DWORD offset = pefile->sections_data->size - eof_size;
		char *destbuf = &pefile->sections_data->buf[offset];
		eofdatabuf = new_buffer(eof_size);
		memcpy(eofdatabuf->buf, destbuf, eof_size);
		pefile->sections_data->size -= eof_size;
	}

	bufferlist_add(&buflist, pefile->sections_data->buf, pefile->sections_data->size);

	// first padding is to make sure the new section data starts at a section alignment, not always naturally the case.
	pre_padding_size = pad_to_alignment(pefile->sections_data->size, pefile->image_nt_headers.OptionalHeader.FileAlignment);
	pre_padding_size -= pefile->sections_data->size;
	if (pre_padding_size > 0)
		bufferlist_add(&buflist, NULL, pre_padding_size);

	bufferlist_add(&buflist, newdata->buf, newdata->size);
	
	post_padding_size = pad_to_alignment(newdata->size, pefile->image_nt_headers.OptionalHeader.FileAlignment);
	post_padding_size -= newdata->size;
	if (post_padding_size > 0)
		bufferlist_add(&buflist, NULL, post_padding_size);
	
	if (eof_size != 0)
	{
		bufferlist_add_buffer(&buflist, eofdatabuf);
	}

	newbuf = bufferlist_to_buffer(buflist);
	free_bufferlist(&buflist);
	retval = &newbuf->buf[pefile->sections_data->size + pre_padding_size];
	free_buffer(&pefile->sections_data);
	if (eof_size != 0)
		free_buffer(&eofdatabuf);
	pefile->sections_data = newbuf;

	return retval;
}

// return the amount of end of file data at the end of the pe file (some call this an overlay)
static DWORD get_eof_size(pefile_t *pefile)
{
	int i;
	DWORD end_of_data = 0;

	nASSERT('PED0', pefile != NULL);
	nASSERT('PED1', pefile->sections_data != NULL);
	nASSERT('PED2', pefile->sections_data->buf != NULL);
	nASSERT('PED3', pefile->sections_data->size != 0);

	for (i = 0; i < pefile->image_nt_headers.FileHeader.NumberOfSections; i++)
	{
		DWORD end_of_section = pefile->pimage_section_headers[i].PointerToRawData + pefile->pimage_section_headers[i].SizeOfRawData;
		if (end_of_section > end_of_data)
			end_of_data = end_of_section;
	}

	return pefile->first_section_offset + pefile->sections_data->size - end_of_data;
}

// return a new offset which represents the adjusted location depending on where the 
// specified address is in the file. 
static DWORD adjust_offset(DWORD address, DWORD header_size, DWORD section_data_offset, DWORD remainder_adjustment, DWORD section_adjustment)
{
	if (address < header_size)
		return address;
	else if (address < section_data_offset)
		return address + remainder_adjustment;
	else
		return address + section_adjustment;
}

/* This funciton will update all necessary pointers within a PE file to 
 * point to the new location if adding a section header moved the data
 */
static void adjust_pointers(pefile_t *pefile, DWORD remainder_adjustment, DWORD section_adjustment)
{
	DWORD header_size;
	DWORD first_section_offset;
	DWORD first_section_rva;
	int i;

	header_size = get_header_size(pefile) - remainder_adjustment - pefile->header_remainder_data->size;
	first_section_offset = get_first_section_offset(pefile);
	first_section_rva = get_first_section_rva(pefile);

	// Update section headers
	for (i = 0; i < pefile->image_nt_headers.FileHeader.NumberOfSections; i++) {
		adjust_offset((pefile->pimage_section_headers[i]).PointerToRawData,
		              header_size, first_section_offset, remainder_adjustment, section_adjustment);
	}

	// Update data directory entries
	for (i = 0; i < pefile->image_nt_headers.OptionalHeader.NumberOfRvaAndSizes; i++) {
		PIMAGE_DATA_DIRECTORY idd_entry = &pefile->image_nt_headers.OptionalHeader.DataDirectory[i];
		
		if (idd_entry->VirtualAddress > 0 && idd_entry->VirtualAddress < first_section_rva) {
			DWORD a = adjust_offset(idd_entry->VirtualAddress,
				                                      header_size, first_section_rva, 
													  remainder_adjustment, 0);
			idd_entry->VirtualAddress = a;
		}

		// FIXME:  need to update special directory entries.
	}
}

char *add_virtual_section_to_pefile(pefile_t *pefile, char *name, DWORD size, DWORD characteristics)
{
	buffer_t data;

	data.buf = NULL;
	data.size = 0;

	return inner_add_section_to_pefile(pefile, name, &data, size, characteristics);
}

char *add_section_to_pefile(pefile_t *pefile, const char *name, buffer_t *data, DWORD characteristics)
{
	nASSERT('PEE0', data != NULL);

	return inner_add_section_to_pefile(pefile, name, data, data->size, characteristics);
}

static char *inner_add_section_to_pefile(pefile_t *pefile, char *name, buffer_t *data, DWORD virtual_size, DWORD characteristics)
{
	DWORD first_section_offset;
	DWORD header_size;
	DWORD remainder_adjustment_size;  // how far we need to move the header remainder data
	DWORD section_adjustment_size = 0;    // how far (if any) we need to move the section data
	PIMAGE_SECTION_HEADER new_section_header;
	DWORD file_alignment;      // for quick reference
	char *retval;
	DWORD eof_size;

	nASSERT('PEF0', pefile != NULL);
	nASSERT('PEF1', name != NULL);
	nASSERT('PEF2', data != NULL);

	file_alignment = pefile->image_nt_headers.OptionalHeader.FileAlignment; 

	remainder_adjustment_size = sizeof (IMAGE_SECTION_HEADER);

	eof_size = get_eof_size(pefile);

	// Add a new section header and populate it with as much info as we can at this point
	new_section_header = grow_section_table(pefile);

	strncpy((char *)new_section_header->Name, name, strnlen(name, 8));
	new_section_header->VirtualAddress = get_next_availible_rva(pefile);
	if (data->size > 0) {
		new_section_header->PointerToRawData = get_next_availible_offset(pefile);
		new_section_header->SizeOfRawData = pad_to_alignment(data->size, file_alignment);
	} else {
		new_section_header->PointerToRawData = 0;
		new_section_header->SizeOfRawData = 0;
	}
	new_section_header->Misc.VirtualSize = virtual_size;
	new_section_header->Characteristics = characteristics;
	
	if (data->size > 0)
		retval = grow_sections_data(pefile, data, eof_size);
	else
		retval = NULL;

	// FIXME: this is only for initialized data and executable charactaristics.
	pefile->image_nt_headers.OptionalHeader.SizeOfInitializedData += new_section_header->SizeOfRawData;

	pefile->image_nt_headers.OptionalHeader.SizeOfImage = new_section_header->VirtualAddress 
		+ pad_to_alignment(new_section_header->Misc.VirtualSize, pefile->image_nt_headers.OptionalHeader.SectionAlignment);
	
	// determine if we need to move the section data further down
	// in the file to make room for the new section header
	if (get_header_padding_size(pefile) < 0) {
		int i;
		// ASSUMPTION:  the file alignment *should* always be larger than a section header
		section_adjustment_size = pefile->image_nt_headers.OptionalHeader.FileAlignment;
		
		pefile->image_nt_headers.OptionalHeader.SizeOfHeaders += section_adjustment_size;
		
		// Move all section data offsets to the next alignment
		for (i = 0; i < pefile->image_nt_headers.FileHeader.NumberOfSections; i++)
		{
			if (pefile->pimage_section_headers[i].PointerToRawData != 0)
			{
				pefile->pimage_section_headers[i].PointerToRawData += section_adjustment_size;
			}
		}
	}

	first_section_offset = get_first_section_offset(pefile);
	header_size = get_header_size(pefile);

	// Adjust all pointers in the file to point to moved locations, if their locations
	// have been moved by adding the new section header
	adjust_pointers(pefile, remainder_adjustment_size, section_adjustment_size);

	return retval;
}

/* This function will return a section number associated with a given name */
int lookup_section_name(pefile_t *pefile, const char *name)
{
	int i;

	nASSERT('PEa0', pefile != NULL);
	nASSERT('PEa1', name != NULL);

	for (i = 0; i < pefile->image_nt_headers.FileHeader.NumberOfSections; i++)
		if (strncmp(name, pefile->pimage_section_headers[i].Name, 8) == 0)
			return i;

	return -1;
}

/* this function will return a section number which contains the data pointed
 * to by the specified RVA */
int lookup_section_rva(pefile_t *pefile, DWORD rva)
{
	int i;

	nASSERT('PEb0', pefile != NULL);

	for (i = 0; i < pefile->image_nt_headers.FileHeader.NumberOfSections; i++)
	{
		if (rva >= pefile->pimage_section_headers[i].VirtualAddress 
			&& rva < pefile->pimage_section_headers[i].VirtualAddress + pefile->pimage_section_headers[i].Misc.VirtualSize)
		{
			return i;
		}
	}

	return -1;
}

int lookup_section_raw(pefile_t *pefile, DWORD raw)
{
	int i;

	nASSERT('PEc0', pefile != NULL);

	for (i = 0; i < pefile->image_nt_headers.FileHeader.NumberOfSections; i++)
	{
		if (raw >= pefile->pimage_section_headers[i].PointerToRawData
			&& raw < pefile->pimage_section_headers[i].PointerToRawData + pefile->pimage_section_headers[i].SizeOfRawData)
		{
			return i;
		}
	}
	
	return -1;
}

/* This function will return a pointer to section data */

char *generate_section_name(pefile_t *pefile)
{
	char *name;
	int i;

	nASSERT('PEd0', pefile != NULL);

	name = emalloc(9);
	name[8] = '\0';

	for (i = 0; i < 100; i++) {
		if (i == 0)
			snprintf(name, 8, ".nick");
		else
			snprintf(name, 8, ".nick%d", i);
		if (lookup_section_name(pefile, name) == -1)
			return name;
	}

	efree(name);
	return NULL;
}

void free_pefile(pefile_t **pefile)
{
	nASSERT('PEe0', pefile != NULL);
	nASSERT('PEe1', *pefile != NULL);

	free_buffer(&(*pefile)->boot_stub_data);
	efree((*pefile)->pimage_section_headers);
	if ((*pefile)->header_remainder_data != NULL)
		free_buffer(&(*pefile)->header_remainder_data);
	free_buffer(&(*pefile)->sections_data);
	efree(*pefile);
	*pefile = NULL;
}

#ifndef MIN
#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))
#endif /*MIN*/

// This function will create a buffer which contains all
// the section data as it would look in memory after
// loading.
buffer_t *sections_data_expand(pefile_t *pefile)
{
	int i;
	DWORD first_section_offset;
	DWORD first_section_rva;
	buffer_t *buffer;

	nASSERT('PEf0', pefile != NULL);

	first_section_offset = get_first_section_offset(pefile);
	if (first_section_offset > pefile->image_nt_headers.OptionalHeader.SizeOfImage)
		return NULL;
	
	first_section_rva = get_first_section_rva(pefile);
	if (first_section_rva > pefile->image_nt_headers.OptionalHeader.SizeOfImage)
		return NULL;
	
	buffer = new_buffer(pefile->image_nt_headers.OptionalHeader.SizeOfImage - first_section_rva);
	nASSERT('PEf1', buffer != NULL);

	for (i = 0; i < pefile->image_nt_headers.FileHeader.NumberOfSections; i++) {
		DWORD copy_amount = MIN(pefile->pimage_section_headers[i].SizeOfRawData, pefile->pimage_section_headers[i].Misc.VirtualSize);
		DWORD dest_offset = pefile->pimage_section_headers[i].VirtualAddress - first_section_rva;
		DWORD src_offset = pefile->pimage_section_headers[i].PointerToRawData - first_section_offset;

		if (dest_offset + copy_amount > buffer->size) {
			free_buffer(&buffer);
			return NULL;
		}
		
		memcpy(&buffer->buf[dest_offset], &pefile->sections_data->buf[src_offset], copy_amount);
	}

	return buffer;
}

pefile_t *make_new_pefile(DWORD file_alignment)
{
	pefile_t *pefile;

	nASSERT('PEg0', file_alignment > 0);

	pefile = ecalloc(sizeof *pefile, 1);

	pefile->boot_stub_data = new_buffer(0);
	pefile->header_remainder_data = new_buffer(0);
	
	pefile->image_dos_header.e_magic = IMAGE_DOS_SIGNATURE;
	pefile->image_dos_header.e_cblp = 0x0090;
	pefile->image_dos_header.e_cp = 0x0003;
	pefile->image_dos_header.e_cparhdr = 0x0004;
	pefile->image_dos_header.e_maxalloc = 0xFFFF;
	pefile->image_dos_header.e_sp = 0x00B8;
	pefile->image_dos_header.e_lfarlc = 0x0040;
	pefile->image_dos_header.e_lfanew = 0x00000040;
	
	pefile->image_nt_headers.Signature = IMAGE_NT_SIGNATURE;
	
	pefile->image_nt_headers.FileHeader.Machine = 0x14C;
	pefile->image_nt_headers.FileHeader.SizeOfOptionalHeader = 0xE0;
	pefile->image_nt_headers.FileHeader.Characteristics = 0x103;

	pefile->image_nt_headers.OptionalHeader.Magic = 0x10B;
	pefile->image_nt_headers.OptionalHeader.MajorLinkerVersion = 0x08;
	pefile->image_nt_headers.OptionalHeader.BaseOfCode = 0x1000;
	pefile->image_nt_headers.OptionalHeader.BaseOfData = 0x1000;
	pefile->image_nt_headers.OptionalHeader.ImageBase = 0x00400000;
	pefile->image_nt_headers.OptionalHeader.SectionAlignment = 0x1000;
	pefile->image_nt_headers.OptionalHeader.FileAlignment = file_alignment;
	pefile->image_nt_headers.OptionalHeader.MajorOperatingSystemVersion = 0x0004;
	pefile->image_nt_headers.OptionalHeader.MajorSubsystemVersion = 0x0004;
	pefile->image_nt_headers.OptionalHeader.SizeOfImage = 0x1000;
	pefile->image_nt_headers.OptionalHeader.SizeOfHeaders = file_alignment;
	pefile->image_nt_headers.OptionalHeader.Subsystem = 0x0003;
	pefile->image_nt_headers.OptionalHeader.SizeOfStackReserve = 0x00100000;
	pefile->image_nt_headers.OptionalHeader.SizeOfStackCommit = 0x00001000;
	pefile->image_nt_headers.OptionalHeader.SizeOfHeapReserve = 0x00100000;
	pefile->image_nt_headers.OptionalHeader.SizeOfHeapCommit = 0x00001000;
	pefile->image_nt_headers.OptionalHeader.NumberOfRvaAndSizes = 0x10;

	return pefile;
}

DWORD get_datadir_offset(pefile_t *pefile, int entry_num)
{
	DWORD retval;

	nASSERT('PEh0', pefile != NULL);
	nASSERT('PEh1', entry_num > 0);

	retval = ((char *)&pefile->image_nt_headers.OptionalHeader.DataDirectory[entry_num]) - ((char *)&pefile->image_nt_headers);
	retval += pefile->image_dos_header.e_lfanew;

	return retval;
}

char *get_section_data(pefile_t *pefile, int section_number, size_t *size)
{
	char *retval;

	nASSERT('PEi0', pefile != NULL);

	if (section_number >= pefile->image_nt_headers.FileHeader.NumberOfSections)
		return NULL;

	retval = &pefile->sections_data->buf[pefile->pimage_section_headers[section_number].PointerToRawData - get_first_section_offset(pefile)];

	if (size != NULL)
		*size = pefile->pimage_section_headers[section_number].SizeOfRawData;

	return retval;
}

DWORD rva_to_va(pefile_t *pefile, DWORD rva)
{
	nASSERT('PEj0', pefile != NULL);

	return rva + pefile->image_nt_headers.OptionalHeader.ImageBase;
}

DWORD va_to_rva(pefile_t *pefile, DWORD va)
{
	nASSERT('PEk0', pefile != NULL);
	
	return va - pefile->image_nt_headers.OptionalHeader.ImageBase;
}

DWORD rva_to_raw(pefile_t *pefile, DWORD rva)
{
	int section_number;
	DWORD retval;

	nASSERT('PEl0', pefile != NULL);

	section_number = lookup_section_rva(pefile, rva);
	if (section_number == -1)
		return -1;

	retval = (rva - pefile->pimage_section_headers[section_number].VirtualAddress) + pefile->pimage_section_headers[section_number].PointerToRawData;
	if (retval >= pefile->pimage_section_headers[section_number].PointerToRawData + pefile->pimage_section_headers[section_number].SizeOfRawData)
		return -1;
	else
		return retval;
}

DWORD raw_to_sections_data_offset(pefile_t *pefile, DWORD raw)
{
	DWORD first_section_offset;
	nASSERT('PEm0', pefile != NULL);

	first_section_offset = get_first_section_offset(pefile);

	if (raw < 0 || raw > pefile->sections_data->size + first_section_offset)
		return -1;
	
	return raw - first_section_offset;
}

char *raw_to_ptr(pefile_t *pefile, DWORD raw)
{
	DWORD sections_data_offset = raw_to_sections_data_offset(pefile, raw);

	if (sections_data_offset == -1)
		return NULL;

	return &pefile->sections_data->buf[sections_data_offset];
}

char *rva_to_ptr(pefile_t *pefile, DWORD rva)
{
	nASSERT('PEn0', pefile != NULL);

	return raw_to_ptr(pefile, rva_to_raw(pefile, rva));
}

char *va_to_ptr(pefile_t *pefile, DWORD va)
{
	nASSERT('PEo0', pefile != NULL);

	return rva_to_ptr(pefile, va_to_rva(pefile, va));
}

DWORD ptr_to_sections_data_offset(pefile_t *pefile, char *ptr)
{
	nASSERT('PEp0', pefile != NULL);
	nASSERT('PEp1', ptr != NULL);

	return ptr - pefile->sections_data->buf;
}

DWORD sections_data_offset_to_raw(pefile_t *pefile, DWORD offset)
{
	nASSERT('PEq0', pefile != NULL);

	return offset + get_first_section_offset(pefile);
}

DWORD raw_to_rva(pefile_t *pefile, DWORD raw)
{
	int section_number;

	nASSERT('PEr0', pefile != NULL);

	section_number = lookup_section_raw(pefile, raw);
	if (section_number == -1)
		return -1;

	return (raw - pefile->pimage_section_headers[section_number].PointerToRawData)
		   + pefile->pimage_section_headers[section_number].VirtualAddress;
}

DWORD ptr_to_va(pefile_t *pefile, char *ptr)
{
	return rva_to_va(pefile, 
				raw_to_rva(pefile, 
					sections_data_offset_to_raw(pefile, 
						ptr_to_sections_data_offset(pefile, ptr))));
}

DWORD ptr_to_rva(pefile_t *pefile, char *ptr)
{
	DWORD rva;
	DWORD raw;
	DWORD section_offset;

	section_offset = ptr_to_sections_data_offset(pefile, ptr);
	raw = sections_data_offset_to_raw(pefile, section_offset);
	rva = raw_to_rva(pefile, raw);
	return rva;
   /* return raw_to_rva(pefile,
            sections_data_offset_to_raw(pefile,
                ptr_to_sections_data_offset(pefile, ptr)));*/
}

BOOL rva_points_to_code(pefile_t *pefile, DWORD rva)
{
	int section;
	DWORD dwIATVirtualAddress;
	DWORD dwIATSize;

	nASSERT('PEs0', pefile != NULL);

	section = lookup_section_rva(pefile, rva);
	if (section == -1)
		return FALSE;

	dwIATVirtualAddress = pefile->image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
	dwIATSize = pefile->image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;

	if (rva >= dwIATVirtualAddress && rva < dwIATVirtualAddress + dwIATSize)
		return FALSE;

	return pefile->pimage_section_headers[section].Characteristics & IMAGE_SCN_CNT_CODE;
}

BOOL va_points_to_code(pefile_t *pefile, DWORD va)
{
	return rva_points_to_code(pefile, va_to_rva(pefile, va));
}

BOOL rva_points_to_initialized_data(pefile_t *pefile, DWORD rva)
{
	int section;
	DWORD dwIATVirtualAddress;
	DWORD dwIATSize;

	nASSERT('PEt0', pefile != NULL);

	section = lookup_section_rva(pefile, rva);
	if (section == -1)
		return FALSE;

	dwIATVirtualAddress = pefile->image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
	dwIATSize = pefile->image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;

	if (rva >= dwIATVirtualAddress && rva < dwIATVirtualAddress + dwIATSize)
		return FALSE;

	return pefile->pimage_section_headers[section].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA;
}

BOOL va_points_to_initialized_data(pefile_t *pefile, DWORD va)
{
	return rva_points_to_initialized_data(pefile, va_to_rva(pefile, va));
}

DWORD ql_rva_to_raw(pefile_t *pefile, DWORD rva)
{
	sections_quicklook_t *sql;

	//nASSERT(pefile != NULL);

	for (sql = pefile->sections_quicklook; sql != NULL; sql = sql->next)
	{
		if (rva >= sql->RVA.Start && rva < sql->RVA.End)
		{ 
			if (sql->Raw.Start < sql->Raw.End)
			{
				DWORD retval = rva + sql->RVA.toRaw;
				if (retval < sql->Raw.Start || retval >= sql->Raw.End)
					return -1;
				else 
					return rva + sql->RVA.toRaw;
			}
			else
				return -1;
		}
	}

	return -1;
}

DWORD ql_raw_to_sections_data_offset(pefile_t *pefile, DWORD raw)
{
	//nASSERT(pefile != NULL);

	return raw - pefile->first_section_offset;
}

BOOL ql_rva_points_to_code(pefile_t *pefile, DWORD rva)
{
	sections_quicklook_t *sql;

	DWORD dwIATVirtualAddress;
	DWORD dwIATSize;

	for (sql = pefile->sections_quicklook; sql != NULL; sql = sql->next)
	{
		if (rva >= sql->RVA.Start && rva < sql->RVA.End)
		{
			if (!sql->isCode)
				return FALSE;

			dwIATVirtualAddress = pefile->image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
			dwIATSize = pefile->image_nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;

			if (rva >= dwIATVirtualAddress && rva < dwIATVirtualAddress + dwIATSize)
				return FALSE;

			return TRUE;
		}
	}
	
	return FALSE;
}

BOOL ql_va_points_to_code(pefile_t *pefile, DWORD va)
{
	return ql_rva_points_to_code(pefile, va_to_rva(pefile, va));
}

char *ql_rva_to_ptr(pefile_t *pefile, DWORD rva)
{
	sections_quicklook_t *sql;

	for (sql = pefile->sections_quicklook; sql != NULL; sql = sql->next)
	{
		if (rva >= sql->RVA.Start && rva < sql->RVA.End)
			return rva + sql->RVA.toPtr;
	}

	return NULL;
}

char *ql_va_to_ptr(pefile_t *pefile, DWORD va)
{
	return ql_rva_to_ptr(pefile, va_to_rva(pefile, va));
}