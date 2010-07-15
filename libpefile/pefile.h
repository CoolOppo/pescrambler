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

#ifndef PEFILE_H
#define PEFILE_H

#include <windows.h>
#include "buffers.h"

typedef enum {
    IMPORT_TYPE_NAME,
    IMPORT_TYPE_ORDINAL,
    IMPORT_TYPE_FORWARD
} import_type_t;

typedef struct import_item {
    struct import_item *next;
    import_type_t import_type;
    union {
        char *forwarder_string;
        WORD ordinal;
        char *name;
    } u;
    DWORD iat_rva;
} import_item_t;

typedef struct imported_dll {
    struct imported_dll *next;
    import_item_t *items;
    char *name;
} imported_dll_t;

typedef enum {
	EXPORT_TYPE_NAME,
	EXPORT_TYPE_ORDINAL
} export_type_t;

typedef enum {
	EXPORT_ADDRESS_TYPE_RVA,
	EXPORT_ADDRESS_TYPE_FORWARDER_RVA
} export_address_type_t;

typedef struct dll_export {
	export_type_t export_type;
	union {
		char *name;
		WORD ordinal;
	} nameord;
	export_address_type_t export_address_type;
	union {
		DWORD rva;
		DWORD forwarder_rva;
	} rva;
} dll_export_t;

typedef struct {
	IMAGE_EXPORT_DIRECTORY image_export_directory;
	dll_export_t *exports;
} exports_t;

struct section_view {
	DWORD Start;
	DWORD End;
	int toVA;
	int toRVA;
	int toRaw;
	char *toPtr;
};

typedef struct sections_quicklook_s {
	struct sections_quicklook_s *next;
	struct section_view VA;
	struct section_view RVA;
	struct section_view Raw;
	struct {
		char *Start;
		char *End;
		char *toVA;
		char *toRVA;
		char *toRaw;
	} Ptr;
	DWORD sectiondata_offset;
	BOOL isCode;
} sections_quicklook_t;

typedef struct {
	IMAGE_DOS_HEADER image_dos_header;
	buffer_t *boot_stub_data;
	IMAGE_NT_HEADERS image_nt_headers;
	PIMAGE_SECTION_HEADER pimage_section_headers;
	buffer_t *header_remainder_data;
	buffer_t *sections_data;
    imported_dll_t *imports;
	exports_t *exports;
	// Quicklook additions
	sections_quicklook_t *sections_quicklook;
	DWORD first_section_offset;
} pefile_t;

BOOL mz_quick_check(char *filename);

pefile_t *parse_pefile(buffer_t *buffer);
void dump_pefile(pefile_t *pefile, char *output_filename);
char *add_section_to_pefile(pefile_t *pefile, char *name, buffer_t *data, DWORD characteristics);
char *generate_section_name(pefile_t *pefile);
int lookup_section_name(pefile_t *pefile, const char *name);
char *get_section_data(pefile_t *pefile, int section_number, size_t *size);
int lookup_section_rva(pefile_t *pefile, DWORD rva);
void free_pefile(pefile_t **pefile);
DWORD get_first_section_offset(pefile_t *pefile);
buffer_t *sections_data_expand(pefile_t *pefile);
pefile_t *make_new_pefile(DWORD file_alignment);
char *add_virtual_section_to_pefile(pefile_t *pefile, char *name, DWORD size, DWORD characteristics);
DWORD get_datadir_offset(pefile_t *pefile, int entry_num);
int lookup_section_raw(pefile_t *pefile, DWORD raw);

DWORD rva_to_va(pefile_t *pefile, DWORD rva);
DWORD va_to_rva(pefile_t *pefile, DWORD va);
DWORD rva_to_raw(pefile_t *pefile, DWORD rva);
char *raw_to_ptr(pefile_t *pefile, DWORD raw);
char *rva_to_ptr(pefile_t *pefile, DWORD rva);
char *va_to_ptr(pefile_t *pefile, DWORD va);
DWORD raw_to_sections_data_offset(pefile_t *pefile, DWORD raw);
DWORD ptr_to_va(pefile_t *pefile, char *ptr);
DWORD ptr_to_rva(pefile_t *pefile, char *ptr);
DWORD raw_to_rva(pefile_t *pefile, DWORD raw);
DWORD sections_data_offset_to_raw(pefile_t *pefile, DWORD offset);
DWORD ptr_to_sections_data_offset(pefile_t *pefile, char *ptr);

BOOL va_points_to_code(pefile_t *pefile, DWORD va);
BOOL rva_points_to_initialized_data(pefile_t *pefile, DWORD rva);
BOOL va_points_to_initialized_data(pefile_t *pefile, DWORD va);

// quicklook api
DWORD ql_rva_to_raw(pefile_t *pefile, DWORD rva);
DWORD ql_raw_to_sections_data_offset(pefile_t *pefile, DWORD raw);
DWORD ql_rva_points_to_code(pefile_t *pefile, DWORD rva);
DWORD ql_va_points_to_code(pefile_t *pefile, DWORD va);
char *ql_rva_to_ptr(pefile_t *pefile, DWORD rva);
char *ql_va_to_ptr(pefile_t *pefile, DWORD va);

#endif /* !PEFILE_H */