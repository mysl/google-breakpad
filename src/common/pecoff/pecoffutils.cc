// Copyright (c) 2014 Google Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// pecoffutils.c: Utilities for dealing with PECOFF files
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/pecoff/pecoffutils.h"

namespace google_breakpad {

bool IsValidPeCoff(const uint8_t* obj_base) {
  // at offset 0x3c, find the offset to PE signature
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);

  // XXX: ideally we want to check that the offset is less than the size of the
  // mapped file, but we don't have that information at the moment
  //
  // if(*peOffsetPtr > size) return FALSE;

  // check PE signature
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);
  if (peHeader->mMagic !=  IMAGE_FILE_MAGIC)
    return false;

  return true;
}

int PeCoffClass(const uint8_t* obj_base) {
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);
  uint16_t* peOptionalHeader =  (uint16_t *)((uint32_t*)peHeader + 6);
  // We need to read the magic before we know if this a Pe32OptionalHeader or
  // Pe32PlusOptionalHeader
  return *peOptionalHeader;
}

// Return the breakpad symbol file identifier for the architecture of
// HEADER.
template<typename PeOptionalHeaderType>
const char*
PeCoffObjectFileReader<PeOptionalHeaderType>::Architecture(ObjectFileBase header) {
  const uint8_t* obj_base = (uint8_t*) header;
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);

  uint16_t arch = peHeader->mMachine;
  switch (arch) {
    case IMAGE_FILE_MACHINE_I386:
      return "x86";
    case IMAGE_FILE_MACHINE_ARM:
      return "arm";
    case IMAGE_FILE_MACHINE_MIPS16:
    case IMAGE_FILE_MACHINE_MIPSFPU:
    case IMAGE_FILE_MACHINE_MIPSFPU16:
    case IMAGE_FILE_MACHINE_WCEMIPSV2:
      return "mips";
    case IMAGE_FILE_MACHINE_POWERPC:
    case IMAGE_FILE_MACHINE_POWERPCFP:
      return "ppc";
    case IMAGE_FILE_MACHINE_AMD64:
      return "x86_64";
    default:
      fprintf(stderr, "unrecognized machine architecture: %d\n",
              peHeader->mMachine);
      return NULL;
  }
}

// Get the endianness of HEADER. If it's invalid, return false.
template<typename PeOptionalHeaderType>
bool
PeCoffObjectFileReader<PeOptionalHeaderType>::Endianness(ObjectFileBase header, bool* big_endian) {
  // XXX: Note sure what bigendian PECOFF looks like: characteristics flag
  // IMAGE_FILE_BYTES_REVERSED_HI and/or certain machine types are big-endian
  *big_endian = false;
  return true;
}

//
// Helper functions
//

template<typename PeOptionalHeaderType>
typename PeCoffObjectFileReader<PeOptionalHeaderType>::PeOptionalHeader *
PeCoffObjectFileReader<PeOptionalHeaderType>::GetOptionalHeader(ObjectFileBase header) {
  const uint8_t* obj_base = (uint8_t*) header;
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);
  PeOptionalHeader* peOptionalHeader = (PeOptionalHeader*) ((uint32_t*)peHeader + 6);
  return peOptionalHeader;
}

template<typename PeOptionalHeaderType>
PeSectionHeader*
PeCoffObjectFileReader<PeOptionalHeaderType>::GetSectionTable(ObjectFileBase header) {
  const uint8_t* obj_base = (uint8_t*) header;
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);
  PeOptionalHeader* peOptionalHeader = GetOptionalHeader(header);
  uint64_t peOptionalHeaderOffset = (uint64_t) peOptionalHeader - (uint64_t) obj_base;
  int64_t sectionHeaderOffset = peOptionalHeaderOffset + peHeader->mSizeOfOptionalHeader;
  PeSectionHeader* section_table = (PeSectionHeader*) (obj_base+sectionHeaderOffset);
  return section_table;
}

template<typename PeOptionalHeaderType>
const char *
PeCoffObjectFileReader<PeOptionalHeaderType>::GetStringTable(ObjectFileBase header) {
  const uint8_t* obj_base = (uint8_t*) header;
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);

  // string table immediately follows symbol table
  uint32_t string_table_offset = peHeader->mPointerToSymbolTable + peHeader->mNumberOfSymbols*sizeof(PeSymbol);
  const char *string_table = (char *)obj_base + string_table_offset;
  return string_table;
}

template<class PeOptionalHeaderType>
PeDataDirectory *
PeCoffObjectFileReader<PeOptionalHeaderType>::GetDataDirectoryEntry(ObjectFileBase header, int entry) {
  // locate the data directory, immediately following the optional header
  PeOptionalHeader* peOptionalHeader = GetOptionalHeader(header);
  PeDataDirectory *data_directory = (PeDataDirectory *)((uint32_t *)(&peOptionalHeader->mNumberOfRvaAndSizes) + 1);
  uint32_t data_directory_size = peOptionalHeader->mNumberOfRvaAndSizes;

  // locate the required directory entry, if present
  if (data_directory_size < entry)
    return NULL;

  return &data_directory[entry];
}

template<typename PeOptionalHeaderType>
const uint8_t *
PeCoffObjectFileReader<PeOptionalHeaderType>::ConvertRVAToPointer(ObjectFileBase header,
                                                                  unsigned int rva) {
  // find which section contains the rva to compute it's mapped address
  PeSectionHeader* section_table = GetSectionTable(header);
  for (int s = 0; s < GetNumberOfSections(header); s++) {
    PeSectionHeader* section =  &(section_table[s]);

    if ((rva >= section->VirtualAddress) &&
        (rva < (section->VirtualAddress + section->SizeOfRawData)))
    {
      uint32_t offset = rva - section->VirtualAddress;
      const uint8_t *pointer = GetSectionPointer(header, (Section)section) + offset;
      return pointer;
    }
  }

  fprintf(stderr, "No section containing could be found containing RVA %x\n", rva);
  return NULL;
}

//
//
//

template<typename PeOptionalHeaderType>
int
PeCoffObjectFileReader<PeOptionalHeaderType>::GetNumberOfSections(ObjectFileBase header) {
  const uint8_t* obj_base = (uint8_t*) header;
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);
  return peHeader->mNumberOfSections;
}

// Find the preferred loading address of the binary.
template<typename PeOptionalHeaderType>
typename PeCoffObjectFileReader<PeOptionalHeaderType>::Addr
PeCoffObjectFileReader<PeOptionalHeaderType>::GetLoadingAddress(ObjectFileBase header) {
  PeOptionalHeaderType* peOptionalHeader = GetOptionalHeader(header);
  return peOptionalHeader->mImageBase;
}

template<typename PeOptionalHeaderType>
const typename PeCoffObjectFileReader<PeOptionalHeaderType>::Section
PeCoffObjectFileReader<PeOptionalHeaderType>::FindSectionByIndex(ObjectFileBase header, int i) {
  PeSectionHeader* section_table = GetSectionTable(header);
  return reinterpret_cast<const Section>(&(section_table[i]));
}

// Attempt to find a section named |section_name|
template<typename PeOptionalHeaderType>
const typename PeCoffObjectFileReader<PeOptionalHeaderType>::Section
PeCoffObjectFileReader<PeOptionalHeaderType>::FindSectionByName(const char* section_name, ObjectFileBase mapped_base) {
  const uint8_t* obj_base = (uint8_t*) mapped_base;
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);
  PeSectionHeader* section_table = GetSectionTable(mapped_base);

  // string table immediately follows symbol table
  const char *string_table = GetStringTable(mapped_base);
  uint32_t string_table_length = *(uint32_t *)string_table;

  for (int s = 0; s < peHeader->mNumberOfSections; s++) {
    const char * name = section_table[s].Name;

    // look up long section names in string table
    if (name[0] == '/')
    {
      unsigned int offset = ::atoi(section_table[s].Name+1);

      if (offset > string_table_length)
        fprintf(stderr, "section name offset %d exceeds string table length",
                offset);
      else
        name = string_table + offset;
    }

    if (::strcmp(section_name, name) == 0) {
      return reinterpret_cast<const Section>(&(section_table[s]));
    }
  }

  // nothing found
  return NULL;
}

// Convert a section from a header into a pointer to the mapped
// address in the current process. Takes an extra template parameter
// to specify the return type T to avoid having to dynamic_cast the
// result.
template<typename PeOptionalHeaderType>
const uint8_t *
PeCoffObjectFileReader<PeOptionalHeaderType>::GetSectionPointer(ObjectFileBase header, Section section) {
  return reinterpret_cast<uint8_t *>(reinterpret_cast<uintptr_t>(header) +
                                     reinterpret_cast<const PeSectionHeader *>(section)->PointerToRawData);
}

// Get the size of a section from a header
template<typename PeOptionalHeaderType>
typename PeCoffObjectFileReader<PeOptionalHeaderType>::Offset
PeCoffObjectFileReader<PeOptionalHeaderType>::GetSectionSize(ObjectFileBase header, Section section) {
  return reinterpret_cast<const PeSectionHeader *>(section)->VirtualSize;
  // XXX: trying to access beyond SizeOfRawData will not work well...
}

// Get RVA of a section from a header
template<typename PeOptionalHeaderType>
typename PeCoffObjectFileReader<PeOptionalHeaderType>::Offset
PeCoffObjectFileReader<PeOptionalHeaderType>::GetSectionRVA(ObjectFileBase header, Section section) {
  return reinterpret_cast<const PeSectionHeader *>(section)->VirtualAddress;
}

// Get name of a section from a header
template<typename PeOptionalHeaderType>
const char *
PeCoffObjectFileReader<PeOptionalHeaderType>::GetSectionName(ObjectFileBase header,Section section) {
    const char *string_table = GetStringTable(header);
    uint32_t string_table_length = *(uint32_t *)string_table;

    const char *name = reinterpret_cast<const PeSectionHeader *>(section)->Name;

    // look up long section names in string table
    if (name[0] == '/')
      {
      unsigned int offset = ::atoi(name+1);

      if (offset > string_table_length)
        fprintf(stderr, "section name offset %d exceeds string table length",
                offset);
      else
        name = string_table + offset;
    }

    return name;
}

// Get build-id
template<typename PeOptionalHeaderType>
bool
PeCoffObjectFileReader<PeOptionalHeaderType>::GetBuildID(ObjectFileBase header,
                                                         uint8_t identifier[kMDGUIDSize]) {

  // locate the debug directory, if present
  PeDataDirectory * data_directory_debug_entry = GetDataDirectoryEntry(header, PE_DEBUG_DATA);
  if (!data_directory_debug_entry)
    return false;

  uint32_t debug_directory_size = data_directory_debug_entry->Size;
  if (debug_directory_size == 0)
    return false;

  PeDebugDirectory *debug_directory = (PeDebugDirectory *)ConvertRVAToPointer(header, data_directory_debug_entry->VirtualAddress);
  if (debug_directory == NULL) {
    fprintf(stderr, "No section containing the debug directory VMA could be found\n");
    return false;
  }

  // search the debug directory for a codeview entry
  for (int i = 0; i < debug_directory_size/sizeof(PeDebugDirectory); i++) {
    if (debug_directory[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW) {
      // interpret the codeview record to get build-id
      CV_INFO_PDB70 *codeview_record = (CV_INFO_PDB70 *)(header + debug_directory[i].PointerToRawData);
      if ((codeview_record->CvSignature) == CODEVIEW_PDB70_CVSIGNATURE) {
        memcpy(identifier, codeview_record->Signature, kMDGUIDSize);
        return true;
      }
      else {
        fprintf(stderr, "Unhandled codeview signature %x\n", codeview_record->CvSignature);
      }
    }
  }

  fprintf(stderr, "No codeview entry in debug directory\n");
  return false;
}

template<typename PeOptionalHeaderType>
bool
PeCoffObjectFileReader<PeOptionalHeaderType>::HashTextSection(ObjectFileBase header,
                               uint8_t identifier[kMDGUIDSize]) {
  Section text_section;
  Offset text_size;

  if (!(text_section = FindSectionByName(".text", header)) ||
      ((text_size = GetSectionSize(header, text_section)) == 0))
    return false;

  memset(identifier, 0, kMDGUIDSize);
  const uint8_t* ptr = GetSectionPointer(header, text_section);
  const uint8_t* ptr_end = ptr + std::min(text_size, 4096U);
  while (ptr < ptr_end) {
    for (unsigned i = 0; i < kMDGUIDSize; i++)
      identifier[i] ^= ptr[i];
    ptr += kMDGUIDSize;
  }
  return true;
}

// Load symbols from the object file's exported symbol table
template<class PeOptionalHeaderType>
bool
PeCoffObjectFileReader<PeOptionalHeaderType>::ExportedSymbolsToModule(ObjectFileBase header, Module *module) {

  // locate the export table, if present
  PeDataDirectory *data_directory_export_entry = GetDataDirectoryEntry(header, PE_EXPORT_TABLE);
  if (data_directory_export_entry && data_directory_export_entry->Size != 0) {
    PeExportTable *export_table = (PeExportTable *)ConvertRVAToPointer(header, data_directory_export_entry->VirtualAddress);
    uint32_t *eat = (uint32_t *)ConvertRVAToPointer(header, export_table->ExportAddressTableRVA);
    uint32_t *enpt = (uint32_t *)ConvertRVAToPointer(header, export_table->NamePointerRVA);
    uint16_t *eot = (uint16_t *)ConvertRVAToPointer(header, export_table->OrdinalTableRVA);

    // process the export name pointer table
    for (unsigned int i = 0; i < export_table->NumberofNamePointers; i++) {
      // look up the name for the export
      uint32_t export_name_rva = enpt[i];
      if (export_name_rva == 0)
        continue;
      char *export_name = (char *)ConvertRVAToPointer(header, export_name_rva);

      // find the corresponding export address table entry
      uint16_t export_ordinal = eot[i];
      if ((export_ordinal < export_table->OrdinalBase) ||
          (export_ordinal >= (export_table->OrdinalBase + export_table->AddressTableEntries))) {
        fprintf(stderr, "exported ordinal %d out of range for EAT!\n", export_ordinal);
        continue;
      }
      unsigned int eat_index = export_ordinal - export_table->OrdinalBase;
      uint32_t export_rva = eat[eat_index];

      // if the export's address lies inside the export table, it's a forwarded
      // export, which we can ignore
      if ((export_rva >= data_directory_export_entry->VirtualAddress) &&
          (export_rva < (data_directory_export_entry->VirtualAddress + data_directory_export_entry->Size)))
        continue;

      Module::Extern *ext = new Module::Extern;
      ext->name = export_name;
      ext->address = export_rva + GetLoadingAddress(header);
      module->AddExtern(ext);
    }

    return true;
  }

  // report if a COFF symbol table exists, but we don't use it (yet)
  // According to the PECOFF spec. COFF debugging information is deprecated.
  // We don't know of any tools which produce that and don't produce DWARF or
  // MS CodeView debug information.
  const uint8_t* obj_base = (uint8_t*) header;
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);

  if (peHeader->mPointerToSymbolTable) {
    fprintf(stderr, "COFF debug symbols present but are not implemented\n");
  }

  return false;
}

// instantiation of templated classes
template class PeCoffObjectFileReader<Pe32OptionalHeader>;
template class PeCoffObjectFileReader<Pe32PlusOptionalHeader>;

}
