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

bool IsValidPeCoff(const uint8_t* obj_base)
{
  // offset 0x3c - find offset to PE signature
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);

  //  if (*peOffsetPtr > size)
  //      return FALSE;

  // check PE signature
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);
  if (peHeader->mMagic !=  IMAGE_FILE_MAGIC)
    return false;

  return true;
}

int PeCoffClass(const uint8_t* obj_base)
{
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);
  PeOptionalHeader* peOptionalHeader = (PeOptionalHeader*) ((uint32_t*)peHeader + 6);

  return peOptionalHeader->mMagic;
}

// Convert a section from a header into a pointer to the mapped
// address in the current process. Takes an extra template parameter
// to specify the return type T to avoid having to dynamic_cast the
// result.
template<typename FileFormatClass, typename T>
const T*
GetSectionPointer(const typename FileFormatClass::Ehdr* header,
                 const typename FileFormatClass::Shdr* section) {

  return reinterpret_cast<const T*>(reinterpret_cast<uintptr_t>(header) +
                                    section->PointerToRawData);
}

// Get the size of a section from a header
template<typename FileFormatClass>
typename FileFormatClass::Off
GetSectionSize(const typename FileFormatClass::Ehdr* header,
               const typename FileFormatClass::Shdr* section) {
  return section->VirtualSize;
  // XXX: trying to access beyond SizeOfRawData will not work well...
}

// Get RVA of a section from a header
template<typename FileFormatClass>
typename FileFormatClass::Off
GetSectionRVA(const typename FileFormatClass::Ehdr* header,
              const typename FileFormatClass::Shdr* section){
  return section->VirtualAddress;
}

template<typename FileFormatClass>
const char *
GetSectionName(const typename FileFormatClass::Ehdr* header,
               const typename FileFormatClass::Shdr* section) {

    const uint8_t* obj_base = (uint8_t*) header;
    uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
    PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);

    // string table immediately follows symbol table
    uint32_t string_table_offset = peHeader->mPointerToSymbolTable + peHeader->mNumberOfSymbols*sizeof(PeSymbol);
    char *string_table = (char *)obj_base + string_table_offset;
    uint32_t string_table_length = *(uint32_t *)string_table;

    const char *name = section->Name;

    // look up long section names in string table
    if (name[0] == '/')
      {
      int offset = ::atoi(name+1);

      if (offset > string_table_length)
        printf(" offset exceeds string table length");
      else {
        name = string_table + offset;
      }
    }

    return name;
}

// Get the endianness of HEADER. If it's invalid, return false.
template<typename FileFormatClass>
bool Endianness(const typename FileFormatClass::Ehdr* header,
                   bool* big_endian) {
  // XXX: characteristics IMAGE_FILE_BYTES_REVERSED_HI and/or certain machine types are big-endian
  *big_endian = false;
  return true;
}

// Return the breakpad symbol file identifier for the architecture of
// HEADER.
template<typename FileFormatClass>
const char* Architecture(const typename FileFormatClass::Ehdr* header) {

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

// Find the preferred loading address of the binary.
template<typename FileFormatClass>
typename FileFormatClass::Addr GetLoadingAddress(
    const typename FileFormatClass::Ehdr *header) {

  const uint8_t* obj_base = (uint8_t*) header;
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);
  PeOptionalHeader* peOptionalHeader = (PeOptionalHeader*) ((uint32_t*)peHeader + 6);

  return peOptionalHeader->mImageBase;
}

template<typename FileFormatClass>
int GetNumberOfSections(const typename FileFormatClass::Ehdr* header) {
    const uint8_t* obj_base = (uint8_t*) header;
    uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
    PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);
    return peHeader->mNumberOfSections;
}

template<typename FileFormatClass>
const typename FileFormatClass::Shdr*
FindSectionByIndex(const typename FileFormatClass::Ehdr* header, int i) {
    const uint8_t* obj_base = (uint8_t*) header;
    uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
    PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);

    PeOptionalHeader* peOptionalHeader = (PeOptionalHeader*) ( (int32_t*) peHeader + 6);
    uint64_t peOptionalHeaderOffset = (uint64_t) peOptionalHeader - (uint64_t) obj_base + 1;
    int64_t sectionHeaderOffset = peOptionalHeaderOffset + peHeader->mSizeOfOptionalHeader;
    PeSectionHeader* section_table = (PeSectionHeader*) ((uint32_t*)obj_base+(sectionHeaderOffset/4));

    return &(section_table[i]);
}

// Attempt to find a section named |section_name|
template<typename FileFormatClass>
const typename FileFormatClass::Shdr* FindSectionByName(
    const char* section_name,
    const void *mapped_base) {

    const uint8_t* obj_base = (uint8_t*) mapped_base;
    uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
    PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);

    PeOptionalHeader* peOptionalHeader = (PeOptionalHeader*) ( (int32_t*) peHeader + 6);
    uint64_t peOptionalHeaderOffset = (uint64_t) peOptionalHeader - (uint64_t) obj_base + 1;
    int64_t sectionHeaderOffset = peOptionalHeaderOffset + peHeader->mSizeOfOptionalHeader;
    PeSectionHeader* section_table = (PeSectionHeader*) ((uint32_t*)obj_base+(sectionHeaderOffset/4));

    // string table immediately follows symbol table
    uint32_t string_table_offset = peHeader->mPointerToSymbolTable + peHeader->mNumberOfSymbols*sizeof(PeSymbol);
    char *string_table = (char *)obj_base + string_table_offset;
    uint32_t string_table_length = *(uint32_t *)string_table;

    for (int s = 0; s < peHeader->mNumberOfSections; s++) {
        const char * name = section_table[s].Name;
        printf("section name: %.8s", name);

        // look up long section names in string table
        if (name[0] == '/')
          {
            int offset = ::atoi(section_table[s].Name+1);

            if (offset > string_table_length)
              printf(" offset exceeds string table length");
            else {
              name = string_table + offset;
              printf(" = %s", name);
            }
          }

        printf("\n");
        printf("Virtual Size %08x Virtual Address Offset %08x, Raw Size %08x, File Offset %08x, Characteristics %08x\n",
               section_table[s].VirtualSize,
               section_table[s].VirtualAddress,
               section_table[s].SizeOfRawData,
               section_table[s].PointerToRawData,
               section_table[s].Characteristics);


        if (::strcmp(section_name, name) == 0) {
          return &(section_table[s]);
        }
    }

    // nothing found
    return NULL;
}

bool PeCoffFileIdentifierFromMappedFile(const uint8_t * header,
                                        uint8_t *identifier){
  // XXX: locate and read file-id from CV record, otherwise compute hash
  ::strcpy((char *)identifier, "000000000000000000000000000000000");
  return true;
}

// template instantations
template const char* Architecture<PeCoffClass32>(const PeCoffClass32::Ehdr* header);
template char const *GetSectionPointer<PeCoffClass32>(const PeCoffClass32::Ehdr* header,
                                                      const PeCoffClass32::Shdr* section);
template unsigned char const *GetSectionPointer<PeCoffClass32>(const PeCoffClass32::Ehdr* header,
                                                      const PeCoffClass32::Shdr* section);
template PeCoffClass32::Off GetSectionSize<PeCoffClass32>(const PeCoffClass32::Ehdr* header,
                                                          const PeCoffClass32::Shdr* section);
template PeCoffClass32::Off GetSectionRVA<PeCoffClass32>(const PeCoffClass32::Ehdr* header,
                                                         const PeCoffClass32::Shdr* section);
template PeCoffClass32::Addr GetLoadingAddress<PeCoffClass32>(const PeCoffClass32::Ehdr *header);
template const PeCoffClass32::Shdr* FindSectionByName<PeCoffClass32>(const char* section_name, const void *mapped_base);
template bool Endianness<PeCoffClass32>(const PeCoffClass32::Ehdr* header, bool* big_endian);
template int GetNumberOfSections<PeCoffClass32>(const PeCoffClass32::Ehdr* header);
template const PeCoffClass32::Shdr* FindSectionByIndex<PeCoffClass32>(const PeCoffClass32::Ehdr* header, int i);
template const char *GetSectionName<PeCoffClass32>(const PeCoffClass32::Ehdr* header, const PeCoffClass32::Shdr* section);

template const char* Architecture<PeCoffClass64>(const PeCoffClass64::Ehdr* header);
template char const *GetSectionPointer<PeCoffClass64>(const PeCoffClass64::Ehdr* header,
                                                      const PeCoffClass64::Shdr* section);
template unsigned char const *GetSectionPointer<PeCoffClass64>(const PeCoffClass64::Ehdr* header,
                                                      const PeCoffClass64::Shdr* section);
template PeCoffClass64::Off GetSectionSize<PeCoffClass64>(const PeCoffClass64::Ehdr* header,
                                                          const PeCoffClass64::Shdr* section);
template PeCoffClass64::Off GetSectionRVA<PeCoffClass64>(const PeCoffClass64::Ehdr* header,
                                                         const PeCoffClass64::Shdr* section);
template PeCoffClass64::Addr GetLoadingAddress<PeCoffClass64>(const PeCoffClass64::Ehdr *header);
template const PeCoffClass64::Shdr* FindSectionByName<PeCoffClass64>(const char* section_name, const void *mapped_base);
template bool Endianness<PeCoffClass64>(const PeCoffClass64::Ehdr* header, bool* big_endian);
template int GetNumberOfSections<PeCoffClass64>(const PeCoffClass64::Ehdr* header);
template const PeCoffClass64::Shdr* FindSectionByIndex<PeCoffClass64>(const PeCoffClass64::Ehdr* header, int i);
template const char *GetSectionName<PeCoffClass64>(const PeCoffClass64::Ehdr* header, const PeCoffClass64::Shdr* section);

}
