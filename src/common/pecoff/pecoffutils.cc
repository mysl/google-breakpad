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

int PeCoffClass(const uint8_t* obj_base) {
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);
  uint32_t* peOptionalHeader =  ((uint32_t*)peHeader + 6);
  // We need to read the magic before we know if this a Pe32OptionalHeader or
  // Pe32PlusOptionalHeader
  return *peOptionalHeader;
}

// Return the breakpad symbol file identifier for the architecture of
// HEADER.
const char*
PeCoffObjectFileReader::Architecture(PeCoffObjectFileReader::ObjectFileBase header) {
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
bool PeCoffObjectFileReader::Endianness(ObjectFileBase header, bool* big_endian) {
  // XXX: Note sure what bigendian PECOFF looks like: characteristics flag
  // IMAGE_FILE_BYTES_REVERSED_HI and/or certain machine types are big-endian
  *big_endian = false;
  return true;
}

// Helper functions

// Some functions need to be Specialized for PE32 or PE32+ to account for
// difference in size of the OptionalHeader.
// XXX: perhaps base PeCoffObjectFileReader on a templatized base class which
// just implements these functions?

// Specialized for PE32
Pe32OptionalHeader *
PeCoffClass32::GetOptionalHeader(ObjectFileBase header) {
  const uint8_t* obj_base = (uint8_t*) header;
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);
  Pe32OptionalHeader* peOptionalHeader = (Pe32OptionalHeader*) ((uint32_t*)peHeader + 6);
  return peOptionalHeader;
}

PeSectionHeader*
PeCoffClass32::GetSectionTable(ObjectFileBase header) {
  const uint8_t* obj_base = (uint8_t*) header;
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);
  Pe32OptionalHeader* peOptionalHeader = GetOptionalHeader(header);
  uint64_t peOptionalHeaderOffset = (uint64_t) peOptionalHeader - (uint64_t) obj_base;
  int64_t sectionHeaderOffset = peOptionalHeaderOffset + peHeader->mSizeOfOptionalHeader;
  PeSectionHeader* section_table = (PeSectionHeader*) (obj_base+sectionHeaderOffset);
  return section_table;
}

// specialized for PE32+
Pe32PlusOptionalHeader *
PeCoffClass64::GetOptionalHeader(ObjectFileBase header) {
  const uint8_t* obj_base = (uint8_t*) header;
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);
  Pe32PlusOptionalHeader* peOptionalHeader = (Pe32PlusOptionalHeader*) ((uint32_t*)peHeader + 6);
  return peOptionalHeader;
}

PeSectionHeader*
PeCoffClass64::GetSectionTable(ObjectFileBase header) {
  const uint8_t* obj_base = (uint8_t*) header;
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);
  Pe32PlusOptionalHeader* peOptionalHeader = GetOptionalHeader(header);
  uint64_t peOptionalHeaderOffset = (uint64_t) peOptionalHeader - (uint64_t) obj_base;
  int64_t sectionHeaderOffset = peOptionalHeaderOffset + peHeader->mSizeOfOptionalHeader;
  PeSectionHeader* section_table = (PeSectionHeader*) (obj_base+sectionHeaderOffset);
  return section_table;
}

const char *
PeCoffObjectFileReader::GetStringTable(ObjectFileBase header) {
  const uint8_t* obj_base = (uint8_t*) header;
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);

  // string table immediately follows symbol table
  uint32_t string_table_offset = peHeader->mPointerToSymbolTable + peHeader->mNumberOfSymbols*sizeof(PeSymbol);
  const char *string_table = (char *)obj_base + string_table_offset;
  return string_table;
}

int
PeCoffObjectFileReader::GetNumberOfSections(ObjectFileBase header) {
  const uint8_t* obj_base = (uint8_t*) header;
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);
  return peHeader->mNumberOfSections;
}

// Find the preferred loading address of the binary.
// again, specialized for different optional header
PeCoffObjectFileReader::Addr
PeCoffClass32::GetLoadingAddress(ObjectFileBase header) {
  Pe32OptionalHeader* peOptionalHeader = GetOptionalHeader(header);
  return peOptionalHeader->mImageBase;
}

PeCoffObjectFileReader::Addr
PeCoffClass64::GetLoadingAddress(ObjectFileBase header) {
  Pe32PlusOptionalHeader* peOptionalHeader = GetOptionalHeader(header);
  return peOptionalHeader->mImageBase;
}

const PeCoffObjectFileReader::Section
PeCoffObjectFileReader::FindSectionByIndex(ObjectFileBase header, int i) {
  PeSectionHeader* section_table = GetSectionTable(header);
  return reinterpret_cast<const Section>(&(section_table[i]));
}

// Attempt to find a section named |section_name|
const PeCoffObjectFileReader::Section
PeCoffObjectFileReader::FindSectionByName(const char* section_name, ObjectFileBase mapped_base) {
  const uint8_t* obj_base = (uint8_t*) mapped_base;
  uint32_t* peOffsetPtr = (uint32_t*) (obj_base + 0x3c);
  PeHeader* peHeader = (PeHeader*) (obj_base+*peOffsetPtr);
  PeSectionHeader* section_table = GetSectionTable(mapped_base);

  // string table immediately follows symbol table
  const char *string_table = GetStringTable(mapped_base);
  uint32_t string_table_length = *(uint32_t *)string_table;

  for (int s = 0; s < peHeader->mNumberOfSections; s++) {
    const char * name = section_table[s].Name;
    printf("section name: %.8s", name);

    // look up long section names in string table
    if (name[0] == '/')
    {
      unsigned int offset = ::atoi(section_table[s].Name+1);

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
const uint8_t *
PeCoffObjectFileReader::GetSectionPointer(ObjectFileBase header, Section section) {
  return reinterpret_cast<uint8_t *>(reinterpret_cast<uintptr_t>(header) +
                                     reinterpret_cast<const PeSectionHeader *>(section)->PointerToRawData);
}

// Get the size of a section from a header
PeCoffObjectFileReader::Offset
PeCoffObjectFileReader::GetSectionSize(ObjectFileBase header, Section section) {
  return reinterpret_cast<const PeSectionHeader *>(section)->VirtualSize;
  // XXX: trying to access beyond SizeOfRawData will not work well...
}

// Get RVA of a section from a header
PeCoffObjectFileReader::Offset
PeCoffObjectFileReader::GetSectionRVA(ObjectFileBase header, Section section) {
  return reinterpret_cast<const PeSectionHeader *>(section)->VirtualAddress;
}

// Get name of a section from a header
const char *
PeCoffObjectFileReader::GetSectionName(ObjectFileBase header,Section section) {
    const char *string_table = GetStringTable(header);
    uint32_t string_table_length = *(uint32_t *)string_table;

    const char *name = reinterpret_cast<const PeSectionHeader *>(section)->Name;

    // look up long section names in string table
    if (name[0] == '/')
      {
      unsigned int offset = ::atoi(name+1);

      if (offset > string_table_length)
        printf(" offset exceeds string table length");
      else {
        name = string_table + offset;
      }
    }

    return name;
}

// Load symbols from the object file's exported symbol table
bool
PeCoffObjectFileReader::ExportedSymbolsToModule(ObjectFileBase obj_file, Module *module) {
  // XXX: load exported symbols
  return true;
}

bool PeCoffFileIdentifierFromMappedFile(const uint8_t * header,
                                        uint8_t *identifier){
  // XXX: locate and read file-id from CV record, otherwise compute hash
  ::strcpy((char *)identifier, "000000000000000000000000000000000");
  return true;
}

}
