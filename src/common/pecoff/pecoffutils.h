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

// pecoffutils.h: Utilities for dealing with PECOFF files

#ifndef COMMON_PECOFF_PECOFFUTILS_H__
#define COMMON_PECOFF_PECOFFUTILS_H__

#include "pecoff.h"
#include "pecoff_file_id.h"
#include "common/module.h"

namespace google_breakpad {

bool IsValidPeCoff(const uint8_t* obj_file);
int PeCoffClass(const uint8_t* obj_file);

template <typename PeOptionalHeaderType>
class PeCoffObjectFileReader {
public:
  typedef const uint8_t * ObjectFileBase;
  typedef const uint8_t * Section;
  typedef uint32_t Offset;
  typedef uint32_t Addr; // 64!

  static bool IsValid(ObjectFileBase obj_file) {
    return IsValidPeCoff(obj_file);
  };

  // Load the identifier for the file mapped into memory at |base| into
  // |identifier|.  Return false if the identifier could not be created for the
  // file.
  static bool FileIdentifierFromMappedFile(ObjectFileBase obj_file,
                                           uint8_t *identifier) {
    return PeCoffFileID::PeCoffFileIdentifierFromMappedFile(obj_file, identifier);
  };

  // Load symbols from the object file's exported symbol table
  static bool ExportedSymbolsToModule(ObjectFileBase obj_file, Module *module);

  //
  // Helpers for PeCoffFileID
  //

  // Get the build-id
  static bool GetBuildID(ObjectFileBase header, uint8_t identifier[kMDGUIDSize]);
  // Has the text section
  static bool HashTextSection(ObjectFileBase header, uint8_t identifier[kMDGUIDSize]);

  //
  // Header information
  //

  // Return the breakpad symbol file identifier for the architecture of HEADER.
  static const char* Architecture(ObjectFileBase header);

  // Get the endianness of HEADER. If it's invalid, return false.
  static bool Endianness(ObjectFileBase header, bool* big_endian);

  // Find the preferred loading address of the binary.
  static Addr GetLoadingAddress(ObjectFileBase header);

  //
  // Section enumeration and location
  //

  static int GetNumberOfSections(ObjectFileBase header);
  static const Section FindSectionByIndex(ObjectFileBase header, int i);
  // Attempt to find a section named |section_name|
  static const Section FindSectionByName(const char* section_name,
                                         ObjectFileBase mapped_base);

  //
  // Section information
  //

  // Convert a section from a header into a pointer to the mapped
  // address in the current process.
  static const uint8_t *GetSectionPointer(ObjectFileBase header,
                                          Section section);

  // Get the size of a section from a header
  static Offset GetSectionSize(ObjectFileBase header, Section section);

  // Get RVA of a section from a header
  static Offset GetSectionRVA(ObjectFileBase header, Section section);

  // Get name of a section from a header
  static const char * GetSectionName(ObjectFileBase header,Section section);

  // Find any linked section
  const Section FindLinkedSection(ObjectFileBase header, Section section) {
    return 0; // PECOFF doesn't have the concept of linked sections
  }

private:
  typedef PeOptionalHeaderType PeOptionalHeader;

  // Helper functions
  static PeOptionalHeader* GetOptionalHeader(ObjectFileBase header);
  static PeSectionHeader* GetSectionTable(ObjectFileBase header);
  static const char* GetStringTable(ObjectFileBase header);
  static PeDataDirectory *GetDataDirectoryEntry(ObjectFileBase header, int entry);
  static const uint8_t *ConvertRVAToPointer(ObjectFileBase header, unsigned int rva);
};

class PeCoffClass32 : public PeCoffObjectFileReader<Pe32OptionalHeader> {
public:
  static const int kClass = PE32;
  static const size_t kAddrSize = 4;
};

class PeCoffClass64 : public PeCoffObjectFileReader<Pe32PlusOptionalHeader> {
public:
  static const int kClass = PE32PLUS;
  static const size_t kAddrSize = 8;
};

}  // namespace google_breakpad

#endif  // COMMON_PECOFF_PECOFFUTILS_H__
