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
//

#ifndef COMMON_PECOFF_PECOFFUTILS_H__
#define COMMON_PECOFF_PECOFFUTILS_H__

#include "pecoff.h"
#include "common/module.h"

namespace google_breakpad {

bool IsValidPeCoff(const uint8_t* obj_file);
int PeCoffClass(const uint8_t* obj_file);
bool PeCoffFileIdentifierFromMappedFile(const uint8_t * header, uint8_t *identifier);

// Traits classes so consumers can write templatized code to deal
// with specific PECOFF bits.

struct PeCoffClass32 {
  typedef const uint8_t Ehdr;
  /* typedef PeCoff32_Nhdr Nhdr; */
  /* typedef PeCoff32_Phdr Phdr; */
  typedef PeSectionHeader Shdr;
  typedef uint32_t Addr;
  /* typedef PeCoff32_Half Half; */
  typedef uint32_t Off;
  /* typedef PeCoff32_Word Word; */
  static const int kClass = PE32;
  static const size_t kAddrSize = 4;

  // XXX: place traits in a nested class!
  static bool IsValid(const uint8_t* obj_file) {
    return IsValidPeCoff(obj_file);
  }

  // Load the identifier for the file mapped into memory at |base| into
  // |identifier|.  Return false if the identifier could not be created for the
  // file.
  static bool FileIdentifierFromMappedFile(const Ehdr* header,
                                           uint8_t *identifier) {
    return PeCoffFileIdentifierFromMappedFile(header, identifier);
  }
};

struct PeCoffClass64 {
  typedef const uint8_t Ehdr;
  /* typedef PeCoff64_Nhdr Nhdr; */
  /* typedef PeCoff64_Phdr Phdr; */
  typedef PeSectionHeader Shdr;
  typedef uint32_t Addr;
  /* typedef PeCoff64_Half Half; */
  typedef uint32_t Off;
  /* typedef PeCoff64_Word Word; */
  static const int kClass = PE32PLUS;
  static const size_t kAddrSize = 8;

  static bool IsValid(const uint8_t* obj_file) {
    return IsValidPeCoff(obj_file);
  }

  // Load the identifier for the file mapped into memory at |base| into
  // |identifier|.  Return false if the identifier could not be created for the
  // file.
  static bool FileIdentifierFromMappedFile(const Ehdr* header,
                                           uint8_t *identifier) {
    return PeCoffFileIdentifierFromMappedFile(header, identifier);
  }
};

// Convert a section from a header into a pointer to the mapped
// address in the current process. Takes an extra template parameter
// to specify the return type T to avoid having to dynamic_cast the
// result.
template<typename FileFormatClass, typename T>
const T*
GetSectionPointer(const typename FileFormatClass::Ehdr* header,
                 const typename FileFormatClass::Shdr* section);

// Get the size of a section from a header
template<typename FileFormatClass>
typename FileFormatClass::Off
GetSectionSize(const typename FileFormatClass::Ehdr* header,
               const typename FileFormatClass::Shdr* section);

// Get RVA of a section from a header
template<typename FileFormatClass>
typename FileFormatClass::Off
GetSectionRVA(const typename FileFormatClass::Ehdr* header,
              const typename FileFormatClass::Shdr* section);

#if 0
// Convert an offset from a header into a pointer to the mapped
// address in the current process. Takes an extra template parameter
// to specify the return type to avoid having to dynamic_cast the
// result.
template<typename FileFormatClass, typename T>
const T*
GetOffset(const typename FileFormatClass::Ehdr* elf_header,
          typename FileFormatClass::Off offset);
#endif

// Return the breakpad symbol file identifier for the architecture of
// HEADER.
template<typename FileFormatClass>
const char* Architecture(const typename FileFormatClass::Ehdr* header);

// Find the preferred loading address of the binary.
template<typename FileFormatClass>
typename FileFormatClass::Addr GetLoadingAddress(
    const typename FileFormatClass::Ehdr *header);

// Attempt to find a section named |section_name|
template<typename FileFormatClass>
const typename FileFormatClass::Shdr* FindSectionByName(
    const char* section_name,
    const void *mapped_base);

// Find any linked section
template<typename FileFormatClass>
const typename FileFormatClass::Shdr* FindLinkedSection(
    const typename FileFormatClass::Shdr* section) {
    return 0; // PECOFF doesn't have the concept of linked sections
  }

// Get the endianness of HEADER. If it's invalid, return false.
template<typename FileFormatClass>
bool Endianness(const typename FileFormatClass::Ehdr* header,
                bool* big_endian);

template<typename FileFormatClass>
int GetNumberOfSections(const typename FileFormatClass::Ehdr* header);

template<typename FileFormatClass>
const typename FileFormatClass::Shdr*
FindSectionByIndex(const typename FileFormatClass::Ehdr* header, int i);

template<typename FileFormatClass>
typename FileFormatClass::Off
GetSectionSize(const typename FileFormatClass::Ehdr* header,
               const typename FileFormatClass::Shdr* section);

template<typename FileFormatClass>
const char *
GetSectionName(const typename FileFormatClass::Ehdr* header,
               const typename FileFormatClass::Shdr* section);

}  // namespace google_breakpad

// XXX: reading the exported symbol table needs to be done in
// a fileformat dependent way, so this needs more refactoring...
template<typename FileFormatClass>
bool SymbolsToModule(const uint8_t *symtab_section,
                     size_t symtab_size,
                     const uint8_t *string_section,
                     size_t string_size,
                     const bool big_endian,
                     size_t value_size,
                     google_breakpad::Module *module) {
  return false;
}



#endif  // COMMON_PECOFF_PECOFFUTILS_H__
