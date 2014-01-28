// Copyright (c) 2011 Google Inc.
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

#include <elf.h>

#include "common/linux/dump_symbols.h"
#include "common/linux/elfutils.h"
#include "common/linux/elfutils-inl.h"
#include "common/linux/elf_symbols_to_module.h"
#include "common/linux/file_id.h"
#include "common/dump_symbols-inl.h"

// This namespace contains helper functions.
namespace {

using google_breakpad::FindElfSectionByName;

// Return the breakpad symbol file identifier for the architecture of
// ELF_HEADER.
template<typename FileFormatClass>
const char* Architecture(const typename FileFormatClass::Ehdr* elf_header) {
  typedef typename FileFormatClass::Half Half;
  Half arch = elf_header->e_machine;
  switch (arch) {
    case EM_386:        return "x86";
    case EM_ARM:        return "arm";
    case EM_MIPS:       return "mips";
    case EM_PPC64:      return "ppc64";
    case EM_PPC:        return "ppc";
    case EM_S390:       return "s390";
    case EM_SPARC:      return "sparc";
    case EM_SPARCV9:    return "sparcv9";
    case EM_X86_64:     return "x86_64";
    default: return NULL;
  }
}

// Get the endianness of ELF_HEADER. If it's invalid, return false.
template<typename FileFormatClass>
bool Endianness(const typename FileFormatClass::Ehdr* elf_header,
                   bool* big_endian) {
  if (elf_header->e_ident[EI_DATA] == ELFDATA2LSB) {
    *big_endian = false;
    return true;
  }
  if (elf_header->e_ident[EI_DATA] == ELFDATA2MSB) {
    *big_endian = true;
    return true;
  }

  fprintf(stderr, "bad data encoding in ELF header: %d\n",
          elf_header->e_ident[EI_DATA]);
  return false;
}

//
template<typename FileFormatClass>
const typename ElfClass::Shdr* FindSectionByName(
    const char* name,
    typename ElfClass::Word section_type,
    const typename ElfClass::Shdr* sections,
    const char* section_names,
    const char* names_end,
    int nsection) {
  // XXX: see FindElfSectionByName
}


// Find the preferred loading address of the binary.
template<typename FileFormatClass>
typename FileFormatClass::Addr GetLoadingAddress(const typename FileFormatClass::Ehdr* header) {
  const typename FileFormatClass::Phdr*  = GetOffset<FileFormatClass, Phdr>(header, header->e_phoff);
  int nheader = header->e_phnum;

  typedef typename FileFormatClass::Phdr Phdr;

  // For non-PIC executables (e_type == ET_EXEC), the load address is
  // the start address of the first PT_LOAD segment.  (ELF requires
  // the segments to be sorted by load address.)  For PIC executables
  // and dynamic libraries (e_type == ET_DYN), this address will
  // normally be zero.
  for (int i = 0; i < nheader; ++i) {
    const Phdr& header = program_headers[i];
    if (header.p_type == PT_LOAD)
      return header.p_vaddr;
  }
  return 0;
}


template<typename FileFormatClass>
bool SymbolsToModule(const uint8_t *symtab_section,
                        size_t symtab_size,
                        const uint8_t *string_section,
                        size_t string_size,
                        const bool big_endian,
                        size_t value_size,
                        Module *module)
{
  // XXX: see ElfSymbolsToModule();
}

}

namespace google_breakpad {

using google_breakpad::ElfClass;
using google_breakpad::ElfClass32;
using google_breakpad::ElfClass64;
using google_breakpad::IsValidElf;

// Not explicitly exported, but not static so it can be used in unit tests.
bool ReadSymbolDataInternal(const uint8_t* obj_file,
                            const string& obj_filename,
                            const std::vector<string>& debug_dirs,
                            const DumpOptions& options,
                            Module** module) {
  if (!IsValidElf(obj_file)) {
    fprintf(stderr, "Not a valid ELF file: %s\n", obj_filename.c_str());
    return false;
  }

  int elfclass = ElfClass(obj_file);
  if (elfclass == ELFCLASS32) {
    return ReadSymbolDataElfClass<ElfClass32>(
        reinterpret_cast<const Elf32_Ehdr*>(obj_file), obj_filename, debug_dirs,
        options, module);
  }
  if (elfclass == ELFCLASS64) {
    return ReadSymbolDataElfClass<ElfClass64>(
        reinterpret_cast<const Elf64_Ehdr*>(obj_file), obj_filename, debug_dirs,
        options, module);
  }

  return false;
}

bool WriteSymbolFile(const string &obj_file,
                     const std::vector<string>& debug_dirs,
                     const DumpOptions& options,
                     std::ostream &sym_stream) {
  Module* module;
  if (!ReadSymbolData(obj_file, debug_dirs, options, &module))
    return false;

  bool result = module->Write(sym_stream, options.symbol_data);
  delete module;
  return result;
}

bool ReadSymbolData(const string& obj_file,
                    const std::vector<string>& debug_dirs,
                    const DumpOptions& options,
                    Module** module) {
  MmapWrapper map_wrapper;
  void* elf_header = NULL;
  if (!LoadFile(obj_file, &map_wrapper, &elf_header))
    return false;

  return ReadSymbolDataInternal(reinterpret_cast<uint8_t*>(elf_header),
                                obj_file, debug_dirs, options, module);
}

}  // namespace google_breakpad
