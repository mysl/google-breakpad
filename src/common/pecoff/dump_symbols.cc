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

// dump_symbols.cc: implement google_breakpad::WriteSymbolFile:
// Find all the debugging info in a file and dump it as a Breakpad symbol file.

#include "common/pecoff/dump_symbols.h"

#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>

#include <iostream>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "common/dwarf/bytereader-inl.h"
#include "common/dwarf/dwarf2diehandler.h"
#include "common/dwarf_cfi_to_module.h"
#include "common/dwarf_cu_to_module.h"
#include "common/dwarf_line_to_module.h"
#include "common/linux/file_id.h"

#include "config.h"
#include <bfd.h>

//
// BFDWrapper
//
// Wrapper class for BFD library
//
class BFDWrapper {
public:
  BFDWrapper(const std::string &obj_filename);
  ~BFDWrapper();

  bool Endianness(bool *big_endian);
  const char *Architecture();
  const asection *FindSectionByName(const char *name);
  unsigned int GetLoadingAddress();

  bfd *bfd_;
};

BFDWrapper::BFDWrapper(const std::string &obj_filename) {
  bfd_ = NULL;
  bfd_ = bfd_openr (obj_filename.c_str(), NULL);
  if (bfd_ == NULL) {
    fprintf(stderr, "Error opening file: %s\n", obj_filename.c_str());
    exit(-1);
  }

  // check if the file is an object file
  if (!bfd_check_format (bfd_, bfd_object)) {
    if (bfd_get_error () != bfd_error_file_ambiguously_recognized) {
      fprintf(stderr, "Not an object file: %s\n", obj_filename.c_str());
      exit(-1);
    }
  }

  fprintf(stderr,"target is %s.\n", bfd_->xvec->name);
  fprintf(stderr,"architecture is %s.\n", bfd_printable_name(bfd_));
  fprintf(stderr,"entry point is at address 0x%x\n", bfd_get_start_address(bfd_));

  // dump out section information
  asection *s;
  for (s = bfd_->sections; s; s = s->next) {
    if (bfd_get_section_flags (bfd_, s) & (SEC_LOAD)) {
      if (bfd_section_lma (bfd_, s) != bfd_section_vma (bfd_, s)) {
        fprintf(stderr, "loadable section %s: lma = 0x%08x (vma = 0x%08x) size = 0x%08x\n", bfd_section_name (bfd_, s), (unsigned int) bfd_section_lma (bfd_, s), (unsigned int) bfd_section_vma (bfd_, s), (unsigned int) bfd_section_size (bfd_, s));
      } else {
        fprintf(stderr, "loadable section %s: addr = 0x%08x size = 0x%08x\n", bfd_section_name (bfd_, s), (unsigned int) bfd_section_lma (bfd_, s), (unsigned int) bfd_section_size (bfd_, s));
      }
    }
    else {
      fprintf(stderr, "non-loadable section %s: addr = 0x%08x size = 0x%08x\n", bfd_section_name (bfd_, s), (unsigned int) bfd_section_vma (bfd_, s), (unsigned int) bfd_section_size (bfd_, s));
    }
  }
}

// Get the endianness of the bfd target.  If it's invalid, return false.
bool
BFDWrapper::Endianness(bool *big_endian)
{
  if (bfd_->xvec->byteorder == BFD_ENDIAN_LITTLE) {
    *big_endian = false;
    return true;
  }

  if (bfd_->xvec->byteorder == BFD_ENDIAN_BIG) {
    *big_endian = true;
    return true;
  }

  fprintf(stderr, "unknown endianness%d\n");
  return false;
}

// Return the breakpad architecture identifier for the bfd target's architecture
const char *
BFDWrapper::Architecture() {
  enum bfd_architecture arch = bfd_get_arch(bfd_);
  switch (arch) {
  case bfd_arch_i386:
    {
      unsigned long march = bfd_get_mach(bfd_);
      switch (march)
        {
        case bfd_mach_i386_i386:
          return "x86";
        case bfd_mach_x86_64:
          return "x86_64";
        default:
          fprintf(stderr, "unrecognized machine architecture: %x\n", march);
          return NULL;
        }
    }
  default:
    fprintf(stderr, "unrecognized architecture: %x\n", arch);
    return NULL;
  }
}

const asection *BFDWrapper::FindSectionByName(const char *name)
{
  // Assumes that only one section exists with the name
  asection *sec = bfd_get_section_by_name(bfd_, name);

  if (!sec->flags & SEC_HAS_CONTENTS) {
        fprintf(stderr,
                "Section %s found, but ignored because it didn't have SEC_HAS_CONTENTS.\n",
                name);
  }
  return sec;
}

unsigned int BFDWrapper::GetLoadingAddress()
{
  unsigned int ImageBase = 0xFFFFFFFF;

  // BFD doesn't provide access to the PE ImageBase, so use this horrible heuristic to guess...
  asection *s;
  for (s = bfd_->sections; s; s = s->next) {
    unsigned int candidate = (unsigned int) bfd_section_vma(bfd_, s);
    if (candidate < ImageBase)
      ImageBase = candidate;
  }
  return ImageBase - 0x1000;
}

// This namespace contains helper functions.
namespace {

using google_breakpad::DumpOptions;
using google_breakpad::DwarfCFIToModule;
using google_breakpad::DwarfCUToModule;
using google_breakpad::DwarfLineToModule;
using google_breakpad::Module;

// A line-to-module loader that accepts line number info parsed by
// dwarf2reader::LineInfo and populates a Module and a line vector
// with the results.
class DumperLineToModule: public DwarfCUToModule::LineToModuleHandler {
 public:
  // Create a line-to-module converter using BYTE_READER.
  explicit DumperLineToModule(dwarf2reader::ByteReader *byte_reader)
      : byte_reader_(byte_reader) { }
  void StartCompilationUnit(const string& compilation_dir) {
    compilation_dir_ = compilation_dir;
  }
  void ReadProgram(const char *program, uint64 length,
                   Module *module, std::vector<Module::Line> *lines) {
    DwarfLineToModule handler(module, compilation_dir_, lines);
    dwarf2reader::LineInfo parser(program, length, byte_reader_, &handler);
    parser.Start();
  }
 private:
  string compilation_dir_;
  dwarf2reader::ByteReader *byte_reader_;
};

static const std::pair<const char*, uint64>& FindSection(DwarfCUToModule::FileContext &file_context,
                                                           const char *sectionName)
{
  dwarf2reader::SectionMap::const_iterator section_entry = file_context.section_map().find(sectionName);
  assert(section_entry != file_context.section_map().end());
  const std::pair<const char*, uint64>& section = section_entry->second;
  assert(section.first);
  return section;
}

static bool LoadDwarf(const std::string &dwarf_filename,
                      bfd *abfd,
                      const bool big_endian,
                      DwarfCUToModule::FileContext &file_context,
                      Module *module) {
  const dwarf2reader::Endianness endianness = big_endian ?
      dwarf2reader::ENDIANNESS_BIG : dwarf2reader::ENDIANNESS_LITTLE;
  dwarf2reader::ByteReader byte_reader(endianness);

  // Parse all the compilation units in the .debug_info section.
  DumperLineToModule line_to_module(&byte_reader);
  dwarf2reader::SectionMap::const_iterator debug_info_entry =
      file_context.section_map().find(".debug_info");
  assert(debug_info_entry != file_context.section_map().end());
  const std::pair<const char*, uint64>& debug_info_section =
      debug_info_entry->second;
  // We should never have been called if the file doesn't have a
  // .debug_info section.
  assert(debug_info_section.first);
  uint64 debug_info_length = debug_info_section.second;
  for (uint64 offset = 0; offset < debug_info_length;) {
    // Make a handler for the root DIE that populates MODULE with the
    // data we find.
    DwarfCUToModule::WarningReporter reporter(dwarf_filename, offset);
    DwarfCUToModule root_handler(&file_context, &line_to_module, &reporter);
    // Make a Dwarf2Handler that drives our DIEHandler.
    dwarf2reader::DIEDispatcher die_dispatcher(&root_handler);
    // Make a DWARF parser for the compilation unit at OFFSET.
    dwarf2reader::CompilationUnit reader(file_context.section_map(),
                                         offset,
                                         &byte_reader,
                                         &die_dispatcher);
    // Process the entire compilation unit; get the offset of the next.
    offset += reader.Start();
  }
  return true;
}

// Fill REGISTER_NAMES with the register names appropriate to the
// machine architecture given in HEADER, indexed by the register
// numbers used in DWARF call frame information. Return true on
// success, or false if we don't recognize HEADER's machine
// architecture.
static bool DwarfCFIRegisterNames(bfd *abfd,
                                  std::vector<std::string> *register_names) {
  enum bfd_architecture arch = bfd_get_arch(abfd);
  switch (arch) {
  case bfd_arch_i386:
    {
      unsigned long march = bfd_get_mach(abfd);
      switch (march)
        {
        case bfd_mach_i386_i386:
          *register_names = DwarfCFIToModule::RegisterNames::I386();
          return true;
        case bfd_mach_x86_64:
          *register_names = DwarfCFIToModule::RegisterNames::X86_64();
          return true;
        }
    }
  }
  return false;
}

static bool LoadDwarfCFI(const std::string &dwarf_filename,
                         bfd *abfd,
                         const char *section_name,
                         const char *section,
                         unsigned int section_length,
                         const bool eh_frame,
                         const char *got_section,
                         const char *text_section,
                         const bool big_endian,
                         Module *module) {
  // Find the appropriate set of register names for this file's
  // architecture.
  std::vector<std::string> register_names;
  if (!DwarfCFIRegisterNames(abfd, &register_names)) {
    fprintf(stderr, "%s: unrecognized machine architecture;"
            " cannot convert DWARF call frame information\n",
            dwarf_filename.c_str());
    return false;
  }

  const dwarf2reader::Endianness endianness = big_endian ?
      dwarf2reader::ENDIANNESS_BIG : dwarf2reader::ENDIANNESS_LITTLE;

  // Find the call frame information and its size.
  const char *cfi = section;
  size_t cfi_size = section_length;

  // Plug together the parser, handler, and their entourages.
  DwarfCFIToModule::Reporter module_reporter(dwarf_filename, section_name);
  DwarfCFIToModule handler(module, register_names, &module_reporter);
  dwarf2reader::ByteReader byte_reader(endianness);
  byte_reader.SetAddressSize(4); // XXX: not correct for PE+

  // Provide the base addresses for .eh_frame encoded pointers, if
  // possible.
  byte_reader.SetCFIDataBase(reinterpret_cast<uint64>(section), cfi);
  if (got_section)
    byte_reader.SetDataBase(reinterpret_cast<uint64>(got_section));
  if (text_section)
    byte_reader.SetTextBase(reinterpret_cast<uint64>(text_section));

  dwarf2reader::CallFrameInfo::Reporter dwarf_reporter(dwarf_filename,
                                                       section_name);
  dwarf2reader::CallFrameInfo parser(cfi, cfi_size,
                                     &byte_reader, &handler, &dwarf_reporter,
                                     eh_frame);
  parser.Start();
  return true;
}

//
// LoadSymbolsInfo
//
// Holds the state between the two calls to LoadSymbols() in case we have to
// follow the .gnu_debuglink section and load debug information from a
// different file.
//
class LoadSymbolsInfo {
 public:
  explicit LoadSymbolsInfo(const std::vector<string>& dbg_dirs) :
    debug_dirs_(dbg_dirs),
    has_loading_addr_(false) {}

  // Keeps track of which sections have been loaded so we don't accidentally
  // load it twice from two different files.
  void LoadedSection(const std::string &section) {
    if (loaded_sections_.count(section) == 0) {
      loaded_sections_.insert(section);
    } else {
      fprintf(stderr, "Section %s has already been loaded.\n",
              section.c_str());
    }
  }

  // We expect the PE file and linked debug file to have the same preferred
  // loading address.
  void set_loading_addr(unsigned int addr, const std::string &filename) {
    if (!has_loading_addr_) {
      loading_addr_ = addr;
      loaded_file_ = filename;
      return;
    }

    if (addr != loading_addr_) {
      fprintf(stderr,
              "file '%s' and debug file '%s' "
              "have different load addresses.\n",
              loaded_file_.c_str(), filename.c_str());
      assert(false);
    }
  }

  // Setters and getters
  const std::vector<string>& debug_dirs() const {
    return debug_dirs_;
  }

  std::string debuglink_file() const {
    return debuglink_file_;
  }
  void set_debuglink_file(std::string file) {
    debuglink_file_ = file;
  }

 private:
  const std::vector<string>& debug_dirs_; // Directories in which to
                                          // search for the debug ELF file.

  std::string debuglink_file_;  // Full path to the debug ELF file.

  bool has_loading_addr_;  // Indicate if LOADING_ADDR_ is valid.

  unsigned int loading_addr_;  // Saves the preferred loading address from the
                             // first call to LoadSymbols().

  std::string loaded_file_;  // Name of the file loaded from the first call to
                             // LoadSymbols().

  std::set<std::string> loaded_sections_;  // Tracks the Loaded ELF sections
                                           // between calls to LoadSymbols().
};

static bool LoadSymbols(const std::string &obj_file,
                        const bool big_endian,
                        BFDWrapper *abfd,
                        const bool read_gnu_debug_link,
                        LoadSymbolsInfo *info,
                        const DumpOptions& options,
                        Module *module) {

  unsigned int loading_addr = abfd->GetLoadingAddress();
  module->SetLoadAddress(loading_addr);
  info->set_loading_addr(loading_addr, obj_file);

  bool found_debug_info_section = false;
  bool found_usable_info = false;

  // XXX: should obey options.symbols_data = ONLY_CFI or NO_CFI

  // Construct a context for this file.
  DwarfCUToModule::FileContext file_context(obj_file,
                                            module,
                                            options.handle_inter_cu_refs);

  // Build a map of all the PE file's sections.
  int num_sections = 0;
  for (asection *p = abfd->bfd_->sections; p != NULL; p = p-> next) {
    num_sections++;
    std::string name = p->name;
    uint64 length = p->size;
    char *contents = reinterpret_cast<char *>(malloc(length));
    bfd_get_section_contents(abfd->bfd_, p, contents, 0, length);
    file_context.AddSectionToSectionMap(name, contents, length);
  }

  // Look for STABS debugging information, note that we are ignoring it
  const asection *stab_section = abfd->FindSectionByName(".stab");
  if (stab_section) {
    fprintf(stderr, "%s: \".stab\" section found, but ignored\n");
  }

  // Look for DWARF debugging information, and load it if present.
  const asection *dwarf_section = abfd->FindSectionByName(".debug_info");
  if (dwarf_section) {
    found_debug_info_section = true;
    found_usable_info = true;
    info->LoadedSection(".debug_info");
    if (!LoadDwarf(obj_file, abfd->bfd_, big_endian, file_context, module))
      fprintf(stderr, "%s: \".debug_info\" section found, but failed to load "
              "DWARF debugging information\n", obj_file.c_str());
  }

  // Dwarf Call Frame Information (CFI) is actually independent from
  // the other DWARF debugging information, and can be used alone.
  if (abfd->FindSectionByName(".debug_frame")) {
    info->LoadedSection(".debug_frame");

    std::pair<const char *, uint64> debug_frame_section
      = FindSection(file_context,".debug_info");

    assert(debug_frame_section.first);

    // Ignore the return value of this function; even without call frame
    // information, the other debugging information could be perfectly
    // useful.
    bool result =
      LoadDwarfCFI(obj_file, abfd->bfd_, ".debug_frame",
                   debug_frame_section.first, debug_frame_section.second,
                   false, 0, 0, big_endian, module);
    found_usable_info = found_usable_info || result;
  }

  // gcc C++ exception handling information can also provide
  // unwinding data.
  if (abfd->FindSectionByName(".eh_frame")) {
    info->LoadedSection(".eh_frame");

    std::pair<const char *, uint64> eh_frame_section
      = FindSection(file_context, ".eh_frame");

    assert(eh_frame_section.first);

    // Pointers in .eh_frame data may be relative to the base addresses of
    // certain sections. Provide those sections if present.
    const char *got_section = 0;
    const char *text_section = 0;

    if (abfd->FindSectionByName(".got"))
      got_section = FindSection(file_context, ".got").first;

    if (abfd->FindSectionByName(".text"))
      text_section = FindSection(file_context, ".text").first;

#if 0
    // As above, ignore the return value of this function.
    bool result =
      LoadDwarfCFI(obj_file, abfd->bfd_, ".eh_frame",
                   eh_frame_section.first, eh_frame_section.second,
                   true, got_section, text_section, big_endian, module);
    found_usable_info = found_usable_info || result;
#endif
  }

  if (!found_debug_info_section) {
    fprintf(stderr, "%s: file contains no debugging information"
            " (no \".debug_info\" section)\n",
            obj_file.c_str());

    // Failed, but maybe we can find a .gnu_debuglink section?
    if (read_gnu_debug_link) {
      if (!info->debug_dirs().empty()) {
        bool found = false;
        std::vector<string>::const_iterator it;

        for (it = info->debug_dirs().begin(); it < info->debug_dirs().end(); ++it) {
          const string& debug_dir = *it;
          const char *debuglink_file = bfd_follow_gnu_debuglink(abfd->bfd_, debug_dir.c_str());
          if (debuglink_file) {
            info->set_debuglink_file(debuglink_file);
            found = true;
            break;
          }
        }

        if (!found) {
          fprintf(stderr, "Failed to find debug file for '%s'\n",
                  obj_file.c_str());
        }

      } else {
        fprintf(stderr, ".gnu_debuglink section found in '%s', "
                "but no debug path specified.\n", obj_file.c_str());
      }
    } else {
      // Return true if some usable information was found, since
      // the caller doesn't want to use .gnu_debuglink.
      return found_usable_info;
    }

    // No debug info was found, let the user try again with .gnu_debuglink
    // if present.
    return false;
  }

  return true;
}

// Return the non-directory portion of FILENAME: the portion after the
// last slash, or the whole filename if there are no slashes.
std::string BaseFileName(const std::string &filename) {
  // Lots of copies!  basename's behavior is less than ideal.
  char *c_filename = strdup(filename.c_str());
  std::string base = basename(c_filename);
  free(c_filename);
  return base;
}

}  // namespace

namespace google_breakpad {

bool WriteSymbolFile(const std::string &obj_filename,
                     const std::vector<string>& debug_dirs,
                     const DumpOptions& options,
                     std::ostream &sym_stream) {

  bfd_init();

  BFDWrapper *abfd = new BFDWrapper(obj_filename);

  if (!abfd) {
    fprintf(stderr, "Not a valid PE file: %s\n", obj_filename.c_str());
    return false;
  }

  const char *architecture = abfd->Architecture();
  if (!architecture) {
    return false;
  }

  // Figure out what endianness this file is.
  bool big_endian;
  if (!abfd->Endianness(&big_endian))
    return false;

  std::string name = BaseFileName(obj_filename);
  std::string os = "windows";
  // PE generated with gcc don't currently have CV records, so the Windows
  // minidumper can't record any identifier information, so there's no
  // useful identifier for us to match with
  std::string id = "000000000000000000000000000000000";

  LoadSymbolsInfo info(debug_dirs);
  Module module(name, os, architecture, id);

  if (!LoadSymbols(obj_filename, big_endian, abfd, !debug_dirs.empty(),
                   &info, options, &module)) {
    const std::string debuglink_file = info.debuglink_file();
    if (debuglink_file.empty())
      return false;

    // Load debuglink file.
    fprintf(stderr, "Found debugging info in %s\n", debuglink_file.c_str());

    BFDWrapper *debug_bfd = new BFDWrapper(debuglink_file);

    // Sanity checks to make sure everything matches up.
    const char *debug_architecture = debug_bfd->Architecture();
    if (!debug_architecture) {
      return false;
    }
    if (strcmp(architecture, debug_architecture)) {
      fprintf(stderr, "%s with machine architecture %s does not match "
              "%s with architecture %s\n",
              debuglink_file.c_str(), debug_architecture,
              obj_filename.c_str(), architecture);
      return false;
    }

    bool debug_big_endian;
    if (!debug_bfd->Endianness(&debug_big_endian))
      return false;
    if (debug_big_endian != big_endian) {
      fprintf(stderr, "%s and %s does not match in endianness\n",
              obj_filename.c_str(), debuglink_file.c_str());
      return false;
    }

    if (!LoadSymbols(debuglink_file, debug_big_endian, debug_bfd,
                     false, &info, options, &module)) {
      return false;
    }
  }

  if (!module.Write(sym_stream, options.symbol_data))
    return false;

  return true;
}

}  // namespace google_breakpad
