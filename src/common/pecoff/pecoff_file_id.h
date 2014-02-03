// Copyright (c) 2006, Google Inc.
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
//
// pecoff_file_id.h: Return a unique identifier for a file
//

#ifndef COMMON_PECOFF_PECOFF_FILE_ID_H__
#define COMMON_PECOFF_PECOFF_FILE_ID_H__

#include <limits.h>
#include "common/file_id.h"

namespace google_breakpad {

class PeCoffFileID : FileID {
 public:
  explicit PeCoffFileID(const char* path);
  ~PeCoffFileID() {}

  // Load the identifier for the PECOFF file mapped into memory at |base| into
  // |identifier|.  Return false if the identifier could not be created for the
  // file.
  // The current implementation will look for a CodeView file signature
  // and use that as the file id, otherwise it falls back to
  // XORing the first 4096 bytes of the .text section to generate an identifier.
  static bool PeCoffFileIdentifierFromMappedFile(const void* base,
                                                 uint8_t identifier[kMDGUIDSize]);
};

}  // namespace google_breakpad

#endif  // COMMON_PECOFF_PECOFF_FILE_ID_H__
