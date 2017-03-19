// Copyright (c) 2016, Google Inc.
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

// vcvarsall.bat x64
// cl /Zi pdb_pdata.cc /Fe./pdb_pdata_in_exe.exe /link /PROFILE
// dump_syms pdb_pdata_in_exe.pdb > pdb_pdata_in_exe.sym
// cl /Zi pdb_pdata.cc /Fe./pdb_pdata_in_pdb.exe /link /PROFILE /debugtype:pdata
// del pdb_pdata_in_pdb.exe
// dump_syms pdb_pdata_in_pdb.pdb > pdb_pdata_in_pdb.sym
// diff pdb_pdata_in_pdb.sym pdb_pdata_in_exe.sym
// should be identical apart from debug-id

namespace google_breakpad {

class C {
 public:
  C() : member_(1) {}
  virtual ~C() {}

  void set_member(int value) { member_ = value; }
  int member() const { return member_; }

  int e() { return member_ + g(); }
  void f() { member_ = g(); }
  virtual int g() { return 2; }
  static char* h(const C &that) { return 0; }

 private:
  int member_;
};

static int j() {
  return 3;
}

static int i() {
  return j();
}

}  // namespace google_breakpad

int main(int argc, char **argv) {
  google_breakpad::C object;
  object.set_member(google_breakpad::i());
  object.f();
  int value = object.g();
  char *nothing = object.h(object);

  return 0;
}
