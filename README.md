# Breakpad for Cygwin/MinGW

google-breakpad with added support for Cygwin/MinGW:
- A `dump_syms` tool which can read DWARF debugging information from PE/COFF executables.
- The breakpad crash-reporting client libraries built using Makefiles rather than MSVC solutions.

## Compiling

### Preparation

Run autoreconf to generate ./configure

````
autoreconf -fvi
````

### Compiling

See README.orig.md

````
./configure && make
````

will produce `dump_syms.exe`, `minidump_dump.exe`, `minidump_stackwalk.exe`, `libbreakpad.a`,
and for MinGW `libcrash_generation_client.a`, `libcrash_generation_server.a`, `crash_generation_app.exe`

Note that since git-svn ignores svn externals, this repository is missing the
gyp and gtest dependencies.

## Using

See [Getting started with breakpad](https://chromium.googlesource.com/breakpad/breakpad/+/master/docs/getting_started_with_breakpad.md)

### Producing and installing symbols

````
dump_syms crash_generation_app.exe >crash_generation_app.sym
FILE=`head -1 crash_generation_app.sym | cut -f5 -d' '`
BUILDID=`head -1 crash_generation_app.sym | cut -f4 -d' '`
SYMBOLPATH=/symbols/${FILE}/${BUILDID}/
mkdir -p ${SYMBOLPATH}
mv crash_generation_app.sym ${SYMBOLPATH}
````

### Generating a minidump file

A small test application demonstrating out-of-process dumping called
`crash_generation_app.exe` is built.

- Run it once, selecting "Server->Start" from the menu
- Run it again, selecting "Client->Deref zero"
- Client should crash, and a .dmp is written to C:\Dumps\

### Processing the minidump to produce a stack trace

````
minidump_stackwalk blah.dmp /symbols/
````

## Issues

### Lack of build-id

On Windows, the build-id takes the form of a CodeView record.
This build-id is captured for all modules in the process by MiniDumpWriteDump(),
and is used by the breakpad minidump processing tools to find the matching
symbol file.

See http://debuginfo.com/articles/debuginfomatch.html

I have implemented 'ld --build-id' for PE/COFF executables (See
https://sourceware.org/ml/binutils/2014-01/msg00296.html), but you must use a
sufficently recent version of binutils (2.25 or later) and build with
'-Wl,--build-id' (or a gcc configured with '--enable-linker-build-id', which
turns that flag on by default) to enable that.

A tool could be written to add a build-id to existing PE/COFF executables, but in
practice this turns out to be quite tricky...

### Symbols from a PDB or the Microsoft Symbol Server

<a href="http://hg.mozilla.org/users/tmielczarek_mozilla.com/fetch-win32-symbols">
symsrv_convert</a> and dump_syms for PDB cannot be currently built with MinGW,
because (i) they require the MS DIA (Debug Interface Access) SDK (only in paid
editions of Visual Studio 2013), and (ii) the DIA SDK uses ATL.

An alternate PDB parser is available at https://github.com/luser/dump_syms, but
that also needs some work before it can be built with MinGW.
