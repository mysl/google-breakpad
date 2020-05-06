# This is not a full replacement of the original gyp buildsystem
# It's just for building the dump_syms tool.

cmake_minimum_required(VERSION 3.12)

add_definitions(-DNO_STABS_SUPPORT)

if(APPLE)
add_definitions(-DHAVE_MACH_O_NLIST_H)

add_executable(dump_syms
    src/tools/mac/dump_syms/dump_syms_tool.cc
    src/common/mac/macho_walker.cc
    src/common/mac/arch_utilities.cc
    src/common/mac/macho_id.cc
    src/common/mac/file_id.cc
    src/common/mac/macho_utilities.cc
    src/common/mac/dump_syms.cc
    src/common/mac/macho_reader.cc

    src/common/test_assembler.cc
    src/common/module.cc
    src/common/md5.cc
    src/common/language.cc
    src/common/dwarf_line_to_module.cc
    src/common/path_helper.cc
    src/common/stabs_reader.cc
    src/common/stabs_to_module.cc
    src/common/dwarf_cfi_to_module.cc
    src/common/dwarf_cu_to_module.cc
    src/common/dwarf/functioninfo.cc
    src/common/dwarf/bytereader.cc
    src/common/dwarf/elf_reader.cc
    src/common/dwarf/dwarf2reader.cc
    src/common/dwarf/cfi_assembler.cc
    src/common/dwarf/dwarf2diehandler.cc
)
elseif(WIN32)
    if(MINGW)
	set(CMAKE_BUILD_TYPE Debug)
	set(CMAKE_CXX_STANDARD_LIBRARIES "-static-libgcc -static-libstdc++ ${CMAKE_CXX_STANDARD_LIBRARIES}")
    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-Bstatic,--whole-archive -lwinpthread -Wl,--no-whole-archive")
	include_directories(/mingw64/x86_64-w64-mingw32/include
	                    src/third_party/musl/include
	                    src/common/mingw/include)

	add_definitions(-DMINGW)
	add_definitions(-D__ARM_EABI__)

	link_directories(src/common/mingw/lib
					/mingw64/x86_64-w64-mingw32/lib)

        add_executable(dump_syms
        src/tools/windows/dump_syms_elf/dump_syms.cc
		src/common/mingw/compat_mingw.cc

        src/common/module.cc
        src/common/language.cc
        src/common/dwarf_line_to_module.cc
        src/common/path_helper.cc
        src/common/dwarf_cfi_to_module.cc
        src/common/dwarf_cu_to_module.cc
        src/common/dwarf/bytereader.cc
        src/common/dwarf/dwarf2reader.cc
        src/common/dwarf/dwarf2diehandler.cc
        src/common/linux/crc32.cc
        src/common/linux/dump_symbols.cc
        src/common/linux/elf_core_dump.cc
        src/common/linux/elf_symbols_to_module.cc
        src/common/linux/elfutils.cc
        src/common/linux/file_id.cc
        src/common/linux/linux_libc_support.cc
        src/common/linux/memory_mapped_file.cc
        )
        target_link_libraries(dump_syms
		    mman
            ws2_32
        )
    elseif(MSVC)
        add_executable(dump_syms
            src/tools/windows/dump_syms/dump_syms.cc

            src/common/windows/dia_util.cc
            src/common/windows/guid_string.cc
            src/common/windows/omap.cc
            src/common/windows/pdb_source_line_writer.cc
            src/common/windows/string_utils.cc
        )

        target_include_directories(dump_syms PRIVATE
          "$ENV{VSINSTALLDIR}/DIA SDK/include"
        )

        target_link_libraries(dump_syms PRIVATE imagehlp)
        if (CMAKE_SIZEOF_VOID_P EQUAL 8)
            target_link_libraries(dump_syms PRIVATE "$ENV{VSINSTALLDIR}/DIA SDK/lib/amd64/diaguids.lib")
        else()
            target_link_libraries(dump_syms PRIVATE "$ENV{VSINSTALLDIR}/DIA SDK/lib/diaguids.lib")
        endif()
    endif()
elseif("${CMAKE_SYSTEM}" MATCHES "Linux")
    add_executable(dump_syms
        src/tools/linux/dump_syms/dump_syms.cc

        src/common/module.cc
        src/common/language.cc
        src/common/dwarf_line_to_module.cc
        src/common/path_helper.cc
        src/common/dwarf_cfi_to_module.cc
        src/common/dwarf_cu_to_module.cc
        src/common/dwarf/bytereader.cc
        src/common/dwarf/dwarf2reader.cc
        src/common/dwarf/dwarf2diehandler.cc
        src/common/linux/crc32.cc
        src/common/linux/dump_symbols.cc
        src/common/linux/elf_core_dump.cc
        src/common/linux/elf_symbols_to_module.cc
        src/common/linux/elfutils.cc
        src/common/linux/file_id.cc
        src/common/linux/linux_libc_support.cc
        src/common/linux/memory_mapped_file.cc
    )

    target_link_libraries(dump_syms pthread dl)
endif()

target_include_directories(dump_syms PRIVATE "src")

install(TARGETS dump_syms RUNTIME DESTINATION bin)
