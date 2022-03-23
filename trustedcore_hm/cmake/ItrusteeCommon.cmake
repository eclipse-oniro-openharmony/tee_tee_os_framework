macro(tee_addprefix prefix list_name)
   SET(${list_name}_TMP)
   foreach(l ${list_name})
      list(APPEND ${list_name}_TMP ${prefix}${l} )
   endforeach()

   SET(${list_name} ${list_name}_TMP)
   UNSET(${list_name}_TMP)
endmacro(tee_addprefix)

macro(tee_list_addprefix prefix list_names)
   foreach(list_name ${list_names})
        tee_addprefix(${prefix} ${list_name})
   endforeach()
endmacro(tee_list_addprefix)

function(tee_target_linker_flags target)
    set(flags ${ARGN})
    list(LENGTH flags num_flags)
    if (num_flags GREATER 0)
        foreach (f ${flags})
            _tee_target_link_options(${target} ${f})
        endforeach()
    endif()
endfunction()

function(tee_target_link_libraries target)
    set(libraries ${ARGN})
    list(LENGTH librarys num_libraries)
    if (num_libraries GREATER 0)
        foreach (lib ${libraries})
            target_link_libraries(${target} ${lib})
        endforeach()
    endif()
endfunction()

function(tee_append_compiler_flags target)
    set(flags ${ARGN})
    list(LENGTH flags num_flags)
    if (num_flags GREATER 0)
        foreach (f ${flags})
            target_compile_options(${target} PRIVATE ${f})
        endforeach()
    endif()
endfunction()

function(tee_append_definitions target)
    set(flags ${ARGN})
    list(LENGTH flags num_flags)
    if (num_flags GREATER 0)
        foreach (f ${flags})
            target_compile_definitions(${target} PRIVATE ${f})
        endforeach()
    endif()
endfunction()

function(tee_include_directories target)
    set(flags ${ARGN})
    list(LENGTH flags num_flags)
    if (num_flags GREATER 0)
        foreach (f ${flags})
            target_include_directories(${target} PRIVATE ${f})
        endforeach()
    endif()
endfunction()

function(teeuapps_include_directories target)
    tee_include_directories(${target} ${ARGN})
endfunction()

function(tee_include_dirs target)
    cmake_parse_arguments(
        ARG
        "PRIVATE;INTERNAL;PUBLIC"
        ""
        "DIRS"
        ${ARGN}
        )
    list(LENGTH ARG_DIRS num_flags)
    if (NOT num_flags GREATER 0)
        return()
    endif()

    if (ARG_PRIVATE)
        foreach (f ${ARG_DIRS})
            target_include_directories(${target} PRIVATE ${f})
        endforeach()
    elseif (ARG_INTERNAL)
        foreach (f ${ARG_DIRS})
            target_include_directories(${target} PUBLIC
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/${f}>)
        endforeach()
    elseif (ARG_PUBLIC)
    endif()
endfunction()

function(tee_add_executable target)
    cmake_parse_arguments(
        TEEUAPPS
        "DYNAMIC;DEBUG;NO_INSTALL"
        "RPATH;"
        "SOURCES;COMPILER_FLAGS;PRIVATE_INCLUDES;LINKGROUP;OBJECTS;WHOLEARCHIVE;LIBRARY_PATHS;LIBRARIES;LINKER_SCRIPT"
        ${ARGN}
        )

    add_executable(${target} ${TEEUAPPS_SOURCES})

    tee_append_compiler_flags(${target} ${TEEUAPPS_COMPILER_FLAGS})
    tee_append_definitions(${target} ${TEEUAPPS_COMPILER_DEFINITIONS})
    tee_target_link_libraries(${target} ${TEEUAPPS_LINK_LIBRARIES})

endfunction()

function(tee_add_library target)
    cmake_parse_arguments(
        TEELIB
        "STATIC;SHARED;OBJECT;DEBUG;NO_INSTALL"
        "OUTPUT_NAME;LIBS_INSTALL_PATH;HEADERS_INSTALL_PATH;"
        "SOURCES;COMPILER_FLAGS;COMPILER_DEF;PRIVATE_INCLUDES;PUBLIC_INCLUDES;INTERNAL_INCLUDES;LIBRARIES;LIBRARY_PATHS;OBJECTS;WHOLEARCHIVE;LINKER_SCRIPT;RPATH;"
        ${ARGN}
        )

    if (TEELIB_STATIC)
        add_library(${target} STATIC ${TEELIB_SOURCES})
    elseif (TEELIB_SHARED)
        add_library(${target} SHARED ${TEELIB_SOURCES})
    elseif (TEELIB_OBJECT)
        add_library(${target} OBJECT ${TEELIB_SOURCES})
    endif()

    tee_append_compiler_flags(${target} ${TEELIB_COMPILER_FLAGS})
    tee_append_definitions(${target} ${TEELIB_COMPILER_DEF})
    tee_target_link_libraries(${target} ${TEELIB_LINK_LIBRARIES})

    # Mark the internal headers as INTERFACE.
    # Other targets in the same build can automatically include this directory.
    # Note that public headers are also internal headers.
    if (TEELIB_INTERNAL_INCLUDES)
        tee_include_dirs(${target} INTERNAL DIRS ${TEELIB_INTERNAL_INCLUDES})
    endif()

    # A special component for install public headers ONLY!
    # It is excluded from the default ``make install''.
    foreach (inc ${TEELIB_PUBLIC_INCLUDES})
    get_filename_component(abs_inc ${inc} ABSOLUTE)
    if (IS_DIRECTORY "${abs_inc}")
        install(DIRECTORY ${inc}
        DESTINATION ${HDR_INSTALL_DIR}
         COMPONENT headers_install
        EXCLUDE_FROM_ALL
        )
    else()
        install(FILES ${inc}
        DESTINATION ${HDR_INSTALL_DIR}
        COMPONENT headers_install
        EXCLUDE_FROM_ALL
        PERMISSIONS OWNER_READ OWNER_WRITE
        GROUP_READ
        WORLD_READ
        )
    endif()
    endforeach()
endfunction()
