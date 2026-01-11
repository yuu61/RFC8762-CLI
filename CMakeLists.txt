# CMakeLists.txt for RFC 8762 STAMP implementation
cmake_minimum_required(VERSION 3.16)
project(RFC8762-CLI VERSION 1.0.0 LANGUAGES C)

# C standard settings
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Default build type to Release if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release")

# CPU optimization option
option(NATIVE_BUILD "Optimize for build machine CPU (-march=native)" ON)
option(PORTABLE_BUILD "Build portable binary for distribution" OFF)
option(ENABLE_LTO "Enable Link-Time Optimization (increases build time and memory usage)" ON)

# NATIVE_BUILDとPORTABLE_BUILDの相互排他性を確認
if(NATIVE_BUILD AND PORTABLE_BUILD)
    message(WARNING "Both NATIVE_BUILD and PORTABLE_BUILD are ON. PORTABLE_BUILD takes precedence.")
    set(NATIVE_BUILD OFF)
endif()

# Architecture detection and optimization flags
set(ARCH_FLAGS "")
if(NOT MSVC)
    if(PORTABLE_BUILD)
        # Portable: conservative optimization for broad compatibility
        message(STATUS "Building portable binary")
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
            set(ARCH_FLAGS "-mtune=generic")
        elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64")
            set(ARCH_FLAGS "-mtune=generic")
        elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
            set(ARCH_FLAGS "-mtune=generic-armv7-a")
        endif()
    elseif(NATIVE_BUILD)
        # Native: maximum optimization for build machine
        message(STATUS "Building for native CPU")
        set(ARCH_FLAGS "-march=native -mtune=native")
    else()
        # Architecture-specific baseline optimization
        message(STATUS "Building for architecture: ${CMAKE_SYSTEM_PROCESSOR}")
        if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
            # x86_64: Use x86-64-v2 when supported; fall back for older GCC versions
            if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_LESS "11.0")
                set(ARCH_FLAGS "-march=x86-64 -msse4.2 -mtune=generic")
            else()
                set(ARCH_FLAGS "-march=x86-64-v2 -mtune=generic")
            endif()
        elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|ARM64")
            # ARM64: NEON is always available
            set(ARCH_FLAGS "-march=armv8-a -mtune=generic")
        elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
            # ARM32: assume NEON support
            set(ARCH_FLAGS "-march=armv7-a -mfpu=neon -mtune=generic-armv7-a")
        endif()
    endif()
endif()

# Compiler flags
if(MSVC)
    # MSVC: /W4 for warnings, /utf-8 for UTF-8 source files
    add_compile_options(/W4 /utf-8)
    # Debug build
    add_compile_options($<$<CONFIG:Debug>:/Od> $<$<CONFIG:Debug>:/Zi>)
    # Release build: Maximum optimization
    add_compile_options(
        $<$<CONFIG:Release>:/O2>      # Maximum optimization
        $<$<CONFIG:Release>:/Oi>      # Enable intrinsic functions
        $<$<CONFIG:Release>:/Ot>      # Favor fast code
        $<$<CONFIG:Release>:/GL>      # Whole program optimization
        $<$<CONFIG:Release>:/Gy>      # Enable function-level linking
        $<$<CONFIG:Release>:/fp:fast> # Fast floating-point model
    )
    add_compile_definitions($<$<CONFIG:Release>:NDEBUG>)
    # MSVC linker flags for release
    add_link_options($<$<CONFIG:Release>:/LTCG> $<$<CONFIG:Release>:/OPT:REF> $<$<CONFIG:Release>:/OPT:ICF>)
else()
    # GCC/Clang: Enhanced warning flags
    add_compile_options(-Wall -Wextra -Wpedantic)
    # Debug build
    add_compile_options($<$<CONFIG:Debug>:-g> $<$<CONFIG:Debug>:-O0>)
    # Release build: Maximum optimization
    add_compile_options(
        $<$<CONFIG:Release>:-O3>                  # Maximum optimization level
        $<$<CONFIG:Release>:-funroll-loops>       # Unroll loops
        $<$<CONFIG:Release>:-fomit-frame-pointer> # Omit frame pointer
    )
    # Link-time optimization (optional, controlled by ENABLE_LTO)
    if(ENABLE_LTO)
        add_compile_options($<$<CONFIG:Release>:-flto>)
    endif()
    # Architecture-specific flags (Release build only for performance)
    # Debug builds use -O0 -g for better debugging experience
    if(ARCH_FLAGS)
        separate_arguments(ARCH_FLAGS_LIST NATIVE_COMMAND "${ARCH_FLAGS}")
        foreach(flag ${ARCH_FLAGS_LIST})
            add_compile_options($<$<CONFIG:Release>:${flag}>)
        endforeach()
    endif()
    add_compile_definitions($<$<CONFIG:Release>:NDEBUG>)
    # GCC/Clang linker flags for LTO (optional)
    if(ENABLE_LTO)
        add_link_options($<$<CONFIG:Release>:-flto>)
    endif()
endif()

# Platform-specific settings
if(WIN32)
    # Windows (including MinGW, MSYS, Cygwin)
    set(PLATFORM_LIBS ws2_32 mswsock)
elseif(UNIX AND NOT APPLE)
    # Linux
    set(PLATFORM_LIBS rt m)
else()
    # macOS and others
    set(PLATFORM_LIBS m)
endif()

# Header files
set(HEADERS src/stamp.h)

# Build reflector executable
add_executable(reflector src/reflector.c ${HEADERS})
target_link_libraries(reflector PRIVATE ${PLATFORM_LIBS})
target_include_directories(reflector PRIVATE ${CMAKE_SOURCE_DIR}/src)

# Build sender executable
add_executable(sender src/sender.c ${HEADERS})
target_link_libraries(sender PRIVATE ${PLATFORM_LIBS})
target_include_directories(sender PRIVATE ${CMAKE_SOURCE_DIR}/src)

# Enable testing
enable_testing()

# Build test executable
add_executable(test_stamp tests/test_stamp.c ${HEADERS})
target_link_libraries(test_stamp PRIVATE ${PLATFORM_LIBS})
target_include_directories(test_stamp PRIVATE ${CMAKE_SOURCE_DIR}/src)

# Register test
add_test(NAME stamp_tests COMMAND test_stamp)

# Custom target for running tests with output
add_custom_target(run_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS test_stamp
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running tests..."
)

# Print build information
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "System processor: ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "Architecture flags: ${ARCH_FLAGS}")
message(STATUS "Platform libraries: ${PLATFORM_LIBS}")
