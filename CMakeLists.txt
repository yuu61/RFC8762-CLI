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

# Require GCC 14 or later
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    if(CMAKE_C_COMPILER_VERSION VERSION_LESS "14")
        message(FATAL_ERROR "GCC 14 or later is required. Found: GCC ${CMAKE_C_COMPILER_VERSION}")
    endif()
else()
    message(WARNING "This project is optimized for GCC 14+. Other compilers may work but are not officially supported.")
endif()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release")

# CPU optimization option
option(PORTABLE_BUILD "Build portable binary for distribution" OFF)
option(ENABLE_LTO "Enable Link-Time Optimization (increases build time and memory usage)" ON)
option(ENABLE_REFLECTOR_DEBUG_LOG "Enable verbose reflector debug logging" OFF)

# Architecture detection and optimization flags
set(ARCH_FLAGS "")
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
else()
    # Native: maximum optimization for build machine
    message(STATUS "Building for native CPU")
    set(ARCH_FLAGS "-march=native -mtune=native")
endif()

# Optional debug logging flags
add_compile_definitions($<$<BOOL:${ENABLE_REFLECTOR_DEBUG_LOG}>:ENABLE_REFLECTOR_DEBUG_LOG>)

# Compiler flags (GCC 14+)
# Enhanced warning flags
add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2)
# Debug build
add_compile_options($<$<CONFIG:Debug>:-g> $<$<CONFIG:Debug>:-O0>)
# Release build: Maximum optimization
add_compile_options(
    $<$<CONFIG:Release>:-O3>                       # Maximum optimization level
    $<$<CONFIG:Release>:-funroll-loops>            # Unroll loops
    $<$<CONFIG:Release>:-fomit-frame-pointer>      # Omit frame pointer
    $<$<CONFIG:Release>:-finline-functions>        # Inline functions
    $<$<CONFIG:Release>:-ffunction-sections>       # Place each function in its own section
    $<$<CONFIG:Release>:-fdata-sections>           # Place each data in its own section
    $<$<CONFIG:Release>:-fipa-pta>                 # Interprocedural pointer analysis
)
# Linux/ELF-specific optimizations
if(UNIX AND NOT APPLE)
    add_compile_options(
        $<$<CONFIG:Release>:-fno-plt>                  # Direct calls without PLT
        $<$<CONFIG:Release>:-fno-semantic-interposition> # Optimize symbol resolution
    )
endif()
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
# Linker flags for Release build (Linux-specific)
if(UNIX AND NOT APPLE)
    add_link_options(
        $<$<CONFIG:Release>:-Wl,--gc-sections>   # Remove unused sections
        $<$<CONFIG:Release>:-Wl,-O2>             # Linker optimization
        $<$<CONFIG:Release>:-Wl,--as-needed>     # Only link needed libraries
    )
endif()
# Linker flags for LTO (optional)
if(ENABLE_LTO)
    add_link_options($<$<CONFIG:Release>:-flto>)
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
