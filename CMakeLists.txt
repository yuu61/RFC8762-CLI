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

# Compiler flags
if(MSVC)
    # MSVC: /W4 for warnings, /utf-8 for UTF-8 source files
    add_compile_options(/W4 /utf-8)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(/Od /Zi)
    else()
        add_compile_options(/O2)
    endif()
else()
    # GCC/Clang: Enhanced warning flags
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O3)
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
message(STATUS "Platform libraries: ${PLATFORM_LIBS}")
