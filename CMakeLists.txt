# CMakeLists.txt for RFC 8762 STAMP implementation
cmake_minimum_required(VERSION 3.25)
project(RFC8762-CLI VERSION 1.0.0 LANGUAGES C)

# C standard settings (gnu17 = C17 + GNU extensions)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# Export compile commands for IDE/tooling support (clangd, clang-tidy)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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
    message(FATAL_ERROR "This project requires GCC 14+. Detected: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}. "
                        "GNU extensions and GCC-specific flags are used throughout.")
endif()
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release")

# CPU optimization option
option(PORTABLE_BUILD "Build portable binary for distribution" OFF)
option(ENABLE_LTO "Enable Link-Time Optimization (increases build time and memory usage)" ON)
option(ENABLE_REFLECTOR_DEBUG_LOG "Enable verbose reflector debug logging" OFF)

# Profile-Guided Optimization (PGO) options
# Usage: 1) cmake -DENABLE_PGO_GENERATE=ON .. && make && ./sender (run workload)
#        2) cmake -DENABLE_PGO_USE=ON .. && make
# IMPORTANT: Profile generation and profile use MUST use the same compiler version.
#            Upgrading the compiler between steps will cause errors or suboptimal code.
option(ENABLE_PGO_GENERATE "Generate profile data for PGO (step 1)" OFF)
option(ENABLE_PGO_USE "Use profile data for optimization (step 2)" OFF)

# Graphite polyhedral optimization (experimental, requires GCC built with ISL)
option(ENABLE_GRAPHITE "Enable Graphite polyhedral loop optimization (experimental)" OFF)

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
# Maximum strictness warning flags
add_compile_options(
    # Core warning sets
    -Wall -Wextra -Wpedantic -Werror
    # Type safety and conversions
    -Wconversion                    # Implicit type conversions
    -Warith-conversion              # Implicit arithmetic conversions
    -Wfloat-conversion              # Implicit float conversions
    -Wdouble-promotion              # Implicit float → double promotion
    -Wcast-qual                     # Casting away const/volatile qualifiers
    -Wcast-align=strict             # Pointer casts increasing alignment requirement
    -Wbad-function-cast             # Casting function return to incompatible type
    # Shadow and scope
    -Wshadow                        # Variable shadowing
    -Wnested-externs                # Nested extern declarations
    # Format string (comprehensive)
    -Wformat=2                      # Enables -Wformat-security -Wformat-nonliteral -Wformat-y2k
    -Wformat-overflow=2             # Detect sprintf buffer overflows
    -Wformat-truncation=2           # Detect snprintf truncation
    -Wformat-signedness             # Format string signedness mismatch
    # String/buffer operations
    -Wstringop-overflow=4           # Maximum level string operation overflow detection
    -Wstringop-truncation           # Detect strncat/strncpy truncation
    # Logic and control flow
    -Wlogical-op                    # Suspicious logical operations (always true/false)
    -Wduplicated-cond               # Duplicated conditions in if-else chains
    -Wduplicated-branches           # Duplicated branches in if-else
    -Wimplicit-fallthrough          # Require explicit fallthrough annotation in switch
    -Wswitch-enum                   # Switch on enum without handling all values
    -Wswitch-default                # Switch without default case
    # Pointer, memory, and array
    -Wnull-dereference              # Static detection of NULL pointer dereference
    -Walloc-zero                    # Zero-size memory allocations
    -Wvla                           # Variable-length array usage
    -Warray-bounds=2                # Enhanced array bounds checking
    -Wtrampolines                   # Trampoline generation (security concern)
    # Declaration quality
    -Wstrict-prototypes             # Reject old-style function declarations
    -Wold-style-definition          # Reject old-style function definitions
    -Wmissing-prototypes            # Missing function prototypes
    -Wmissing-declarations          # Missing function declarations
    -Wredundant-decls               # Redundant declarations
    # Preprocessor and type system
    -Wundef                         # Undefined macros in #if directives
    -Wwrite-strings                 # String literals as const char[]
    -Wdate-time                     # Warn about __DATE__/__TIME__ (reproducibility)
    # GCC optimization feedback
    -Wdisabled-optimization         # Function too large for optimization
    -Wstack-protector               # Stack protector can't be applied
    -Wattribute-alias=2             # Stricter attribute alias checking
    # GCC 14 specific
    -Wflex-array-member-not-at-end  # Flexible array member not at struct end
    -Wcalloc-transposed-args        # Swapped calloc(size, count) arguments
)
# Stack protection (all builds — critical for network-facing applications)
add_compile_options(-fstack-protector-strong)
# CFI: Control-Flow Enforcement (x86_64 only, requires Intel CET)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
    add_compile_options(-fcf-protection)
endif()
# Buffer overflow detection (Release only, requires -O1+)
add_compile_definitions($<$<CONFIG:Release>:_FORTIFY_SOURCE=3>)
# Debug build
add_compile_options($<$<CONFIG:Debug>:-g> $<$<CONFIG:Debug>:-O0> $<$<CONFIG:Debug>:-fno-omit-frame-pointer>)
# Release build: Maximum optimization
add_compile_options(
    # Core optimization
    $<$<CONFIG:Release>:-O3>                       # Maximum optimization level
    $<$<CONFIG:Release>:-funroll-loops>            # Unroll loops
    $<$<CONFIG:Release>:-fomit-frame-pointer>      # Omit frame pointer
    $<$<CONFIG:Release>:-finline-functions>        # Inline functions
    # Section optimization
    $<$<CONFIG:Release>:-ffunction-sections>       # Place each function in its own section
    $<$<CONFIG:Release>:-fdata-sections>           # Place each data in its own section
    # Interprocedural optimization
    $<$<CONFIG:Release>:-fipa-pta>                 # Interprocedural pointer analysis
    # Loop optimization
    $<$<CONFIG:Release>:-ftree-loop-distribution>  # Loop distribution optimization
    $<$<CONFIG:Release>:-ftree-loop-distribute-patterns> # Convert loops to memset/memcpy calls
    $<$<CONFIG:Release>:-ftree-loop-im>            # Loop invariant motion
    $<$<CONFIG:Release>:-ftree-loop-ivcanon>       # Canonical induction variables
    $<$<CONFIG:Release>:-fivopts>                  # Induction variable optimization
    $<$<CONFIG:Release>:-fprefetch-loop-arrays>    # Generate memory prefetch instructions
    $<$<CONFIG:Release>:-fvariable-expansion-in-unroller> # Variable expansion in loop unrolling
    # Register and scheduling optimization
    # NOTE: These flags are architecture-specific and most effective on x86_64/amd64.
    # They increase compilation time but can improve performance for tight loops.
    $<$<CONFIG:Release>:-fweb>                     # Web construction for register allocation
    $<$<CONFIG:Release>:-frename-registers>        # Rename registers to avoid false dependencies
    $<$<CONFIG:Release>:-fschedule-insns>          # Instruction scheduling before register allocation
    $<$<CONFIG:Release>:-fschedule-insns2>         # Instruction scheduling after register allocation
    $<$<CONFIG:Release>:-fsched-pressure>          # Schedule with register pressure
    $<$<CONFIG:Release>:-fschedule-fusion>         # Group similar instructions for execution efficiency
    $<$<CONFIG:Release>:-fmodulo-sched>            # Modulo scheduling for loops (x86_64 optimized)
    $<$<CONFIG:Release>:-fmodulo-sched-allow-regmoves> # Allow register moves in modulo scheduling
    # Superblock optimization
    $<$<CONFIG:Release>:-ftracer>                  # Tail duplication to form superblocks
    # Global common subexpression elimination
    $<$<CONFIG:Release>:-fgcse-sm>                 # Store motion after GCSE
    $<$<CONFIG:Release>:-fgcse-las>                # Load after store optimization
    # Metadata reduction
    $<$<CONFIG:Release>:-fno-ident>                # Remove .ident directives
    # Constant and data optimization
    $<$<CONFIG:Release>:-fmerge-all-constants>     # Merge identical constants
    # Floating point optimization (validated for STAMP/NTP timestamps)
    # NOTE: These flags have been evaluated and confirmed not to degrade RFC 8762 STAMP / NTP
    # timestamp precision. For strictly conservative IEEE semantics, override in your build.
    $<$<CONFIG:Release>:-fno-math-errno>           # Skip errno setting in math functions
    $<$<CONFIG:Release>:-fno-trapping-math>        # Assume no floating-point traps
    $<$<CONFIG:Release>:-fno-signed-zeros>         # Ignore sign of zero
    # Symbol visibility
    $<$<CONFIG:Release>:-fvisibility=hidden>       # Hide symbols by default
)
# Linux/ELF-specific optimizations
if(UNIX AND NOT APPLE)
    add_compile_options(
        $<$<CONFIG:Release>:-fno-plt>                  # Direct calls without PLT
        $<$<CONFIG:Release>:-fno-semantic-interposition> # Optimize symbol resolution
    )
endif()
# Link-time optimization (optional, controlled by ENABLE_LTO)
# Uses CMake's built-in IPO support for better portability across toolchains
if(ENABLE_LTO)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
endif()
# Profile-Guided Optimization (PGO)
if(ENABLE_PGO_GENERATE)
    add_compile_options($<$<CONFIG:Release>:-fprofile-generate>)
    add_link_options($<$<CONFIG:Release>:-fprofile-generate>)
    message(STATUS "PGO: Profile generation enabled - run the binary to generate profile data")
elseif(ENABLE_PGO_USE)
    add_compile_options(
        $<$<CONFIG:Release>:-fprofile-use>
        $<$<CONFIG:Release>:-fprofile-correction>
    )
    add_link_options($<$<CONFIG:Release>:-fprofile-use>)
    message(STATUS "PGO: Using profile data for optimization")
endif()
# Graphite polyhedral optimization (experimental)
# Note: -floop-parallelize-all は OpenMP が必要なため削除
# Note: Graphite requires GCC to be built with ISL (Integer Set Library) support
if(ENABLE_GRAPHITE)
    include(CheckCCompilerFlag)
    check_c_compiler_flag("-floop-nest-optimize" HAVE_GRAPHITE_SUPPORT)
    if(HAVE_GRAPHITE_SUPPORT)
        add_compile_options(
            $<$<CONFIG:Release>:-floop-nest-optimize>      # Polyhedral loop nest optimization
            $<$<CONFIG:Release>:-fgraphite-identity>       # Enable Graphite identity transform
        )
        message(STATUS "Graphite: Polyhedral optimization enabled (experimental)")
    else()
        message(WARNING "Graphite: ISL support not found in compiler. Graphite optimization disabled. "
                        "To enable, rebuild GCC with --with-isl.")
    endif()
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
    # Security hardening: full RELRO + immediate binding
    add_link_options(-Wl,-z,relro -Wl,-z,now)
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
set(HEADERS
    src/stamp.h
    src/stamp_calc.h
    src/stamp_platform.h
    src/stamp_protocol.h
    src/stamp_time.h
    src/stamp_kernel_ts.h
    src/stamp_net.h
)

# Build reflector executable
add_executable(reflector src/reflector.c src/stamp_globals.c ${HEADERS})
target_link_libraries(reflector PRIVATE ${PLATFORM_LIBS})
target_include_directories(reflector PRIVATE ${CMAKE_SOURCE_DIR}/src)

# Build sender executable
add_executable(sender src/sender.c src/stamp_globals.c ${HEADERS})
target_link_libraries(sender PRIVATE ${PLATFORM_LIBS})
target_include_directories(sender PRIVATE ${CMAKE_SOURCE_DIR}/src)

# Install targets
include(GNUInstallDirs)
install(TARGETS reflector sender RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# Enable testing
enable_testing()

# Build test executable
add_executable(test_stamp tests/test_stamp.c src/stamp_globals.c ${HEADERS})
target_link_libraries(test_stamp PRIVATE ${PLATFORM_LIBS})
target_include_directories(test_stamp PRIVATE ${CMAKE_SOURCE_DIR}/src)
# テストコードでは argv[] に文字列リテラルを直接代入するため緩和
target_compile_options(test_stamp PRIVATE -Wno-write-strings)

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
message(STATUS "LTO enabled: ${ENABLE_LTO}")
message(STATUS "PGO generate: ${ENABLE_PGO_GENERATE}")
message(STATUS "PGO use: ${ENABLE_PGO_USE}")
message(STATUS "Graphite enabled: ${ENABLE_GRAPHITE}")
message(STATUS "Platform libraries: ${PLATFORM_LIBS}")
