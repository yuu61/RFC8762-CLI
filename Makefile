# Makefile for RFC 8762 STAMP implementation

CC ?= gcc
CFLAGS ?= -std=c2x -Wall -Wextra
LDFLAGS ?=
LDLIBS ?= -lm

UNAME_S :=
ifneq ($(OS),Windows_NT)
  UNAME_S := $(shell uname -s 2>/dev/null)
endif
ifeq ($(OS),Windows_NT)
  LDLIBS += -lws2_32 -lmswsock
  MKDIR = if not exist $(subst /,\,$(BUILD_DIR)) mkdir $(subst /,\,$(BUILD_DIR))
  RM = rmdir /s /q $(subst /,\,$(BUILD_DIR)) 2>nul || (exit 0)
else ifneq (,$(findstring MINGW,$(UNAME_S)))
  LDLIBS += -lws2_32 -lmswsock
  MKDIR = mkdir -p $(BUILD_DIR)
  RM = rm -rf $(BUILD_DIR)
else ifneq (,$(findstring MSYS,$(UNAME_S)))
  LDLIBS += -lws2_32 -lmswsock
  MKDIR = mkdir -p $(BUILD_DIR)
  RM = rm -rf $(BUILD_DIR)
else ifneq (,$(findstring CYGWIN,$(UNAME_S)))
  LDLIBS += -lws2_32 -lmswsock
  MKDIR = mkdir -p $(BUILD_DIR)
  RM = rm -rf $(BUILD_DIR)
else ifeq ($(UNAME_S),Linux)
  LDLIBS += -lrt
  MKDIR = mkdir -p $(BUILD_DIR)
  RM = rm -rf $(BUILD_DIR)
else
  MKDIR = mkdir -p $(BUILD_DIR)
  RM = rm -rf $(BUILD_DIR)
endif

# Target executables
BUILD_DIR = build
TARGETS = $(BUILD_DIR)/reflector $(BUILD_DIR)/sender
TEST_TARGET = $(BUILD_DIR)/test_stamp.out

# Source files
REFLECTOR_SRC = src/reflector.c
SENDER_SRC = src/sender.c
TEST_SRC = tests/test_stamp.c

# Header files
HEADERS = src/stamp.h

# Default target
all: $(BUILD_DIR) $(TARGETS)

# Create build directory
$(BUILD_DIR):
  @$(MKDIR)

# Build reflector
$(BUILD_DIR)/reflector: $(REFLECTOR_SRC) $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(REFLECTOR_SRC) $(LDLIBS)

# Build sender
$(BUILD_DIR)/sender: $(SENDER_SRC) $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SENDER_SRC) $(LDLIBS)

# Build and run tests
test: $(TEST_TARGET)
	$(TEST_TARGET)

# Build test executable
$(TEST_TARGET): $(TEST_SRC) $(HEADERS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(TEST_SRC) $(LDLIBS)

# Clean build artifacts
clean:
  @$(RM)

# Phony targets
.PHONY: all test clean
