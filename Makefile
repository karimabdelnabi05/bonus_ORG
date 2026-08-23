# Makefile for the Runtime Memory Patcher project
#
# Targets:
#   make all          - Build everything (check, patcher, tests)
#   make check        - Build check.exe (target program)
#   make patcher      - Build patcher.exe (memory patcher tool)
#   make tests        - Build test executables
#   make test         - Build and run all tests
#   make test-check   - Run check.exe integration tests only
#   make test-patcher - Run patcher tests only (requires check.exe running)
#   make clean        - Remove build artifacts

CC = gcc
CFLAGS = -Wall -Wextra -std=c99
BUILD_DIR = build

# Ensure build directory exists
$(shell mkdir -p $(BUILD_DIR) 2>/dev/null || mkdir $(BUILD_DIR) 2>nul)

.PHONY: all check patcher tests test test-check test-patcher clean

all: check patcher tests

# ==========================================
#  Target program
# ==========================================
check: $(BUILD_DIR)/check.exe

$(BUILD_DIR)/check.exe: src/check.c
	$(CC) $(CFLAGS) -o $@ $<

# ==========================================
#  Patcher tool
# ==========================================
patcher: $(BUILD_DIR)/patcher.exe

$(BUILD_DIR)/patcher.exe: src/patcher.c src/patcher_lib.c src/patcher_lib.h
	$(CC) $(CFLAGS) -o $@ src/patcher.c src/patcher_lib.c

# ==========================================
#  Test executables
# ==========================================
tests: $(BUILD_DIR)/test_check.exe $(BUILD_DIR)/test_patcher.exe

$(BUILD_DIR)/test_check.exe: tests/test_check.c tests/test_harness.h
	$(CC) $(CFLAGS) -o $@ tests/test_check.c

$(BUILD_DIR)/test_patcher.exe: tests/test_patcher.c tests/test_harness.h src/patcher_lib.c src/patcher_lib.h
	$(CC) $(CFLAGS) -I. -o $@ tests/test_patcher.c src/patcher_lib.c

# ==========================================
#  Run tests
# ==========================================
test: all test-check test-patcher

test-check: $(BUILD_DIR)/check.exe $(BUILD_DIR)/test_check.exe
	@echo ""
	@echo "Running check.exe integration tests..."
	@cd $(BUILD_DIR) && ./test_check.exe

test-patcher: $(BUILD_DIR)/patcher.exe $(BUILD_DIR)/test_patcher.exe
	@echo ""
	@echo "Running patcher tests..."
	@echo "NOTE: check.exe must be running in another terminal!"
	@cd $(BUILD_DIR) && ./test_patcher.exe

# ==========================================
#  Clean
# ==========================================
clean:
	rm -rf $(BUILD_DIR)
