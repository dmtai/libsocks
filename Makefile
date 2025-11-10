CMAKE_OPTIONS ?= 
NPROCS ?= $(shell nproc)
CLANG_FORMAT ?= clang-format
CMAKE_TOOL ?= cmake
TESTS_TOOL ?= ./socks5_tests

.PHONY: all
all: conan-install-debug build-debug

build_debug/Makefile:
	@mkdir -p build_debug
	@cd build_debug && \
      $(CMAKE_TOOL) $(CMAKE_OPTIONS) --preset=linux-debug ..

build_release/Makefile:
	@mkdir -p build_release
	@cd build_release && \
      $(CMAKE_TOOL) $(CMAKE_OPTIONS) --preset=linux-release ..

.PHONY: cmake-debug cmake-release
cmake-debug cmake-release: cmake-%: build_%/Makefile

.PHONY: build-debug build-release
build-debug build-release: build-%: cmake-%
	@$(CMAKE_TOOL) --build build_$* -j $(NPROCS)

.PHONY: test-debug test-release
test-debug test-release: test-%:
	@cd build_$*/tests && \
		$(TESTS_TOOL) $(TESTS_ARGS)

.PHONY: conan-install-release
conan-install-release:
	@conan install . \
		--output-folder=third_party_build --build=missing -s build_type=Release

.PHONY: conan-install-debug
conan-install-debug:
	@conan install . \
		--output-folder=third_party_build --build=missing -s build_type=Debug

.PHONY: format
format:
	@find src -name '*pp' -type f | xargs $(CLANG_FORMAT) -i
	@find include -name '*pp' -type f | xargs $(CLANG_FORMAT) -i
	@find tests -name '*pp' -type f | xargs $(CLANG_FORMAT) -i
	@find examples -name '*pp' -type f | xargs $(CLANG_FORMAT) -i

.PHONY: clean
clean:
	@rm -rf build
	@rm -rf build_*

.PHONY: clean-all
clean-all:
	@rm -rf build
	@rm -rf third_party_build
	@rm -rf build_*