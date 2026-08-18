#   Copyright (C) 2023 John Törnblom
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

DESTDIR ?= /opt/ps5-payload-sdk

TOOLCHAINS := toolchain/prospero.sh \
              toolchain/prospero.mk \
              toolchain/prospero.cmake \
              toolchain/prospero.ini

TOOLS := bin/prospero-cmake \
         bin/prospero-llvm \
         bin/prospero-meson \
         bin/prospero-llvm-config \
         bin/prospero-clang \
         bin/prospero-clang++ \
         bin/prospero-deploy \
         bin/prospero-lld \
         bin/prospero-pkg-config \
         bin/prospero-nid \
         bin/prospero-fetchpkg \
         bin/prospero-cross-fix-root \
         bin/prospero-pkg

PROSPERO_PKG_DIR := prosperopkg
PROSPERO_PKG_KEYS := $(PROSPERO_PKG_DIR)/keys/passcode.bin \
	$(PROSPERO_PKG_DIR)/keys/mount_image.bin \
	$(PROSPERO_PKG_DIR)/keys/pkg_meta_rsa_key.pem
PROSPERO_PKG_DATA := $(PROSPERO_PKG_DIR)/data/right.sprx
PROSPERO_PKG_LIBRARY_SOURCES := $(PROSPERO_PKG_DIR)/src/aes_xts.cpp \
	$(PROSPERO_PKG_DIR)/src/build.cpp \
	$(PROSPERO_PKG_DIR)/src/content_id.cpp \
	$(PROSPERO_PKG_DIR)/src/crc32c.cpp \
	$(PROSPERO_PKG_DIR)/src/hash.cpp \
	$(PROSPERO_PKG_DIR)/src/image_digests.cpp \
	$(PROSPERO_PKG_DIR)/src/pfsc.cpp \
	$(PROSPERO_PKG_DIR)/src/pfs_image.cpp \
	$(PROSPERO_PKG_DIR)/src/pfs_layout.cpp \
	$(PROSPERO_PKG_DIR)/src/pfs_standalone.cpp \
	$(PROSPERO_PKG_DIR)/src/naps.cpp \
	$(PROSPERO_PKG_DIR)/src/outer_pfs.cpp \
	$(PROSPERO_PKG_DIR)/src/pfs_keys.cpp \
	$(PROSPERO_PKG_DIR)/src/pkg.cpp \
	$(PROSPERO_PKG_DIR)/src/self.cpp \
	$(PROSPERO_PKG_DIR)/src/si.cpp
PROSPERO_PKG_SOURCES := $(PROSPERO_PKG_DIR)/packager.cpp $(PROSPERO_PKG_LIBRARY_SOURCES)
PROSPERO_PKG_TEST_SOURCES := $(PROSPERO_PKG_DIR)/tests/regression.cpp $(PROSPERO_PKG_LIBRARY_SOURCES)

HOST_CXX ?= c++
PROSPERO_PKG_CXXFLAGS := -std=c++20 -O2 -DNDEBUG -DPROSPEROPKG_HAS_ZLIB=1 \
	-I$(PROSPERO_PKG_DIR)/include
ifeq ($(shell uname -s),Darwin)
BOOST_PREFIX ?= /opt/homebrew
endif
PROSPERO_PKG_CXXFLAGS += $(if $(BOOST_PREFIX),-I$(BOOST_PREFIX)/include)
PROSPERO_PKG_LDLIBS ?= -lz

LDSCRIPTS := elf_x86_64.x

.PHONY: all clean install test

all: bin/prospero-pkg

bin/prospero-pkg: $(PROSPERO_PKG_SOURCES)
	$(HOST_CXX) $(PROSPERO_PKG_CXXFLAGS) $(PROSPERO_PKG_SOURCES) $(PROSPERO_PKG_LDLIBS) -o $@

bin/prospero-pkg-tests: $(PROSPERO_PKG_TEST_SOURCES)
	$(HOST_CXX) $(PROSPERO_PKG_CXXFLAGS) $(PROSPERO_PKG_TEST_SOURCES) $(PROSPERO_PKG_LDLIBS) -o $@

test: bin/prospero-pkg-tests
	PROSPERO_PKG_KEYS_DIR=$(PROSPERO_PKG_DIR)/keys ./bin/prospero-pkg-tests

clean:
	rm -f bin/prospero-pkg bin/prospero-pkg-tests

install: install-tools install-symlinks install-ldscripts install-toolchains install-prosperopkg-keys install-prosperopkg-data

install-ldscripts: $(LDSCRIPTS)
	install -d $(DESTDIR)
	install -d $(DESTDIR)/ldscripts
	install $^ $(DESTDIR)/ldscripts
	install -d $(DESTDIR)/target/lib
	ln -sf ../../ldscripts/elf_x86_64.x $(DESTDIR)/target/lib/main.script
	ln -sf ../../ldscripts/elf_x86_64.x $(DESTDIR)/target/lib/prx.script

install-toolchains: $(TOOLCHAINS)
	install -d $(DESTDIR)
	install -d $(DESTDIR)/toolchain
	install $^ $(DESTDIR)/toolchain

install-tools: $(TOOLS)
	install -d $(DESTDIR)
	install -d $(DESTDIR)/bin
	install $^ $(DESTDIR)/bin

install-prosperopkg-keys: $(PROSPERO_PKG_KEYS)
	install -d $(DESTDIR)/share/prosperopkg/keys
	install -m 0644 $^ $(DESTDIR)/share/prosperopkg/keys

install-prosperopkg-data: $(PROSPERO_PKG_DATA)
	install -d $(DESTDIR)/share/prosperopkg
	install -m 0644 $^ $(DESTDIR)/share/prosperopkg/right.sprx

install-symlinks:
	install -d $(DESTDIR)
	install -d $(DESTDIR)/bin
	ln -sf prospero-llvm $(DESTDIR)/bin/llvm-ar
	ln -sf prospero-llvm $(DESTDIR)/bin/llvm-nm
	ln -sf prospero-llvm $(DESTDIR)/bin/llvm-objcopy
	ln -sf prospero-llvm $(DESTDIR)/bin/llvm-ranlib
	ln -sf prospero-llvm $(DESTDIR)/bin/llvm-strip
	ln -sf prospero-llvm $(DESTDIR)/bin/clang
	ln -sf prospero-llvm $(DESTDIR)/bin/clang++
	ln -sf prospero-llvm $(DESTDIR)/bin/clang-cpp
	ln -sf prospero-llvm $(DESTDIR)/bin/ld.lld
	ln -sf llvm-ar $(DESTDIR)/bin/prospero-ar
	ln -sf llvm-nm $(DESTDIR)/bin/prospero-nm
	ln -sf llvm-objcopy $(DESTDIR)/bin/prospero-objcopy
	ln -sf llvm-ranlib $(DESTDIR)/bin/prospero-ranlib
	ln -sf llvm-strip $(DESTDIR)/bin/prospero-strip
	ln -sf prospero-clang $(DESTDIR)/bin/prospero-as
