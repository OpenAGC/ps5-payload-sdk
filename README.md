# ps5-payload-sdk
This is an SDK for developing payloads targeted at exploited PS5s. ELF loaders
known to work include:
- [ps5-payload-elfldr][elfldr]
- [ps5-payload-websrv][websrv]
- [bdj-ipv6-hen][bdj-ipv6-hen]
- [elfloader][elfloader] via [ps5-jar-loader]
- [remote_lua_loader][remote_lua_loader]

Several artifacts in this repository originate from the [PS5SDK][PS5SDK] project.

## Prerequisites
On Debian-flavored operating systems, you can invoke the following commands to
install dependencies used by the SDK.
```console
john@localhost:ps5-payload-dev/sdk$ sudo apt-get update && sudo apt-get upgrade # optional
john@localhost:ps5-payload-dev/sdk$ sudo apt-get install bash clang-18 lld-18 zlib1g-dev # required
john@localhost:ps5-payload-dev/sdk$ sudo apt-get install socat cmake meson pkg-config # optional
```

If you are using Fedora, you can install dependencies as follows (tested with version 41):
```console
john@localhost:ps5-payload-dev/sdk$ sudo dnf install bash llvm-devel clang lld zlib-devel # required
john@localhost:ps5-payload-dev/sdk$ sudo dnf install socat cmake meson pkg-config # optional
```

If you are using macOS, you can install them using the [Homebrew Package Manager][macos-brew] (tested with macOS Sequoia):
```console
john@localhost:ps5-payload-dev/sdk$ brew install llvm@18 # required
john@localhost:ps5-payload-dev/sdk$ export LLVM_CONFIG=/opt/homebrew/opt/llvm@18/bin/llvm-config # required
john@localhost:ps5-payload-dev/sdk$ brew install socat cmake meson # optional
```

## Quick-start
You can download a binary distribution of the SDK from [the latest release page][latest-rel],
then install it to your local storage, e.g,
```console
john@localhost:tmp$ wget https://github.com/ps5-payload-dev/sdk/releases/latest/download/ps5-payload-sdk.zip
john@localhost:tmp$ sudo unzip -d /opt ps5-payload-sdk.zip
```
Assuming you have all the prerequisites and you are on a POSIX system,
the binary distribution should work regardless of CPU architecture, e.g., x86_64, aarch64.

## Usage
```console
john@localhost:ps5-payload-dev/sdk$ export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
john@localhost:ps5-payload-dev/sdk$ make -C samples/hello_world
john@localhost:ps5-payload-dev/sdk$ export PS5_HOST=ps5; export PS5_PORT=9021
john@localhost:ps5-payload-dev/sdk$ make -C samples/hello_world test
```

The host install also provides `prospero-pkg`, which converts a 64-bit SDK ELF
to a fake `eboot.bin` SELF and builds a PS5 debug `.pkg` in one step. The input
may be an ELF/SELF file or an app directory containing `eboot.bin` or
`eboot.elf` (and optional `sce_sys` assets):
```console
john@localhost:app$ prospero-pkg payload.elf app.pkg \
    UP0000-FAKE02932_00-0000000000000000 \
    --title "My payload" --title-id FAKE02932 \
    --eboot-output eboot.bin
```
The default passcode is 32 zeroes, matching the debug package workflow. Use
`--passcode`, `--version`, and `--compression none|zlib|kraken` for the other
LibProsperoPkg build options. When `sce_sys/about/right.sprx` is not supplied,
the builder injects the bundled reference debug module from
`$PS5_PAYLOAD_SDK/share/prosperopkg/right.sprx` (or the path in
`$PROSPERO_PKG_RIGHT_SPRX`). A missing reference resource is reported as an
error instead of silently producing a different package. The package builder is vendored under
`host/prosperopkg` and remains GPLv3+ like the SDK.

This is the current native LibProsperoPkg-seregonwar builder baseline. The
inner PS5 PFS layout is ported from SharpProspero's non-signed v2 builder,
including its superblock, D32 inode table, flat-path table, directory entries,
and block placement. The package path uses the data-first layout and emits a
native `naps_pkg_layout.dat` descriptor alongside the encrypted outer PFS
wrapper with its D32 inode table, FLT/dirent tables, block digests, and
superblock ICV. CNT/FIH metadata, reference-key RSA sealing, and digest
rollups are generated for the debug format, and debug FIH images include the
trailing STORED SI install-metadata ZIP (`naps_meta_18`, `naps_meta_300/301/302/308`,
`pfsimage.xml`, the PlayGo copy, and per-64 KiB CRCs). If `sce_sys/keystone` is absent it
is generated from the passcode using the PS5 debug HMAC construction. Ordinary inner files and metadata
use native PFSv3 Kraken compression when the SharpProspero 15/16 threshold is
met; executable modules and `sce_sys/keystone` remain raw. No PS5 console
validation has been performed, so treat the generated `.pkg` as experimental.

## Building the SDK
```console
john@localhost:ps5-payload-dev/sdk$ make DESTDIR=/opt/ps5-payload-sdk install
john@localhost:ps5-payload-dev/sdk$ export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
john@localhost:ps5-payload-dev/sdk$ ./libcxx.sh # fetch, build, and install libcxx
```

## Adding new SCE Libs
If you have decrypted sprx files that you would like to interact with, you can
build stubs for them as follows:
```console
john@localhost:ps5-payload-dev/sdk$ sudo apt-get install wget python3 python3-pyelftools
john@localhost:ps5-payload-dev/sdk$ ln -s /path/to/sprx/libSceXYZ.sprx sce_stubs/libSceXYZ.sprx
john@localhost:ps5-payload-dev/sdk$ make -C sce_stubs stubs
john@localhost:ps5-payload-dev/sdk$ make DESTDIR=/opt/ps5-payload-sdk install
```

## Reporting Bugs
If you encounter problems with the SDK, please [file a github issue][issues].
If you plan on sending pull requests which affect more than a few lines of code,
please file an issue before you start to work on you changes. This will allow us
to discuss the solution properly before you commit time and effort.

## License
Files in the folder include/freebsd are licenced under BSD licences.
Unless otherwhise explicitly stated inside a file, the rest are licensed under
the GPLv3+.

[issues]: https://github.com/ps5-payload-dev/sdk/issues/new
[latest-rel]: https://github.com/ps5-payload-dev/sdk/releases/latest
[elfldr]: https://github.com/ps5-payload-dev/elfldr
[websrv]: https://github.com/ps5-payload-dev/websrv
[bdj-ipv6-hen]: https://github.com/ps5-payload-dev/bdj-ipv6-hen
[remote_lua_loader]: https://github.com/shahrilnet/remote_lua_loader
[elfloader]: https://github.com/cryonumb/elfloader
[ps5-jar-loader]: https://github.com/hammer-83/ps5-jar-loader
[PS5SDK]: https://github.com/PS5Dev/PS5SDK
[macos-brew]: https://brew.sh
