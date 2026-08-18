// SDK-facing PS5 ELF/PKG packager.
// SPDX-License-Identifier: GPL-3.0-or-later

#include <prosperopkg/build.hpp>
#include <prosperopkg/content_id.hpp>
#include <prosperopkg/self.hpp>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::vector<std::byte> read_file(const fs::path& path)
{
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("could not open input: " + path.string());
    }
    input.seekg(0, std::ios::end);
    const auto end = input.tellg();
    if (end < 0) {
        throw std::runtime_error("could not determine input size: " + path.string());
    }
    input.seekg(0, std::ios::beg);
    std::vector<std::byte> data(static_cast<std::size_t>(end));
    if (!data.empty()) {
        input.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!input) {
            throw std::runtime_error("could not read input: " + path.string());
        }
    }
    return data;
}

void write_file(const fs::path& path, std::span<const std::byte> data)
{
    if (!path.parent_path().empty()) {
        fs::create_directories(path.parent_path());
    }
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        throw std::runtime_error("could not create output: " + path.string());
    }
    output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!output) {
        throw std::runtime_error("could not write output: " + path.string());
    }
}

void copy_tree(const fs::path& source, const fs::path& destination)
{
    fs::create_directories(destination);
    for (const auto& entry : fs::recursive_directory_iterator(source)) {
        const auto relative = fs::relative(entry.path(), source);
        const auto target = destination / relative;
        if (entry.is_directory()) {
            fs::create_directories(target);
        } else if (entry.is_regular_file()) {
            fs::create_directories(target.parent_path());
            fs::copy_file(entry.path(), target, fs::copy_options::overwrite_existing);
        }
    }
}

fs::path make_temp_directory()
{
    const auto ticks = std::chrono::steady_clock::now().time_since_epoch().count();
    const auto path = fs::temp_directory_path() / ("prospero-pkg-" + std::to_string(ticks));
    fs::create_directories(path);
    return path;
}

void prepare_eboot(const fs::path& input, const fs::path& staging)
{
    const auto data = read_file(input);
    if (prosperopkg::is_elf(data)) {
        const auto self = prosperopkg::make_fself(data);
        write_file(staging / "eboot.bin", self);
    } else if (prosperopkg::is_self(data)) {
        std::string error;
        if (!prosperopkg::validate_self(data, &error)) {
            throw std::runtime_error("input SELF failed validation: " + error);
        }
        write_file(staging / "eboot.bin", data);
    } else {
        throw std::runtime_error("input is neither a 64-bit ELF nor a fake SELF: " + input.string());
    }
}

bool is_module_candidate(const fs::path& path)
{
    std::string name = path.filename().string();
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return name == "eboot.bin" || name.ends_with(".elf") ||
           name.ends_with(".prx") || name.ends_with(".sprx");
}

void fake_sign_modules(const fs::path& staging)
{
    std::vector<fs::path> candidates;
    for (const auto& entry : fs::recursive_directory_iterator(staging)) {
        if (entry.is_regular_file() && is_module_candidate(entry.path())) {
            candidates.push_back(entry.path());
        }
    }
    for (const auto& path : candidates) {
        const auto data = read_file(path);
        if (prosperopkg::is_elf(data)) {
            write_file(path, prosperopkg::make_fself(data));
        } else if (prosperopkg::is_self(data)) {
            std::string error;
            if (!prosperopkg::validate_self(data, &error)) {
                throw std::runtime_error("module SELF failed validation (" + path.string() + "): " + error);
            }
        }
    }
}

struct Options {
    fs::path input;
    fs::path output;
    std::string content_id;
    std::string passcode = "00000000000000000000000000000000";
    std::string title;
    std::string title_id;
    std::string version = "01.00";
    fs::path eboot_output;
    prosperopkg::InnerCompression compression = prosperopkg::InnerCompression::none;
};

void usage(const char* program)
{
    std::cerr
        << "usage: " << program << " <elf-or-app-dir> <output.pkg> <content-id> [options]\n\n"
        << "Converts an SDK ELF to eboot.bin (fake SELF) and builds a PS5 debug FIH package.\n"
        << "When the input is a directory it is copied as the app staging directory; an\n"
        << "existing eboot.bin is preserved, otherwise eboot.elf is converted.\n\n"
        << "options:\n"
        << "  --passcode <32 chars>   Package passcode (default: 32 zeroes)\n"
        << "  --title <name>          Title for generated sce_sys/param.json\n"
        << "  --title-id <id>         Nine-character title ID\n"
        << "  --version <01.00|01.000.000>  Master or content version (default: 01.00)\n"
        << "  --eboot-output <path>   Also keep the generated eboot.bin\n"
        << "  --compression <none|zlib|kraken>  Inner image form (default: none)\n"
        << "  -h, --help              Show this help\n";
}

Options parse_options(int argc, char** argv)
{
    if (argc == 2 && (std::string_view(argv[1]) == "-h" || std::string_view(argv[1]) == "--help")) {
        usage(argv[0]);
        std::exit(0);
    }
    if (argc < 4) {
        usage(argv[0]);
        throw std::runtime_error("missing required arguments");
    }
    Options options{fs::path(argv[1]), fs::path(argv[2]), argv[3]};
    for (int index = 4; index < argc; ++index) {
        const std::string_view arg(argv[index]);
        const auto value = [&](const char* name) {
            if (index + 1 >= argc) {
                throw std::runtime_error(std::string(name) + " requires a value");
            }
            return std::string(argv[++index]);
        };
        if (arg == "-h" || arg == "--help") {
            usage(argv[0]);
            std::exit(0);
        } else if (arg == "--passcode") {
            options.passcode = value("--passcode");
        } else if (arg == "--title") {
            options.title = value("--title");
        } else if (arg == "--title-id") {
            options.title_id = value("--title-id");
        } else if (arg == "--version") {
            options.version = value("--version");
        } else if (arg == "--eboot-output") {
            options.eboot_output = value("--eboot-output");
        } else if (arg == "--compression") {
            const auto compression = value("--compression");
            if (compression == "none") {
                options.compression = prosperopkg::InnerCompression::none;
            } else if (compression == "zlib") {
                options.compression = prosperopkg::InnerCompression::zlib;
            } else if (compression == "kraken") {
                options.compression = prosperopkg::InnerCompression::kraken;
            } else {
                throw std::runtime_error("unknown compression: " + compression);
            }
        } else {
            throw std::runtime_error("unknown option: " + std::string(arg));
        }
    }
    if (!prosperopkg::is_valid_content_id(options.content_id)) {
        throw std::runtime_error("invalid content ID: " + options.content_id);
    }
    if (options.passcode.size() != 32) {
        throw std::runtime_error("passcode must contain exactly 32 characters");
    }
    if (!options.title_id.empty() && !prosperopkg::is_valid_title_id(options.title_id)) {
        throw std::runtime_error("invalid title ID: " + options.title_id);
    }
    return options;
}

fs::path package(const Options& options)
{
    const auto staging = make_temp_directory();
    try {
        if (fs::is_directory(options.input)) {
            copy_tree(options.input, staging);
            const auto eboot = staging / "eboot.bin";
            if (!fs::is_regular_file(eboot)) {
                const auto elf = staging / "eboot.elf";
                if (!fs::is_regular_file(elf)) {
                    throw std::runtime_error("app directory must contain eboot.bin or eboot.elf");
                }
                prepare_eboot(elf, staging);
                fs::remove(elf);
            }
            fake_sign_modules(staging);
        } else if (fs::is_regular_file(options.input)) {
            prepare_eboot(options.input, staging);
        } else {
            throw std::runtime_error("input path does not exist: " + options.input.string());
        }

        if (!options.eboot_output.empty()) {
            const auto eboot = read_file(staging / "eboot.bin");
            write_file(options.eboot_output, eboot);
        }

        const auto output_folder = options.output.parent_path().empty()
            ? fs::path(".") : options.output.parent_path();
        prosperopkg::PackageBuildOptions build_options;
        build_options.source_folder = staging;
        build_options.output_folder = output_folder;
        build_options.content_id = options.content_id;
        build_options.passcode = options.passcode;
        build_options.title = options.title;
        build_options.title_id = options.title_id;
        build_options.version = options.version;
        build_options.mode = prosperopkg::BuildMode::homebrew;
        build_options.output_format = prosperopkg::BuildOutputFormat::debug_image;
        build_options.inner_compression = options.compression;

        const auto built = prosperopkg::build_package(build_options);
        const auto requested = fs::absolute(options.output);
        fs::create_directories(requested.parent_path());
        if (fs::absolute(built) != requested) {
            fs::remove(requested);
            fs::rename(built, requested);
        }
        fs::remove_all(staging);
        return requested;
    } catch (...) {
        fs::remove_all(staging);
        throw;
    }
}

} // namespace

int main(int argc, char** argv)
{
    try {
        const auto options = parse_options(argc, argv);
        const auto output = package(options);
        std::cout << "Wrote PS5 package: " << output << '\n';
        std::cerr
            << "note: debug FIH/CNT metadata uses the native engineering implementation; official retail RSA signing "
               "and console validation still require Sony signing material and hardware testing\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "prospero-pkg: " << error.what() << '\n';
        return 1;
    }
}
