#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <iomanip>
#include <algorithm>

#include "boost/filesystem.hpp"
#include "boost/program_options.hpp"
#include "boost/crc.hpp"

namespace fs = boost::filesystem;
namespace po = boost::program_options;

// Hashing function
unsigned int calculate_crc32(const std::string& data) {
    boost::crc_32_type result;
    result.process_bytes(data.data(), data.length());
    return result.checksum();
}

// Case-insensitive string comparison
std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

// File Processing
std::vector<unsigned int> calculate_file_hashes(const fs::path& path, size_t block_size, std::function<unsigned int(const std::string&)> hash_function) {
    std::vector<unsigned int> hashes;
    try {
        std::ifstream file(path.string(), std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Error opening file: " << path << std::endl;
            return {}; // Return empty vector if file cannot be opened
        }

        std::string block(block_size, 0);
        while (file.read(block.data(), block_size) || file.gcount() > 0) {
            block.resize(file.gcount());  // Resize to actual bytes read
            hashes.push_back(hash_function(block));
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error reading file: " << path << ": " << e.what() << std::endl;
        return {}; // Return empty vector on error
    }
    return hashes;
}

bool should_process(const fs::path& path, size_t min_size, const std::vector<std::string>& masks) {
    if (!fs::is_regular_file(path)) return false;
    if (fs::file_size(path) < min_size) return false;

    if (!masks.empty()) {
        std::string filename = path.filename().string();
        std::string lower_filename = to_lower(filename);

        return std::any_of(masks.begin(), masks.end(), [&](const std::string& mask) {
            return lower_filename.find(to_lower(mask)) != std::string::npos;
            });
    }
    return true;
}

// Main
int main(int argc, char* argv[]) {

    po::options_description desc("Usage: bayan [options] directories...");
    desc.add_options()
        ("help", "Produce help message")
        ("scan-dir", po::value<std::vector<std::string>>()->multitoken(), "Directories to scan (can be multiple)")
        ("exclude-dir", po::value<std::vector<std::string>>()->multitoken(), "Directories to exclude (can be multiple)")
        ("level", po::value<int>()->default_value(0), "Scan level (0 = only specified directories)")
        ("min-size", po::value<size_t>()->default_value(1), "Minimum file size (bytes)")
        ("mask", po::value<std::vector<std::string>>()->multitoken(), "File name masks (case-insensitive)")
        ("block-size", po::value<size_t>()->default_value(1024), "Block size (S) for reading files")
        ("hash-algorithm", po::value<std::string>()->default_value("crc32"), "Hash algorithm (crc32)");

    po::positional_options_description p;
    p.add("scan-dir", -1);

    po::variables_map vm;
    try {
        po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
        po::notify(vm);
    }
    catch (const po::error& e) {
        std::cerr << "Error parsing command line: " << e.what() << std::endl;
        std::cerr << desc << std::endl;
        return 1;
    }

    if (vm.count("help")) {
        std::cout << desc << std::endl;
        return 0;
    }

    // Get options from command line
    std::vector<std::string> scan_dirs = vm.count("scan-dir") ? vm["scan-dir"].as<std::vector<std::string>>() : std::vector<std::string>{};
    if (scan_dirs.empty()) {
        std::cerr << "Error: At least one scan directory must be specified." << std::endl;
        std::cerr << desc << std::endl;
        return 1;
    }

    std::vector<std::string> exclude_dirs = vm.count("exclude-dir") ? vm["exclude-dir"].as<std::vector<std::string>>() : std::vector<std::string>{};
    int level = vm["level"].as<int>();
    size_t min_size = vm["min-size"].as<size_t>();
    
    std::vector<std::string> masks = vm.count("mask") ? vm["mask"].as<std::vector<std::string>>() : std::vector<std::string>{};
    
    size_t block_size = vm["block-size"].as<size_t>();
    std::string hash_algorithm = vm["hash-algorithm"].as<std::string>();

    // Select hash function
    std::function<unsigned int(const std::string&)> hash_function;
    if (hash_algorithm == "crc32") {
        hash_function = calculate_crc32;
    } else {
        std::cerr << "Error: Unsupported hash algorithm: " << hash_algorithm << std::endl;
        return 1;
    }

    // Data structure
    //std::unordered_map<std::vector<unsigned int>, std::vector<fs::path>> hash_to_files; // no work
    std::map<std::vector<unsigned int>, std::vector<fs::path>> hash_to_files;

    // Scan directories
    for (const auto& scan_dir : scan_dirs) {
        fs::path scan_path(scan_dir);
        if (!fs::exists(scan_path)) {
            std::cerr << "Warning: Scan directory does not exist: " << scan_dir << std::endl;
            continue;
        }

        for (fs::recursive_directory_iterator it(scan_path, fs::directory_options::skip_permission_denied), end; it != end; it++) {
            if (level == 0 && it.depth() > 0) {
                it.disable_recursion_pending();
                continue;
            }

            fs::path current_path = *it;

            bool excluded = false;
            for (const auto& exclude_dir : exclude_dirs) {
                if (fs::equivalent(current_path, fs::path(exclude_dir))) {
                    if (fs::is_directory(current_path)) {
                        it.disable_recursion_pending();
                    }
                    excluded = true;
                    break;
                }
            }
            if (excluded) continue;

            if (should_process(current_path, min_size, masks)) {
                std::vector<unsigned int> hashes = calculate_file_hashes(current_path, block_size, hash_function);
                if (!hashes.empty()) {
                    hash_to_files[hashes].push_back(current_path);
                }
            }
        }
    }

    // Output Results
    bool first_group = true;
    for (const auto& [hashes, files] : hash_to_files) {
        if (files.size() > 1) {
            if (!first_group) {
                std::cout << std::endl;
            }
            first_group = false;
            for (const auto& file : files) {
                std::cout << file.string() << std::endl;
            }
        }
    }
    system("pause");
    return 0;
}