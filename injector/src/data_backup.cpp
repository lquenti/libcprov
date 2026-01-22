#include <filesystem>
#include <string>

#include "model.hpp"

namespace fs = std::filesystem;

void copy_folder(const fs::path& src, const fs::path& dst) {
    fs::create_directories(dst);
    fs::copy(
        src, dst,
        fs::copy_options::recursive | fs::copy_options::overwrite_existing);
}

void backup_data_pre_exec(const std::string& exec_path) {
    std::string temporary_storage_path = "";
    // copy_folder(exec_path, temporary_storage_path);
}

void ingest_prov_data(
    OperationsDataBackupFormat& operations_data_backup_format) {
}
