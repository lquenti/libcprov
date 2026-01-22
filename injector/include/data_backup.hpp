#include <string>

#include "model.hpp"

void backup_data_pre_exec(const std::string& exec_path);

void ingest_prov_data(
    OperationsDataBackupFormat& operations_data_backup_format);
