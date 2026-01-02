#include <model.hpp>
#include <string>
#include <vector>

std::string build_header(const std::string& type,
                         const std::string& path_access,
                         const std::string& slurm_job_id,
                         const std::string& slurm_cluster_name);

std::string build_start_json_output(const std::string& job_name,
                                    const std::string& username,
                                    const std::string& path_start,
                                    const std::string& json_start_extra);

std::string build_end_json_output(const std::string& json_end_extra);

std::string build_json_array(
    const std::vector<std::string>& json_object_vector);

std::string build_exec_json_output(const std::string& path_exec,
                                   const std::string& json_exec,
                                   const std::string& cmd,
                                   ProcessedExecData prcoessed_exec_data);
