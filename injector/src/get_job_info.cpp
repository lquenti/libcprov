#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdlib>
#include <string>

std::string get_job_id() {
    return std::getenv("SLURM_JOB_ID") ? std::getenv("SLURM_JOB_ID") : "1";
}

std::string get_cluster_name() {
    return std::getenv("SLURM_CLUSTER_NAME") ? std::getenv("SLURM_CLUSTER_NAME")
                                             : "cname1";
}

std::string get_job_name() {
    return std::getenv("SLURM_JOB_NAME") ? std::getenv("SLURM_JOB_NAME")
                                         : "test_name";
}

std::string get_username() {
    if (passwd* pw = getpwuid(getuid())) {
        if (pw->pw_name) return std::string(pw->pw_name);
    }
    if (const char* u = std::getenv("USER")) return std::string(u);
    if (const char* u = std::getenv("LOGNAME")) return std::string(u);
    return {};
}
