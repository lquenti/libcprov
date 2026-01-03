#include <algorithm>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "model.hpp"

std::string dot_escape_label(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\\' || c == '"') out.push_back('\\');
        if (c == '\n' || c == '\r' || c == '\t')
            out.push_back(' ');
        else
            out.push_back(c);
    }
    return out;
}

std::string html_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '&')
            out += "&amp;";
        else if (c == '<')
            out += "&lt;";
        else if (c == '>')
            out += "&gt;";
        else if (c == '"')
            out += "&quot;";
        else if (c == '\n' || c == '\r' || c == '\t')
            out.push_back(' ');
        else
            out.push_back(c);
    }
    return out;
}

std::string row_color_for_ops(const Operations& ops) {
    if (ops.write) return "#0072B2";
    if (ops.read) return "#D55E00";
    if (ops.deleted) return "#009E73";
    return "#ffffff";
}

std::vector<const ExecData*> sorted_execs(const JobData& job) {
    std::vector<const ExecData*> v;
    v.reserve(job.execs.size());
    for (const auto& e : job.execs) v.push_back(&e);
    std::sort(v.begin(), v.end(), [](const ExecData* a, const ExecData* b) {
        if (a->start_time != b->start_time)
            return a->start_time < b->start_time;
        return a->exec_id < b->exec_id;
    });
    return v;
}

std::vector<std::pair<uint64_t, const Process*>> sorted_processes(
    const ExecData& exec) {
    std::vector<std::pair<uint64_t, const Process*>> v;
    v.reserve(exec.process_map.size());
    for (const auto& [pid, p] : exec.process_map) v.push_back({pid, &p});
    std::sort(v.begin(), v.end(),
              [](auto& a, auto& b) { return a.first < b.first; });
    return v;
}

std::vector<std::pair<std::string, Operations>> sorted_operations(
    const Process& p) {
    std::vector<std::pair<std::string, Operations>> v;
    v.reserve(p.operation_map.size());
    for (const auto& [path, ops] : p.operation_map) v.push_back({path, ops});
    std::sort(v.begin(), v.end(),
              [](auto& a, auto& b) { return a.first < b.first; });
    return v;
}

std::string exec_prefix(size_t idx) {
    return std::string(1, char('A' + (idx % 26)));
}

static std::string proc_node_id(const std::string& epref, size_t pidx1) {
    return epref + "_proc" + std::to_string(pidx1);
}

static std::string process_table_label(
    const std::string& title,
    const std::vector<std::pair<std::string, Operations>>& ops) {
    std::ostringstream os;
    os << "<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\" "
          "CELLPADDING=\"4\" WIDTH=\"0\">";
    os << "<TR><TD BGCOLOR=\"#20262e\" ALIGN=\"LEFT\"><FONT "
          "COLOR=\"#ffffff\"><B>"
       << html_escape(title) << "</B></FONT></TD></TR>";
    for (const auto& [path, op] : ops) {
        if (path.rfind("pipe:[", 0) == 0) continue;
        os << "<TR><TD ALIGN=\"LEFT\" BGCOLOR=\"" << row_color_for_ops(op)
           << "\"><FONT COLOR=\"#000000\">" << html_escape(path)
           << "</FONT></TD></TR>";
    }
    os << "</TABLE>";
    return os.str();
}

std::string build_graph_header(const std::string& job_name,
                               const std::string& username, uint64_t start_time,
                               uint64_t end_time) {
    std::ostringstream os;
    os << R"(graph [rankdir=TB,splines=ortho,newrank=true,labelloc="t",labeljust="l",pad=0.2,label=<)";
    os << R"(<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0"><TR>)";
    os << R"(<TD VALIGN="top"><TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="0">)";
    os << R"(<TR><TD ALIGN="LEFT"><B>Job Name:  </B> )" << html_escape(job_name)
       << R"(</TD></TR>)";
    os << R"(<TR><TD ALIGN="LEFT"><B>User:  </B> )" << html_escape(username)
       << R"(</TD></TR>)";
    os << R"(<TR><TD ALIGN="LEFT"><B>Start:  </B> )" << start_time
       << R"(</TD></TR>)";
    os << R"(<TR><TD ALIGN="LEFT"><B>End:   </B> )" << end_time
       << R"(</TD></TR>)";
    os << R"(</TABLE></TD>)";
    os << R"(<TD WIDTH="20"></TD>)";
    os << R"(<TD VALIGN="top"><TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">)";
    os << R"(<TR><TD COLSPAN="6"><B>Legend</B></TD></TR>)";
    os << R"(<TR>)";
    os << R"(<TD BGCOLOR="#0072B2" WIDTH="14" HEIGHT="14"></TD><TD ALIGN="LEFT">write</TD>)";
    os << R"(<TD BGCOLOR="#D55E00" WIDTH="14" HEIGHT="14"></TD><TD ALIGN="LEFT">read</TD>)";
    os << R"(<TD BGCOLOR="#009E73" WIDTH="14" HEIGHT="14"></TD><TD ALIGN="LEFT">delete</TD>)";
    os << R"(</TR></TABLE></TD>)";
    os << R"(</TR></TABLE>)";
    os << R"(>];)";
    return os.str();
}

std::string build_graph_dot(const JobData& job_data) {
    std::ostringstream os;
    os << "digraph G{\n";
    os << build_graph_header(job_data.job_name, job_data.username,
                             job_data.start_time, job_data.end_time)
       << "\n";
    os << "node[shape=plaintext];\n";
    os << "edge[color=\"gray60\",penwidth=1.4,arrowsize=0.8,fontcolor="
          "\"gray80\"];\n";
    auto execs = sorted_execs(job_data);
    for (size_t ei = 0; ei < execs.size(); ++ei) {
        const ExecData& ex = *execs[ei];
        std::string ep = exec_prefix(ei);
        os << "subgraph cluster_" << ep << "{label=\""
           << dot_escape_label(ex.command) << "\";\n";
        auto procs = sorted_processes(ex);
        size_t pcount = procs.size();
        std::unordered_map<std::string, size_t> cmd_to_idx;
        for (size_t pidx0 = 0; pidx0 < pcount; ++pidx0) {
            const Process& proc = *procs[pidx0].second;
            size_t pidx1 = pidx0 + 1;
            cmd_to_idx[proc.process_command] = pidx1;
            auto ops = sorted_operations(proc);
            os << proc_node_id(ep, pidx1) << "[label=<"
               << process_table_label(proc.process_command, ops) << ">];\n";
        }
        if (pcount >= 2) {
            os << proc_node_id(ep, 1);
            for (size_t k = 2; k <= pcount; ++k)
                os << "->" << proc_node_id(ep, k);
            os << "[style=invis,weight=100000,constraint=true];\n";
        }
        auto it_parent = cmd_to_idx.find("sh -c fortune | cowsay");
        if (it_parent != cmd_to_idx.end()) {
            size_t parent = it_parent->second;
            auto it_fortune = cmd_to_idx.find("fortune");
            if (it_fortune != cmd_to_idx.end()) {
                os << proc_node_id(ep, parent) << "->"
                   << proc_node_id(ep, it_fortune->second)
                   << "[xlabel=\"\",fontcolor=\"gray30\",fontsize=10,minlen=1,"
                      "constraint=false];\n";
            }
            auto it_cowsay = cmd_to_idx.find("perl /usr/bin/cowsay");
            if (it_cowsay != cmd_to_idx.end()) {
                os << proc_node_id(ep, parent) << "->"
                   << proc_node_id(ep, it_cowsay->second)
                   << "[xlabel=\"\",fontcolor=\"gray30\",fontsize=10,minlen=1,"
                      "constraint=false];\n";
            }
        }
        os << "}\n";
    }
    os << "}\n";
    return os.str();
}

void save_graph_to_file(const std::string& graph_string,
                        const std::string& filename) {
    std::ofstream out(filename);
    out << graph_string;
    out.close();
}

void build_graph(const JobData& job_data) {
    save_graph_to_file(build_graph_dot(job_data),
                       "/dev/shm/libcprov/graphviz.dot");
}
