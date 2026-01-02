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

std::string fill_for_ops(const Operations& ops) {
    std::vector<std::string> cols;
    if (ops.read) cols.push_back("#D55E00");
    if (ops.write) cols.push_back("#0072B2");
    if (ops.deleted) cols.push_back("#009E73");
    if (cols.empty()) return "\"white\"";
    if (cols.size() == 1) return "\"" + cols[0] + "\"";
    std::string joined;
    for (size_t i = 0; i < cols.size(); ++i) {
        if (i) joined += ":";
        joined += cols[i];
    }
    return "\"" + joined + "\"";
}

std::string style_for_ops(const Operations& ops) {
    int n = int(ops.read) + int(ops.write) + int(ops.deleted);
    return (n >= 2) ? "wedged" : "filled";
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

std::string node_name(const std::string& pref, size_t n) {
    return pref + "_n" + std::to_string(n);
}

std::string exec_anchor(const std::string& pref) {
    return pref + "_anchor";
}

std::string build_graph_header(const std::string& job_name,
                               const std::string& username, uint64_t start_time,
                               uint64_t end_time) {
    std::ostringstream os;
    os << R"(graph [
      rankdir=TB, splines=ortho, newrank=true,
      labelloc="t", labeljust="l",
      pad=0.2,
      label=<
        <TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0">
          <TR>
            <!-- Left: compact stacked details -->
            <TD VALIGN="top">
              <TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0" CELLPADDING="0">
                <TR><TD ALIGN="LEFT"><B>Job Name:  </B> )";
    os << job_name;
    os << R"(</TD></TR>
                <TR><TD ALIGN="LEFT"><B>User:  </B> )";
    os << username;
    os << R"(</TD></TR>
                <TR><TD ALIGN="LEFT"><B>Start:  </B> )";
    os << std::to_string(start_time);
    os << R"(</TD></TR>
                <TR><TD ALIGN="LEFT"><B>End:   </B> )";
    os << std::to_string(end_time);
    os << R"(</TD></TR>
              </TABLE>
            </TD>
            <TD WIDTH="20"></TD>
            <TD VALIGN="top">
              <TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">
                <TR><TD COLSPAN="8"><B>Legend</B></TD></TR>
                <TR>
                  <TD BGCOLOR="#0072B2" WIDTH="14" HEIGHT="14"></TD>
                  <TD ALIGN="LEFT">write</TD>
                  <TD BGCOLOR="#D55E00" WIDTH="14" HEIGHT="14"></TD>
                  <TD ALIGN="LEFT">read</TD>
                  <TD BGCOLOR="#009E73" WIDTH="14" HEIGHT="14"></TD>
                  <TD ALIGN="LEFT">delete</TD>
                </TR>
              </TABLE>
            </TD>
          </TR>
        </TABLE>
      >
    ];)";
    return os.str();
}

std::string build_graph_dot(const JobData& job_data) {
    std::ostringstream os;
    os << "digraph G { ";
    os << build_graph_header(job_data.job_name, job_data.username,
                             job_data.start_time, job_data.end_time);
    os << "\n";
    auto execs = sorted_execs(job_data);
    std::vector<std::string> pref(execs.size());
    for (size_t i = 0; i < execs.size(); ++i) pref[i] = exec_prefix(i);
    std::vector<size_t> node_counts(execs.size(), 0);
    for (size_t ei = 0; ei < execs.size(); ++ei) {
        const ExecData& ex = *execs[ei];
        auto procs = sorted_processes(ex);
        size_t n = 0;
        for (auto& [pid, pptr] : procs) n += sorted_operations(*pptr).size();
        node_counts[ei] = n;
    }
    size_t global_max_rows = 0;
    for (size_t n : node_counts) global_max_rows = std::max(global_max_rows, n);
    for (size_t ei = 0; ei < execs.size(); ++ei) {
        const ExecData& ex = *execs[ei];
        auto procs = sorted_processes(ex);
        os << "  subgraph cluster_" << pref[ei] << " {\n";
        os << "    label=\"" << dot_escape_label(ex.command) << "\";\n";
        os << "node [shape=ellipse, color=\"gray20\", penwidth=2];\n";
        size_t process_idx = 0;
        size_t node_counter = 0;
        for (auto& [pid, pptr] : procs) {
            const Process& proc = *pptr;
            std::string pcolor = (process_idx % 2 == 0) ? "#56B4E9" : "#F0E442";
            os << "subgraph cluster_process" << (process_idx + 1) << " {\n";
            os << "    label=\"" << dot_escape_label(proc.process_command)
               << "\";\n";
            os << "    color=\"" << pcolor << "\";\n";
            auto ops = sorted_operations(proc);
            for (auto& [path, op] : ops) {
                ++node_counter;
                std::string nid = node_name(pref[ei], node_counter);
                os << "  " << nid << " [label=\"" << dot_escape_label(path)
                   << "\"";
                os << ", shape=\"ellipse\", fontcolor=\"black\", style=";
                os << style_for_ops(op) << ", fillcolor=" << fill_for_ops(op)
                   << "];\n";
            }
            os << "}\n";
            ++process_idx;
        }
        os << "    " << exec_anchor(pref[ei])
           << " [shape=point, width=0, label=\"\", style=invis];\n";
        if (node_counter >= 2) {
            os << "    ";
            for (size_t i = 1; i <= node_counter; ++i) {
                os << node_name(pref[ei], i);
                if (i < node_counter) os << " -> ";
            }
            os << " [style=invis, constraint=true];\n";
            os << "    { rank=same; " << exec_anchor(pref[ei]) << "; ";
            os << node_name(pref[ei], 2) << "; }\n";
        }
        os << "  }\n\n";
    }
    if (!pref.empty()) {
        os << "  { rank=same; ";
        for (size_t i = 0; i < pref.size(); ++i) {
            os << exec_anchor(pref[i]);
            if (i + 1 < pref.size()) os << "; ";
        }
        os << "; }\n";
        for (size_t i = 0; i + 1 < pref.size(); ++i) {
            os << "  " << exec_anchor(pref[i]) << " -> "
               << exec_anchor(pref[i + 1]);
            os << " [style=invis, weight=1000];\n";
        }
    }
    for (size_t r = 0; r < global_max_rows; ++r) {
        os << "  { rank=same; ";
        for (size_t ei = 0; ei < pref.size(); ++ei) {
            if (r + 1 <= node_counts[ei])
                os << node_name(pref[ei], r + 1);
            else
                os << exec_anchor(pref[ei]);
            if (ei + 1 < pref.size()) os << "; ";
        }
        os << "; }\n";
    }
    for (size_t r = 0; r < global_max_rows; ++r) {
        os << "  ";
        bool first = true;
        for (size_t ei = 0; ei < pref.size(); ++ei) {
            if (r + 1 > node_counts[ei]) continue;
            if (!first) os << " -> ";
            os << node_name(pref[ei], r + 1);
            first = false;
        }
        if (!first) os << " [weight=1000, constraint=true];\n";
    }
    os << "}";
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
