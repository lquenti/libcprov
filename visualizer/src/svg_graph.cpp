#include <algorithm>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "model.hpp"
static std::string xml_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':
                out += "&amp;";
                break;
            case '<':
                out += "&lt;";
                break;
            case '>':
                out += "&gt;";
                break;
            case '"':
                out += "&quot;";
                break;
            case '\'':
                out += "&apos;";
                break;
            case '\n':
            case '\r':
            case '\t':
                out.push_back(' ');
                break;
            default:
                out.push_back(c);
                break;
        }
    }
    return out;
}
static std::vector<const ExecData*> sorted_execs(const JobData& job) {
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
static std::vector<std::pair<uint64_t, const Process*>> sorted_processes(
    const ExecData& exec) {
    std::vector<std::pair<uint64_t, const Process*>> v;
    v.reserve(exec.process_map.size());
    for (const auto& [pid, p] : exec.process_map) v.push_back({pid, &p});
    std::sort(v.begin(), v.end(),
              [](auto& a, auto& b) { return a.first < b.first; });
    return v;
}
static std::vector<std::pair<std::string, Operations>> sorted_operations(
    const Process& p) {
    std::vector<std::pair<std::string, Operations>> v;
    v.reserve(p.operation_map.size());
    for (const auto& [path, ops] : p.operation_map) v.push_back({path, ops});
    std::sort(v.begin(), v.end(),
              [](auto& a, auto& b) { return a.first < b.first; });
    return v;
}
struct SvgStyle {
    double page_pad = 18.0;
    double header_h = 88.0;
    double col_gap = 28.0;
    double row_gap = 18.0;
    double box_border = 1.0;
    double process_title_h = 26.0;
    double row_h = 20.0;
    double font_size = 12.0;
    double mono_font_size = 11.0;
    double char_w = 7.1;
    double mono_char_w = 6.6;
    double proc_min_w = 240.0;
    double proc_max_w = 520.0;
    std::string bg = "#ffffff";
    std::string fg = "#111111";
    std::string box_stroke = "#333333";
    std::string proc_title_bg = "#20262e";
    std::string proc_title_fg = "#ffffff";
    std::string shared_header_bg = "#CC79A7";
    std::string shared_header_fg = "#ffffff";
    std::string shared_border = "#CC79A7";
};
static double clamp(double x, double lo, double hi) {
    return x < lo ? lo : (x > hi ? hi : x);
}
static double estimate_text_w(const std::string& s, double cw) {
    return (double)s.size() * cw;
}
static double measure_process_width(const Process& p, const SvgStyle& st) {
    double w = 0.0;
    w = std::max(w, estimate_text_w(p.process_command, st.char_w));
    for (const auto& [path, ops] : p.operation_map) {
        (void)ops;
        w = std::max(w, estimate_text_w(path, st.mono_char_w));
    }
    w += 24.0;
    return clamp(w, st.proc_min_w, st.proc_max_w);
}
static double measure_exec_width(const ExecData& ex, const SvgStyle& st) {
    double w = estimate_text_w(ex.command, st.char_w) + 28.0;
    auto procs = sorted_processes(ex);
    for (auto& [pid, pp] : procs) {
        (void)pid;
        w = std::max(w, measure_process_width(*pp, st));
    }
    return w;
}
static double measure_process_height(const Process& p, const SvgStyle& st) {
    return st.process_title_h + (double)p.operation_map.size() * st.row_h;
}
static double measure_exec_height(const ExecData& ex, const SvgStyle& st) {
    auto procs = sorted_processes(ex);
    double h = 0.0;
    for (size_t i = 0; i < procs.size(); ++i) {
        h += measure_process_height(*procs[i].second, st);
        if (i + 1 < procs.size()) h += st.row_gap;
    }
    return h;
}
static void svg_rect(std::ostringstream& os, double x, double y, double w,
                     double h, const std::string& fill,
                     const std::string& stroke, double sw) {
    os << "<rect x=\"" << x << "\" y=\"" << y << "\" width=\"" << w
       << "\" height=\"" << h << "\" fill=\"" << fill << "\" stroke=\""
       << stroke << "\" stroke-width=\"" << sw << "\" />\n";
}
static void svg_text(std::ostringstream& os, double x, double y,
                     const std::string& text, const std::string& fill,
                     double font_size, const std::string& font_family,
                     const std::string& weight = "normal") {
    os << "<text x=\"" << x << "\" y=\"" << y << "\" fill=\"" << fill
       << "\" font-size=\"" << font_size << "\" font-family=\"" << font_family
       << "\" font-weight=\"" << weight << "\">" << xml_escape(text)
       << "</text>\n";
}
static std::vector<std::string> row_colors_for_ops(const Operations& ops) {
    std::vector<std::string> cs;
    if (ops.write) cs.push_back("#0072B2");
    if (ops.read) cs.push_back("#D55E00");
    if (ops.deleted) cs.push_back("#009E73");
    if (cs.empty()) cs.push_back("#ffffff");
    return cs;
}
static void svg_row_bg(std::ostringstream& os, double x, double y, double w,
                       double h, const Operations& ops,
                       const std::string& stroke, double sw) {
    auto cs = row_colors_for_ops(ops);
    double segw = w / (double)cs.size();
    for (size_t i = 0; i < cs.size(); ++i) {
        double rx = x + segw * (double)i;
        double rw = (i + 1 == cs.size()) ? (x + w - rx) : segw;
        os << "<rect x=\"" << rx << "\" y=\"" << y << "\" width=\"" << rw
           << "\" height=\"" << h << "\" fill=\"" << cs[i]
           << "\" stroke=\"none\" />\n";
    }
    os << "<rect x=\"" << x << "\" y=\"" << y << "\" width=\"" << w
       << "\" height=\"" << h << "\" fill=\"none\" stroke=\"" << stroke
       << "\" stroke-width=\"" << sw << "\" />\n";
}
static void draw_process(std::ostringstream& os, double x, double y, double w,
                         const Process& p, const SvgStyle& st) {
    double h = measure_process_height(p, st);
    svg_rect(os, x, y, w, h, "none", st.box_stroke, st.box_border);
    svg_rect(os, x, y, w, st.process_title_h, st.proc_title_bg, st.box_stroke,
             st.box_border);
    svg_text(os, x + 8, y + 18, p.process_command, st.proc_title_fg,
             st.font_size, "Helvetica", "bold");
    auto ops = sorted_operations(p);
    double cy = y + st.process_title_h;
    for (const auto& [path, op] : ops) {
        svg_row_bg(os, x, cy, w, st.row_h, op, st.box_stroke, st.box_border);
        svg_text(os, x + 8, cy + 14, path, "#000000", st.mono_font_size,
                 "monospace");
        cy += st.row_h;
    }
}
static std::string access_color_for_process_on_path(const Process& p,
                                                    const std::string& path) {
    auto it = p.operation_map.find(path);
    if (it == p.operation_map.end()) return "#ffffff";
    const Operations& ops = it->second;
    if (ops.write) return "#0072B2";
    if (ops.read) return "#D55E00";
    if (ops.deleted) return "#009E73";
    return "#ffffff";
}
struct SharedEntry {
    std::string proc;
    std::string color;
};
static std::vector<std::pair<std::string, std::vector<SharedEntry>>>
compute_shared_tables(const ExecData& ex) {
    auto procs = sorted_processes(ex);
    std::unordered_map<std::string, std::vector<size_t>> path_to_proc_idxs;
    path_to_proc_idxs.reserve(256);
    for (size_t i = 0; i < procs.size(); ++i) {
        const Process& p = *procs[i].second;
        for (const auto& [path, ops] : p.operation_map) {
            (void)ops;
            path_to_proc_idxs[path].push_back(i);
        }
    }
    std::vector<std::pair<std::string, std::vector<SharedEntry>>> tables;
    tables.reserve(path_to_proc_idxs.size());
    for (auto& kv : path_to_proc_idxs) {
        auto& path = kv.first;
        auto& idxs = kv.second;
        std::sort(idxs.begin(), idxs.end());
        idxs.erase(std::unique(idxs.begin(), idxs.end()), idxs.end());
        if (idxs.size() < 2) continue;
        std::vector<SharedEntry> entries;
        entries.reserve(idxs.size());
        for (size_t idx : idxs) {
            const Process& p = *procs[idx].second;
            SharedEntry e;
            e.proc = p.process_command;
            e.color = access_color_for_process_on_path(p, path);
            entries.push_back(std::move(e));
        }
        tables.push_back({path, std::move(entries)});
    }
    std::sort(tables.begin(), tables.end(),
              [](auto& a, auto& b) { return a.first < b.first; });
    return tables;
}
static double measure_shared_tables_height(const ExecData& ex,
                                           const SvgStyle& st) {
    auto tables = compute_shared_tables(ex);
    if (tables.empty()) return 0.0;
    double h = 0.0;
    for (size_t i = 0; i < tables.size(); ++i) {
        h += st.process_title_h;
        h += (double)tables[i].second.size() * st.row_h;
        if (i + 1 < tables.size()) h += st.row_gap;
    }
    h += st.row_gap;
    return h;
}
static void draw_shared_table(std::ostringstream& os, double x, double y,
                              double w, const std::string& path,
                              const std::vector<SharedEntry>& entries,
                              const SvgStyle& st) {
    double h = st.process_title_h + (double)entries.size() * st.row_h;
    svg_rect(os, x, y, w, h, "none", st.shared_border, st.box_border);
    svg_rect(os, x, y, w, st.process_title_h, st.shared_header_bg,
             st.shared_border, st.box_border);
    svg_text(os, x + 8, y + 18, path, st.shared_header_fg, st.font_size,
             "Helvetica", "bold");
    double cy = y + st.process_title_h;
    for (const auto& e : entries) {
        svg_rect(os, x, cy, w, st.row_h, e.color, st.shared_border,
                 st.box_border);
        svg_text(os, x + 8, cy + 14, e.proc, "#000000", st.mono_font_size,
                 "monospace");
        cy += st.row_h;
    }
}
static void draw_shared_tables(std::ostringstream& os, double x, double y,
                               double w, const ExecData& ex,
                               const SvgStyle& st) {
    auto tables = compute_shared_tables(ex);
    double cy = y;
    for (size_t i = 0; i < tables.size(); ++i) {
        draw_shared_table(os, x, cy, w, tables[i].first, tables[i].second, st);
        cy += st.process_title_h + (double)tables[i].second.size() * st.row_h;
        if (i + 1 < tables.size()) cy += st.row_gap;
    }
}
static void draw_exec_column(std::ostringstream& os, double x, double top_y,
                             double w, double h, const ExecData& ex,
                             const SvgStyle& st) {
    svg_rect(os, x, top_y, w, h, "none", st.box_stroke, st.box_border);
    svg_text(os, x + 10, top_y + 18, ex.command, st.fg, st.font_size,
             "Helvetica", "bold");
    double cy = top_y + 32;
    auto procs = sorted_processes(ex);
    for (size_t i = 0; i < procs.size(); ++i) {
        const Process& p = *procs[i].second;
        double pw = std::min(w - 20.0, measure_process_width(p, st));
        draw_process(os, x + 10.0, cy, pw, p, st);
        cy += measure_process_height(p, st);
        if (i + 1 < procs.size()) cy += st.row_gap;
    }
    double shared_h = measure_shared_tables_height(ex, st);
    if (shared_h > 0.0) {
        cy += st.row_gap;
        double tw = w - 20.0;
        draw_shared_tables(os, x + 10.0, cy, tw, ex, st);
    }
}
static std::string build_svg(const JobData& job, const SvgStyle& st) {
    auto execs = sorted_execs(job);
    std::vector<double> col_w(execs.size(), 0.0);
    std::vector<double> col_h(execs.size(), 0.0);
    for (size_t i = 0; i < execs.size(); ++i) {
        col_w[i] = measure_exec_width(*execs[i], st) + 20.0;
        col_h[i] = measure_exec_height(*execs[i], st) + 42.0
                   + measure_shared_tables_height(*execs[i], st);
    }
    double content_w = 0.0;
    for (size_t i = 0; i < col_w.size(); ++i) {
        content_w += col_w[i];
        if (i + 1 < col_w.size()) content_w += st.col_gap;
    }
    double max_col_h = 0.0;
    for (double h : col_h) max_col_h = std::max(max_col_h, h);
    double width = st.page_pad * 2 + std::max(content_w, 600.0);
    double height = st.page_pad * 2 + st.header_h + max_col_h;
    std::ostringstream os;
    os << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    os << "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"" << width
       << "\" height=\"" << height << "\" viewBox=\"0 0 " << width << " "
       << height << "\">\n";
    os << "<rect x=\"0\" y=\"0\" width=\"" << width << "\" height=\"" << height
       << "\" fill=\"" << st.bg << "\" />\n";
    double hx = st.page_pad;
    double hy = st.page_pad;
    svg_text(os, hx, hy + 16, "Job Name: " + job.job_name, st.fg, st.font_size,
             "Helvetica", "bold");
    svg_text(os, hx, hy + 34, "User: " + job.username, st.fg, st.font_size,
             "Helvetica");
    svg_text(os, hx, hy + 52, "Start: " + std::to_string(job.start_time), st.fg,
             st.font_size, "Helvetica");
    svg_text(os, hx, hy + 70, "End: " + std::to_string(job.end_time), st.fg,
             st.font_size, "Helvetica");
    double lx = hx + 360;
    double ly = hy + 4;
    double lw = 220;
    double lh = 54;
    svg_rect(os, lx, ly, lw, lh, "none", st.box_stroke, 1.0);
    svg_text(os, lx + 12, ly + 18, "Legend", st.fg, st.font_size, "Helvetica",
             "bold");
    svg_rect(os, lx + 12, ly + 26, 14, 14, "#0072B2", st.box_stroke, 1.0);
    svg_text(os, lx + 32, ly + 38, "write", st.fg, st.font_size, "Helvetica");
    svg_rect(os, lx + 82, ly + 26, 14, 14, "#D55E00", st.box_stroke, 1.0);
    svg_text(os, lx + 102, ly + 38, "read", st.fg, st.font_size, "Helvetica");
    svg_rect(os, lx + 142, ly + 26, 14, 14, "#009E73", st.box_stroke, 1.0);
    svg_text(os, lx + 162, ly + 38, "delete", st.fg, st.font_size, "Helvetica");
    double top_y = st.page_pad + st.header_h;
    double cx = st.page_pad;
    for (size_t i = 0; i < execs.size(); ++i) {
        draw_exec_column(os, cx, top_y, col_w[i], max_col_h, *execs[i], st);
        cx += col_w[i] + st.col_gap;
    }
    os << "</svg>\n";
    return os.str();
}
void save_graph_to_file(const std::string& graph_string,
                        const std::string& filename) {
    std::ofstream out(filename);
    out << graph_string;
    out.close();
}
void build_graph(const JobData& job_data) {
    SvgStyle st;
    save_graph_to_file(build_svg(job_data, st), "/dev/shm/libcprov/graph.svg");
}
