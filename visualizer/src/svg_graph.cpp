#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "model.hpp"
static std::string format_ns_epoch(uint64_t ns_since_epoch) {
    uint64_t sec = ns_since_epoch / 1000000000ULL;
    std::time_t tt = (std::time_t)sec;
    std::tm tm{};
    localtime_r(&tt, &tm);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    return std::string(buf);
}
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
    std::string fg = "#000000";
    std::string box_stroke = "#000000";
    std::string proc_title_bg = "#000000";
    std::string proc_title_fg = "#ffffff";
    std::string shared_header_bg = "#CC79A7";
    std::string shared_header_fg = "#ffffff";
    std::string shared_border = "#CC79A7";
    std::string execmap_header_bg = "#F0E442";
    std::string execmap_header_fg = "#000000";
    std::string execmap_border = "#F0E442";
    std::string execmap_child_bg = "#000000";
    std::string execmap_child_fg = "#ffffff";
    std::string global_shared_header_bg = "#CC79A7";
    std::string global_shared_header_fg = "#ffffff";
    std::string global_shared_border = "#CC79A7";
    double global_col_w = 320.0;
    std::string global_shared_stroke = "#CC79A7";
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
static double measure_exec_processes_height(const ExecData& ex,
                                            const SvgStyle& st) {
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
struct SharedEntry {
    std::string label;
    Operations ops;
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
            e.label = p.process_command;
            e.ops = p.operation_map.at(path);
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
        svg_row_bg(os, x, cy, w, st.row_h, e.ops, st.shared_border,
                   st.box_border);
        svg_text(os, x + 8, cy + 14, e.label, "#000000", st.mono_font_size,
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
static std::vector<std::pair<uint64_t, std::vector<uint64_t>>>
sorted_execute_set(const ExecData& ex) {
    std::vector<std::pair<uint64_t, std::vector<uint64_t>>> v;
    v.reserve(ex.execute_set_map.size());
    for (const auto& [parent, children_set] : ex.execute_set_map) {
        std::vector<uint64_t> children;
        children.reserve(children_set.size());
        for (uint64_t c : children_set) children.push_back(c);
        std::sort(children.begin(), children.end());
        v.push_back({parent, std::move(children)});
    }
    std::sort(v.begin(), v.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    return v;
}
static std::string proc_name_or_fallback(const ExecData& ex, uint64_t pid) {
    auto it = ex.process_map.find(pid);
    if (it == ex.process_map.end())
        return std::string("pid ") + std::to_string(pid);
    return it->second.process_command;
}
static double measure_execute_tables_height(const ExecData& ex,
                                            const SvgStyle& st) {
    if (ex.execute_set_map.empty()) return 0.0;
    auto items = sorted_execute_set(ex);
    double h = 0.0;
    for (size_t i = 0; i < items.size(); ++i) {
        h += st.process_title_h;
        h += (double)items[i].second.size() * st.row_h;
        if (i + 1 < items.size()) h += st.row_gap;
    }
    return h;
}
static void draw_execute_table(std::ostringstream& os, double x, double y,
                               double w, const std::string& parent_name,
                               const std::vector<uint64_t>& children,
                               const ExecData& ex, const SvgStyle& st) {
    double h = st.process_title_h + (double)children.size() * st.row_h;
    svg_rect(os, x, y, w, h, "none", st.execmap_border, st.box_border);
    svg_rect(os, x, y, w, st.process_title_h, st.execmap_header_bg,
             st.execmap_border, st.box_border);
    svg_text(os, x + 8, y + 18, parent_name, st.execmap_header_fg, st.font_size,
             "Helvetica", "bold");
    double cy = y + st.process_title_h;
    for (uint64_t cpid : children) {
        svg_rect(os, x, cy, w, st.row_h, st.execmap_child_bg, st.execmap_border,
                 st.box_border);
        svg_text(os, x + 8, cy + 14, proc_name_or_fallback(ex, cpid),
                 st.execmap_child_fg, st.mono_font_size, "monospace");
        cy += st.row_h;
    }
}
static void draw_execute_tables(std::ostringstream& os, double x, double y,
                                double w, const ExecData& ex,
                                const SvgStyle& st) {
    auto items = sorted_execute_set(ex);
    double cy = y;
    for (size_t i = 0; i < items.size(); ++i) {
        uint64_t parent_pid = items[i].first;
        const auto& children = items[i].second;
        draw_execute_table(os, x, cy, w, proc_name_or_fallback(ex, parent_pid),
                           children, ex, st);
        cy += st.process_title_h + (double)children.size() * st.row_h;
        if (i + 1 < items.size()) cy += st.row_gap;
    }
}
static double measure_exec_total_height(const ExecData& ex,
                                        const SvgStyle& st) {
    double h = 42.0;
    double ph = measure_exec_processes_height(ex, st);
    if (ph > 0.0) h += ph;
    double eh = measure_execute_tables_height(ex, st);
    if (eh > 0.0) h += st.row_gap + eh;
    double sh = measure_shared_tables_height(ex, st);
    if (sh > 0.0) h += st.row_gap + sh;
    return h;
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
    double execmap_h = measure_execute_tables_height(ex, st);
    if (execmap_h > 0.0) {
        cy += st.row_gap;
        double tw = w - 20.0;
        draw_execute_tables(os, x + 10.0, cy, tw, ex, st);
        cy += execmap_h;
    }
    double shared_h = measure_shared_tables_height(ex, st);
    if (shared_h > 0.0) {
        cy += st.row_gap;
        double tw = w - 20.0;
        draw_shared_tables(os, x + 10.0, cy, tw, ex, st);
    }
}
static Operations union_ops_for_exec_path(const ExecData& ex,
                                          const std::string& path) {
    Operations u{};
    for (const auto& [pid, p] : ex.process_map) {
        (void)pid;
        auto it = p.operation_map.find(path);
        if (it == p.operation_map.end()) continue;
        u.read = u.read || it->second.read;
        u.write = u.write || it->second.write;
        u.deleted = u.deleted || it->second.deleted;
    }
    return u;
}
static std::vector<
    std::pair<std::string, std::vector<std::pair<std::string, Operations>>>>
compute_global_shared_tables(const JobData& job) {
    auto execs = sorted_execs(job);
    std::unordered_map<std::string, std::vector<size_t>> path_to_exec_idxs;
    path_to_exec_idxs.reserve(512);
    for (size_t i = 0; i < execs.size(); ++i) {
        const ExecData& ex = *execs[i];
        std::unordered_set<std::string> seen;
        seen.reserve(ex.process_map.size() * 4 + 8);
        for (const auto& [pid, p] : ex.process_map) {
            (void)pid;
            for (const auto& [path, ops] : p.operation_map) {
                (void)ops;
                seen.insert(path);
            }
        }
        for (const auto& path : seen) path_to_exec_idxs[path].push_back(i);
    }
    std::vector<
        std::pair<std::string, std::vector<std::pair<std::string, Operations>>>>
        tables;
    tables.reserve(path_to_exec_idxs.size());
    for (auto& kv : path_to_exec_idxs) {
        auto& path = kv.first;
        auto& idxs = kv.second;
        std::sort(idxs.begin(), idxs.end());
        idxs.erase(std::unique(idxs.begin(), idxs.end()), idxs.end());
        if (idxs.size() < 2) continue;
        std::vector<std::pair<std::string, Operations>> rows;
        rows.reserve(idxs.size());
        for (size_t idx : idxs) {
            const ExecData& ex = *execs[idx];
            rows.push_back({ex.command, union_ops_for_exec_path(ex, path)});
        }
        tables.push_back({path, std::move(rows)});
    }
    std::sort(tables.begin(), tables.end(),
              [](auto& a, auto& b) { return a.first < b.first; });
    return tables;
}
static double measure_global_shared_height(const JobData& job,
                                           const SvgStyle& st) {
    auto tables = compute_global_shared_tables(job);
    if (tables.empty()) return 0.0;
    double h = 0.0;
    for (size_t i = 0; i < tables.size(); ++i) {
        h += st.process_title_h;
        h += (double)tables[i].second.size() * st.row_h;
        if (i + 1 < tables.size()) h += st.row_gap;
    }
    return h;
}
static void draw_global_shared(std::ostringstream& os, double x, double y,
                               double w, const JobData& job,
                               const SvgStyle& st) {
    auto tables = compute_global_shared_tables(job);
    double cy = y;
    for (size_t i = 0; i < tables.size(); ++i) {
        const std::string& path = tables[i].first;
        const auto& rows = tables[i].second;
        double th = st.process_title_h + (double)rows.size() * st.row_h;
        svg_rect(os, x, cy, w, th, "none", st.global_shared_border,
                 st.box_border);
        svg_rect(os, x, cy, w, st.process_title_h, st.global_shared_header_bg,
                 st.global_shared_border, st.box_border);
        svg_text(os, x + 8, cy + 18, path, st.global_shared_header_fg,
                 st.font_size, "Helvetica", "bold");
        double ry = cy + st.process_title_h;
        for (const auto& r : rows) {
            svg_row_bg(os, x, ry, w, st.row_h, r.second,
                       st.global_shared_border, st.box_border);
            svg_text(os, x + 8, ry + 14, r.first, "#000000", st.mono_font_size,
                     "monospace");
            ry += st.row_h;
        }
        cy += th;
        if (i + 1 < tables.size()) cy += st.row_gap;
    }
}
static std::string build_svg(const JobData& job, const SvgStyle& st) {
    auto execs = sorted_execs(job);
    std::vector<double> col_w(execs.size(), 0.0);
    std::vector<double> col_h(execs.size(), 0.0);
    for (size_t i = 0; i < execs.size(); ++i) {
        col_w[i] = measure_exec_width(*execs[i], st) + 20.0;
        col_h[i] = measure_exec_total_height(*execs[i], st);
    }
    double global_shared_h = measure_global_shared_height(job, st);
    double content_w = 0.0;
    for (size_t i = 0; i < col_w.size(); ++i) {
        content_w += col_w[i];
        if (i + 1 < col_w.size()) content_w += st.col_gap;
    }
    if (global_shared_h > 0.0) content_w += st.col_gap + st.global_col_w;
    double max_col_h = 0.0;
    for (double hh : col_h) max_col_h = std::max(max_col_h, hh);
    double right_h = global_shared_h > 0.0 ? (42.0 + global_shared_h) : 0.0;
    max_col_h = std::max(max_col_h, right_h);
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
    std::string start_s = format_ns_epoch(job.start_time);
    std::string end_s = format_ns_epoch(job.end_time);
    svg_text(os, hx, hy + 16, "Job Name: " + job.job_name, st.fg, st.font_size,
             "Helvetica", "bold");
    svg_text(os, hx, hy + 34, "User: " + job.username, st.fg, st.font_size,
             "Helvetica");
    svg_text(os, hx, hy + 52, "Start: " + start_s, st.fg, st.font_size,
             "Helvetica");
    double end_value_x = hx + estimate_text_w("Start: ", st.char_w) - 18;
    svg_text(os, hx, hy + 70, "End:", st.fg, st.font_size, "Helvetica");
    svg_text(os, end_value_x, hy + 70, end_s, st.fg, st.font_size, "Helvetica");
    double header_text_w = 0.0;
    header_text_w = std::max(
        header_text_w, estimate_text_w("Job Name: " + job.job_name, st.char_w));
    header_text_w = std::max(
        header_text_w, estimate_text_w("User: " + job.username, st.char_w));
    header_text_w = std::max(header_text_w,
                             estimate_text_w("Start: " + start_s, st.char_w));
    header_text_w = std::max(header_text_w,
                             std::max(estimate_text_w("End:", st.char_w),
                                      estimate_text_w("Start: ", st.char_w)
                                          + estimate_text_w(end_s, st.char_w)));
    double lx = hx + header_text_w;
    double ly = hy + 4.0;
    double sw = 14.0;
    double gap = 6.0;
    double item_gap = 20.0;
    double title_to_items = 14.0;
    double pad_l = 12.0;
    double pad_r = 12.0;
    double pad_t = 10.0;
    double pad_b = 12.0;
    double title_h = 14.0;
    double ysw = ly + pad_t + title_h + title_to_items;
    double items_w = 0.0;
    items_w += sw + gap + estimate_text_w("write", st.char_w);
    items_w += item_gap + sw + gap + estimate_text_w("read", st.char_w);
    items_w += item_gap + sw + gap + estimate_text_w("delete", st.char_w);
    items_w += item_gap + sw + gap + estimate_text_w("execute", st.char_w);
    items_w += item_gap + sw + gap + estimate_text_w("shared", st.char_w);
    double title_w = estimate_text_w("Legend", st.char_w);
    double lw = pad_l + std::max(title_w, items_w) + pad_r;
    double lh = pad_t + title_h + title_to_items + sw + pad_b;
    if (lx + lw > width - st.page_pad) lx = width - st.page_pad - lw;
    if (lx < st.page_pad) lx = st.page_pad;
    svg_rect(os, lx, ly, lw, lh, "none", st.box_stroke, 1.0);
    svg_text(os, lx + pad_l, ly + pad_t + 8.0, "Legend", st.fg, st.font_size,
             "Helvetica", "bold");
    double x = lx + pad_l;
    svg_rect(os, x, ysw, sw, sw, "#0072B2", st.box_stroke, 1.0);
    svg_text(os, x + sw + gap, ysw + 12.0, "write", st.fg, st.font_size,
             "Helvetica");
    x += sw + gap + estimate_text_w("write", st.char_w) + item_gap;
    svg_rect(os, x, ysw, sw, sw, "#D55E00", st.box_stroke, 1.0);
    svg_text(os, x + sw + gap, ysw + 12.0, "read", st.fg, st.font_size,
             "Helvetica");
    x += sw + gap + estimate_text_w("read", st.char_w) + item_gap;
    svg_rect(os, x, ysw, sw, sw, "#009E73", st.box_stroke, 1.0);
    svg_text(os, x + sw + gap, ysw + 12.0, "delete", st.fg, st.font_size,
             "Helvetica");
    x += sw + gap + estimate_text_w("delete", st.char_w) + item_gap;
    svg_rect(os, x, ysw, sw, sw, "#F0E442", st.box_stroke, 1.0);
    svg_text(os, x + sw + gap, ysw + 12.0, "execute", st.fg, st.font_size,
             "Helvetica");
    x += sw + gap + estimate_text_w("execute", st.char_w) + item_gap;
    svg_rect(os, x, ysw, sw, sw, "#CC79A7", st.box_stroke, 1.0);
    svg_text(os, x + sw + gap, ysw + 12.0, "shared", st.fg, st.font_size,
             "Helvetica");
    double top_y = st.page_pad + st.header_h;
    double cx = st.page_pad;
    for (size_t i = 0; i < execs.size(); ++i) {
        draw_exec_column(os, cx, top_y, col_w[i], col_h[i], *execs[i], st);
        cx += col_w[i] + st.col_gap;
    }
    if (global_shared_h > 0.0) {
        double gx = cx;
        double gh = 42.0 + global_shared_h;
        svg_rect(os, gx, top_y, st.global_col_w, gh, "none",
                 st.global_shared_stroke, st.box_border);
        svg_text(os, gx + 10, top_y + 18, "shared across execs", st.fg,
                 st.font_size, "Helvetica", "bold");
        double gy = top_y + 32;
        draw_global_shared(os, gx + 10.0, gy, st.global_col_w - 20.0, job, st);
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
