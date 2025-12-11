#include <algorithm>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>

#include "model.hpp"

std::string label_string(const std::string& label,
                         const std::string& shape = "none") {
    std::string shape_element = "";
    std::string label_paranthesis = R"(")";
    if (shape != "none") {
        shape_element = ", shape=" + shape;
        label_paranthesis = "";
    }

    return R"([ label=")" + label + shape_element + label_paranthesis + R"(])";
}

/*std::string sanitize_node_name(const std::string& input) {
    std::string sanitized = input;
    std::replace_if(
        sanitized.begin(), sanitized.end(),
        [](char c) { return !std::isalnum(c); }, '_');
    return sanitized;
}*/

std::string sanitize_node_name(const std::string& input) {
    std::string sanitized = input;
    std::replace_if(
        sanitized.begin(), sanitized.end(),
        [](char c) { return !(std::isalnum(c) || c == '/'); }, '_');
    return sanitized;
}

void save_graph_to_file(const std::string& graph_string,
                        const std::string& filename) {
    std::ofstream out(filename);
    out << graph_string;
    out.close();
}

struct GraphElementMapData {
    int node_counter = 0;
    std::stringstream id_string;
    std::unordered_map<std::string, int> graph_path_id_map;
    std::unordered_map<std::string, std::string> graph_path_path_map;
    std::unordered_map<int, std::string> graph_id_label_map;
};

void rename_graph_element(std::string original_path,
                          const std::string& new_path,
                          GraphElementMapData& graph_element_map_data) {
    std::unordered_map<std::string, std::string>& graph_path_path_map
        = graph_element_map_data.graph_path_path_map;
    if (graph_path_path_map.contains(original_path)) {
        std::string original_path_parameter = original_path;
        std::string original_path
            = graph_path_path_map[original_path_parameter];
        graph_path_path_map.erase(original_path_parameter);
    }
    graph_path_path_map[new_path] = original_path;
}

std::string map_graph_element(std::string path,
                              GraphElementMapData& graph_element_map_data) {
    std::unordered_map<std::string, int>& graph_path_id_map
        = graph_element_map_data.graph_path_id_map;
    int& node_counter = graph_element_map_data.node_counter;
    std::unordered_map<std::string, std::string>& graph_path_path_map
        = graph_element_map_data.graph_path_path_map;
    std::unordered_map<int, std::string>& graph_id_label_map
        = graph_element_map_data.graph_id_label_map;
    if (graph_path_path_map.contains(path)) {
        path = graph_path_path_map[path];
    }
    if (!graph_path_id_map.contains(path)) {
        graph_path_id_map[path] = node_counter;
        std::string label = label_string(path);
        graph_id_label_map[node_counter] = label;
        graph_element_map_data.id_string << std::to_string(node_counter)
                                         << label << "\n";
        node_counter++;
    }
    int id = graph_path_id_map[path];
    return std::to_string(id);
}

void build_graph(const ParsedLibcprovData& parsed_libcprov_data) {
    std::stringstream graphviz_string;
    graphviz_string << "digraph G {\n";
    Payload payload = parsed_libcprov_data.payload.value();
    std::string arrow = " -> ";
    std::string space_string = "    ";
    std::string newline_element = ";\n" + space_string;
    bool add_to_graph;
    for (ExecData exec_data : payload.exec_vector) {
        GraphElementMapData graph_element_map_data;
        std::stringstream event_strings;
        for (Event event : exec_data.events) {
            std::string pid_string = std::to_string(event.pid);
            std::string graph_string;
            add_to_graph = true;
            switch (event.operation_type) {
                case OperationType::ProcessStart:
                    add_to_graph = false;
                    break;
                case OperationType::Read: {
                    Read read = std::get<Read>(event.operation_data);
                    graph_string = pid_string + arrow
                                   + map_graph_element(read.path_in,
                                                       graph_element_map_data)
                                   + label_string("read");
                    break;
                }
                case OperationType::Write: {
                    Write write = std::get<Write>(event.operation_data);
                    graph_string = pid_string + arrow
                                   + map_graph_element(write.path_out,
                                                       graph_element_map_data)
                                   + label_string("wrote");
                    break;
                }
                case OperationType::Execute: {
                    Execute execute = std::get<Execute>(event.operation_data);
                    graph_string = pid_string + arrow
                                   + map_graph_element(execute.path_exec,
                                                       graph_element_map_data)
                                   + label_string("used") + newline_element
                                   + map_graph_element(execute.path_exec,
                                                       graph_element_map_data)
                                   + arrow + std::to_string(execute.child_pid)
                                   + label_string("started");
                    break;
                }
                case OperationType::Rename: {
                    add_to_graph = false;
                    break;
                }
                case OperationType::Link: {
                    add_to_graph = false;
                    break;
                }
                case OperationType::Symlink: {
                    add_to_graph = false;
                    break;
                }
                case OperationType::Delete: {
                    Delete delete_obj = std::get<Delete>(event.operation_data);
                    graph_string = pid_string + arrow
                                   + map_graph_element(delete_obj.deleted_path,
                                                       graph_element_map_data)
                                   + label_string("deleted");
                    break;
                }
                default:
                    add_to_graph = false;
            }
            if (add_to_graph) {
                event_strings << space_string + graph_string + ";\n";
            }
        }
        graphviz_string << graph_element_map_data.id_string.str()
                        << event_strings.str();
    }
    graphviz_string << "}";
    save_graph_to_file(graphviz_string.str(), "/dev/shm/libcprov/graphviz.dot");
}
