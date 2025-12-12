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
    void delete_graph_element(std::string delete_path) {
        this->graph_path_id_map.erase(delete_path);
    }
    void rename_graph_element(std::string original_path,
                              const std::string& new_path) {
        if (this->graph_path_path_map.contains(original_path)) {
            std::string original_path_parameter = original_path;
            std::string original_path
                = this->graph_path_path_map[original_path_parameter];
            this->graph_path_path_map.erase(original_path_parameter);
        }
        this->graph_path_path_map[new_path] = original_path;
    }
    std::string map_graph_element(std::string path) {
        if (this->graph_path_path_map.contains(path)) {
            path = this->graph_path_path_map[path];
        }
        if (!this->graph_path_id_map.contains(path)) {
            this->graph_path_id_map[path] = this->node_counter;
            std::string label = label_string(path);
            graph_id_label_map[this->node_counter] = label;
            this->id_string << std::to_string(node_counter) << label << "\n";
            this->node_counter++;
        }
        int id = this->graph_path_id_map[path];
        return std::to_string(id);
    }
    // void add_exec(){
    // this->
};

void build_graph(const ParsedLibcprovData& parsed_libcprov_data) {
    std::stringstream graphviz_string;
    graphviz_string << "digraph G {\n";
    Payload payload = parsed_libcprov_data.payload.value();
    std::string arrow = " -> ";
    std::string space_string = "    ";
    std::string newline_element = ";\n" + space_string;
    bool add_to_graph;
    GraphElementMapData graph_element_map_data;
    std::stringstream event_strings;
    for (ExecData exec_data : payload.exec_vector) {
        for (Event event : exec_data.events) {
            std::string pid_string = std::to_string(event.pid);
            std::string event_string;
            add_to_graph = true;
            switch (event.operation_type) {
                case OperationType::ProcessStart:
                    add_to_graph = false;
                    break;
                case OperationType::Read: {
                    Read read = std::get<Read>(event.operation_data);
                    event_string = pid_string + arrow
                                   + graph_element_map_data.map_graph_element(
                                       read.path_in)
                                   + label_string("read");
                    break;
                }
                case OperationType::Write: {
                    Write write = std::get<Write>(event.operation_data);
                    event_string = pid_string + arrow
                                   + graph_element_map_data.map_graph_element(
                                       write.path_out)
                                   + label_string("wrote");
                    break;
                }
                case OperationType::Execute: {
                    Execute execute = std::get<Execute>(event.operation_data);
                    event_string = pid_string + arrow
                                   + graph_element_map_data.map_graph_element(
                                       execute.path_exec)
                                   + label_string("used") + newline_element
                                   + graph_element_map_data.map_graph_element(
                                       execute.path_exec)
                                   + arrow + std::to_string(execute.child_pid)
                                   + label_string("started");
                    break;
                }
                case OperationType::Rename: {
                    Rename rename = std::get<Rename>(event.operation_data);
                    graph_element_map_data.rename_graph_element(
                        rename.original_path, rename.new_path);
                    add_to_graph = false;
                    break;
                }
                case OperationType::Link: {
                    Link link = std::get<Link>(event.operation_data);
                    graph_element_map_data.rename_graph_element(
                        link.original_path, link.new_path);
                    add_to_graph = false;
                    break;
                }
                case OperationType::Symlink: {
                    Symlink symlink = std::get<Symlink>(event.operation_data);
                    graph_element_map_data.rename_graph_element(
                        symlink.original_path, symlink.new_path);
                    add_to_graph = false;
                    break;
                }
                case OperationType::Delete: {
                    Delete delete_obj = std::get<Delete>(event.operation_data);
                    event_string = pid_string + arrow
                                   + graph_element_map_data.map_graph_element(
                                       delete_obj.deleted_path)
                                   + label_string("deleted");
                    graph_element_map_data.delete_graph_element(
                        delete_obj.deleted_path);
                    break;
                }
                default:
                    add_to_graph = false;
            }
            if (add_to_graph) {
                event_strings << space_string + event_string + ";\n";
            }
        }
    }
    graphviz_string << graph_element_map_data.id_string.str()
                    << event_strings.str() << "}";
    save_graph_to_file(graphviz_string.str(), "/dev/shm/libcprov/graphviz.dot");
}
