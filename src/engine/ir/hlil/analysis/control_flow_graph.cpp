#include "control_flow_graph.h"
#include <algorithm>
#include <iterator>
#include <map>
#include <set>
#include <stack>
#include <unordered_set>

namespace engine::hlil {

ControlFlowGraph::ControlFlowGraph(const mlil::Function& func) : entry_(func.entry) {
    build_graph(func);
    compute_dominators();
    compute_post_dominators(func);
    compute_loops();
}

const BlockInfo* ControlFlowGraph::get_info(std::uint64_t id) const {
    auto it = blocks_.find(id);
    return it != blocks_.end() ? &it->second : nullptr;
}

BlockInfo* ControlFlowGraph::get_info_mut(std::uint64_t id) {
    auto it = blocks_.find(id);
    return it != blocks_.end() ? &it->second : nullptr;
}

void ControlFlowGraph::build_graph(const mlil::Function& func) {
    for (const auto& b : func.blocks) {
        BlockInfo info;
        info.block = &b;
        info.id = b.start;
        info.preds = b.predecessors;
        info.succs = b.successors;
        blocks_[b.start] = std::move(info);
    }
}

// Simple iterative dominator algorithm
void ControlFlowGraph::compute_dominators() {
    if (blocks_.empty()) return;
    
    std::map<std::uint64_t, std::set<std::uint64_t>> dom;
    std::set<std::uint64_t> all_nodes;
    for (const auto& kv : blocks_) all_nodes.insert(kv.first);

    for (const auto& kv : blocks_) {
        if (kv.first == entry_) dom[kv.first] = {entry_};
        else dom[kv.first] = all_nodes;
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (auto& [id, info] : blocks_) {
            if (id == entry_) continue;
            
            std::set<std::uint64_t> new_dom;
            bool first = true;
            for (std::uint64_t p : info.preds) {
                if (blocks_.find(p) == blocks_.end()) continue;

                if (first) {
                    new_dom = dom[p];
                    first = false;
                } else {
                    std::set<std::uint64_t> intersection;
                    std::set_intersection(new_dom.begin(), new_dom.end(),
                                          dom[p].begin(), dom[p].end(),
                                          std::inserter(intersection, intersection.begin()));
                    new_dom = intersection;
                }
            }
            new_dom.insert(id);
            if (new_dom != dom[id]) {
                dom[id] = new_dom;
                changed = true;
            }
        }
    }

    // IDOM
    for (auto& [id, info] : blocks_) {
        if (id == entry_) continue;
        std::set<std::uint64_t> d = dom[id];
        d.erase(id);
        if (d.empty()) continue;
        
        std::uint64_t best = 0;
        std::size_t max_size = 0;
        for (std::uint64_t cand : d) {
            if (dom[cand].size() > max_size) {
                max_size = dom[cand].size();
                best = cand;
            }
        }
        info.idom = best;
    }
}

void ControlFlowGraph::compute_post_dominators(const mlil::Function& func) {
    std::uint64_t virtual_exit = 0xFFFFFFFFFFFFFFFF;
    std::vector<std::uint64_t> exits;
    for (const auto& [id, info] : blocks_) {
        if (info.succs.empty()) {
            exits.push_back(id);
        }
    }
    std::map<std::uint64_t, std::set<std::uint64_t>> pdom;
    std::set<std::uint64_t> all_nodes;
    for (const auto& kv : blocks_) all_nodes.insert(kv.first);
    all_nodes.insert(virtual_exit);

    // Init
    for (const auto& kv : blocks_) pdom[kv.first] = all_nodes;
    pdom[virtual_exit] = {virtual_exit};

    bool changed = true;
    while (changed) {
        changed = false;

        for (auto& [id, info] : blocks_) {
            std::set<std::uint64_t> new_pdom;
            bool first = true;
            
            // In reverse graph, predecessors of 'id' are the successors of 'id' in original graph.
            auto reverse_preds = info.succs;
            if (reverse_preds.empty()) {
                // Connected to virtual exit
                reverse_preds.push_back(virtual_exit);
            }

            for (std::uint64_t succ : reverse_preds) {
                // If succ is virtual exit, its pdom is {virtual_exit}
                const std::set<std::uint64_t>* src_set = nullptr;
                std::set<std::uint64_t> temp_virtual = {virtual_exit};
                
                if (succ == virtual_exit) {
                    src_set = &temp_virtual;
                } else {
                    if (pdom.find(succ) == pdom.end()) continue; 
                    src_set = &pdom[succ];
                }

                if (first) {
                    new_pdom = *src_set;
                    first = false;
                } else {
                    std::set<std::uint64_t> intersection;
                    std::set_intersection(new_pdom.begin(), new_pdom.end(),
                                          src_set->begin(), src_set->end(),
                                          std::inserter(intersection, intersection.begin()));
                    new_pdom = intersection;
                }
            }
            new_pdom.insert(id);
            if (new_pdom != pdom[id]) {
                pdom[id] = new_pdom;
                changed = true;
            }
        }
    }

    // IPDOM
    for (auto& [id, info] : blocks_) {
        std::set<std::uint64_t> d = pdom[id];
        d.erase(id);
        d.erase(virtual_exit); // Ignore virtual exit for mapping
        if (d.empty()) continue;

        std::uint64_t best = 0;
        std::size_t max_size = 0;
        for (std::uint64_t cand : d) {
            if (pdom[cand].size() > max_size) {
                max_size = pdom[cand].size();
                best = cand;
            }
        }
        info.ipdom = best;
    }
}

void ControlFlowGraph::compute_loops() {
    for (auto& [id, info] : blocks_) {
        for (std::uint64_t succ : info.succs) {
            // Back edge: succ dominates id
            std::uint64_t curr = id;
            bool is_back_edge = false;
            while (curr != 0) {
                if (curr == succ) {
                    is_back_edge = true;
                    break;
                }
                curr = blocks_[curr].idom;
            }

            if (is_back_edge) {
                if (blocks_.find(succ) != blocks_.end()) {
                    blocks_[succ].back_edges.push_back(id);
                    mark_loop(succ, id);
                }
            }
        }
    }
}

void ControlFlowGraph::mark_loop(std::uint64_t header, std::uint64_t latch) {
    std::vector<std::uint64_t> worklist;
    worklist.push_back(latch);
    std::unordered_set<std::uint64_t> seen;
    
    auto add_header = [&](std::uint64_t block_id) {
        auto& info = blocks_[block_id];
        if (std::find(info.loop_headers.begin(), info.loop_headers.end(), header) == info.loop_headers.end()) {
            info.loop_headers.push_back(header);
        }
    };

    while(!worklist.empty()) {
        std::uint64_t curr = worklist.back();
        worklist.pop_back();
        if (!seen.insert(curr).second) continue;
        if (curr == header) continue;

        add_header(curr);
        for (std::uint64_t p : blocks_[curr].preds) {
            worklist.push_back(p);
        }
    }
    add_header(header);
}

std::uint64_t ControlFlowGraph::find_merge_point(std::uint64_t node_id) {
    auto it = blocks_.find(node_id);
    if (it == blocks_.end()) return 0;
    return it->second.ipdom;
}

bool ControlFlowGraph::is_in_loop(std::uint64_t block_id, std::uint64_t header) const {
    if (header == 0) return false;
    auto it = blocks_.find(block_id);
    if (it == blocks_.end()) return false;
    const auto& headers = it->second.loop_headers;
    return std::find(headers.begin(), headers.end(), header) != headers.end();
}

}  // namespace engine::hlil
