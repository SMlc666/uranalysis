#pragma once

#include "engine/mlil.h"
#include <vector>
#include <unordered_map>
#include <vector>
#include <set>

namespace engine::hlil {

struct BlockInfo {
    const mlil::BasicBlock* block = nullptr;
    std::uint64_t id = 0;
    std::vector<std::uint64_t> preds;
    std::vector<std::uint64_t> succs;
    
    // Dominator info
    std::uint64_t idom = 0; 
    std::set<std::uint64_t> dom_frontier;

    // Post-Dominator info (The standard way to find merge points)
    std::uint64_t ipdom = 0;
    
    // Loop info
    std::vector<std::uint64_t> loop_headers;
    std::vector<std::uint64_t> back_edges;
};

class ControlFlowGraph {
public:
    explicit ControlFlowGraph(const mlil::Function& func);

    const BlockInfo* get_info(std::uint64_t id) const;
    BlockInfo* get_info_mut(std::uint64_t id);
    
    std::uint64_t entry_id() const { return entry_; }
    
    // Finds the immediate post-dominator which serves as the natural merge point
    std::uint64_t find_merge_point(std::uint64_t node_id);

    bool is_in_loop(std::uint64_t block_id, std::uint64_t header) const;

private:
    std::uint64_t entry_;
    std::unordered_map<std::uint64_t, BlockInfo> blocks_;
    std::vector<std::uint64_t> post_order_;

    void build_graph(const mlil::Function& func);
    void compute_dominators();
    void compute_post_dominators(const mlil::Function& func);
    void compute_loops();
    void mark_loop(std::uint64_t header, std::uint64_t latch);
};

}  // namespace engine::hlil
