#pragma once

#include <fstream>
#include <vector>
#include <string>
#include <shared_mutex>
#include "bls_utils.h"
#include <iostream>
#include <algorithm>
#include <memory>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstddef>
#include <openssl/sha.h>
#include <cassert>

extern std::shared_mutex FILE_RW_MUTEX;
const long DEFAULT_SHARD_SIZE = 1024 * 4;


// File utility functions

/**
 * @brief 将字符向量转换为无符号长整型
 * @param data 需要转换的字符向量
 * @param fill_byte 填充字节，默认为'\0'
 * @param is_little_endian 是否为小端序，默认为true
 * @return 转换后的无符号长整型值
 */
unsigned long vector_to_ulong(const std::vector<char>& data, char fill_byte = '\0', bool is_little_endian = true);

/**
 * @brief 从文件路径中提取文件名
 * 
 * 该函数从完整的文件路径中提取出文件名部分。
 * 例如，从路径 "/path/to/file.txt" 中提取出 "file.txt"。
 * 
 * @param filePath 完整的文件路径
 * @return std::string 提取出的文件名
 */
std::string get_fileName_from_path(const std::string& filePath);

std::vector<char> read_file_segment(std::fstream& file, size_t start, size_t num);

/**
 * @brief 获取文件的大小和分片数量
 * 
 * 该函数计算一个已打开文件的总大小，并根据指定的分片大小确定需要的分片数量。
 * 
 * @param file 已打开的输入文件流引用
 * @param shard_size 单个分片的大小（以字节为单位）
 * @return std::pair<size_t, size_t> 包含文件总大小和所需分片数量的键值对
 *         - first: 文件的总大小（以字节为单位）
 *         - second: 根据指定分片大小计算得出的分片数量
 */
std::pair<size_t, size_t> get_file_size_and_shard_count(std::fstream& file, size_t shard_size);


// 将二进制哈希转换为十六进制字符串
std::string to_hex(const std::vector<std::byte>& hash);

// 从十六进制字符串转换回字节向量
std::vector<std::byte> from_hex(const std::string& hexStr);

// 重载1: 接受字符串输入
std::vector<std::byte> sha256(const std::string& str);

// 重载2: 接受字节向量输入
std::vector<std::byte> sha256(const std::vector<std::byte>& data);

class MerkleNode : public std::enable_shared_from_this<MerkleNode> {
    public:
        std::vector<std::byte> hash;
        std::shared_ptr<MerkleNode> left;
        std::shared_ptr<MerkleNode> right;
        std::weak_ptr<MerkleNode> parent;
        bool is_leaf;

        MerkleNode(const std::vector<std::byte>& data, bool leaf = true)
            : hash(data), left(nullptr), right(nullptr), is_leaf(leaf) {}

        static std::shared_ptr<MerkleNode> create_node(std::shared_ptr<MerkleNode> left, std::shared_ptr<MerkleNode> right) {
            auto node = std::shared_ptr<MerkleNode>(new MerkleNode(left, right));
            if (left) left->parent = node;
            if (right) right->parent = node;
            return node;
        }

        void compute_hash();

    private:
        MerkleNode(std::shared_ptr<MerkleNode> left, std::shared_ptr<MerkleNode> right)
            : left(left), right(right), is_leaf(false) {
            compute_hash();
        }
};

class MerkleTree {
private:
    std::shared_ptr<MerkleNode> root;
    std::vector<std::shared_ptr<MerkleNode>> leaves;

    std::shared_ptr<MerkleNode> build_tree(const std::vector<std::shared_ptr<MerkleNode>>& nodes);

    // 序列化辅助函数 - 前序遍历
    void serialize_node(std::ostringstream& oss, const std::shared_ptr<MerkleNode>& node) const;

    // 反序列化辅助函数 - 前序遍历
    std::shared_ptr<MerkleNode> deserialize_node(std::istringstream& iss) const;

    // 收集所有叶子节点
    void collect_leaves(const std::shared_ptr<MerkleNode>& node);

public:
    MerkleTree() : root(nullptr) {}
    ~MerkleTree() { clear(); }

    void clear() {
        root.reset();
        leaves.clear();
    }

    void build(const std::vector<std::string>& data) {
        clear();
        if (data.empty()) return;

        for (const auto& item : data) {
            leaves.push_back(std::make_shared<MerkleNode>(sha256(item)));
        }

        root = build_tree(leaves);
    }

    std::string get_root_hash() const {
        return root ? to_hex(root->hash) : "";
    }

    void add_leaf(const std::string& data) {
        leaves.push_back(std::make_shared<MerkleNode>(sha256(data)));
        root = build_tree(leaves);
    }

    void update_leaf(size_t index, const std::string& new_data) {
        if (index >= leaves.size()) {
            throw std::out_of_range("Leaf index out of range");
        }
        leaves[index]->hash = sha256(new_data);
        leaves[index]->compute_hash();
    }

    void remove_leaf(size_t index) {
        if (index >= leaves.size()) {
            throw std::out_of_range("Leaf index out of range");
        }
        leaves.erase(leaves.begin() + index);
        root = build_tree(leaves);
    }

    std::vector<std::pair<std::string, bool>> get_proof(size_t index) const;
    
    static bool verify_proof(const std::vector<std::pair<std::string, bool>>& proof, const std::string& rootHash);

    std::unordered_map<size_t, std::vector<std::pair<std::string, bool>>> 
    batch_get_proofs(const std::vector<size_t>& indices) const;

    /**
     * Verifies multiple proofs against the current root hash
     * @param proofs Map of index to proof
     * @return Map of index to verification result (true/false)
     */
    static bool batch_verify_proofs(const std::unordered_map<size_t, std::vector<std::pair<std::string, bool>>>& proofs, std::string root_hash);

    // Serialize a proof into a string
    std::string serialize_proof(const std::vector<std::pair<std::string, bool>>& proof) const;

    // Deserialize a proof from a string
    static std::vector<std::pair<std::string, bool>> deserialize_proof(const std::string& serialized);

    static std::string serialize_batch_proofs(const std::unordered_map<size_t, std::vector<std::pair<std::string, bool>>>& proofs);

    /**
     * Deserializes batch proofs from string format
     * @throws std::invalid_argument for malformed input
     */
    static std::unordered_map<size_t, std::vector<std::pair<std::string, bool>>> 
    deserialize_batch_proofs(const std::string& serialized);

    // 序列化整个Merkle树
    std::string serialize() const;

    // 反序列化整个Merkle树
    void deserialize(const std::string& serialized);

    void print_tree() const;

    void build_from_file(std::fstream& f, size_t shard_size) ;
};
