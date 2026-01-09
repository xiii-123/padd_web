#include "crypto/bls_utils.h"
#include "crypto/file_utils.hpp"
#include <openssl/evp.h>
#include <stdexcept>
#include <cmath>
#include <algorithm>
#include <cstring>
#include <vector>
#include <fstream>
#include <iostream>
#include <openssl/sha.h>
#include <utility>

// Initialize pairing parameters

std::shared_mutex FILE_RW_MUTEX;

// BLS utility functions implementation

void MerkleNode::compute_hash() {
    if (is_leaf) return;
    
    std::vector<std::byte> combined;
    if (left) combined.insert(combined.end(), left->hash.begin(), left->hash.end());
    if (right) combined.insert(combined.end(), right->hash.begin(), right->hash.end());
    else combined.insert(combined.end(), left->hash.begin(), left->hash.end());
    
    hash = sha256(combined);
    
    if (auto parent_ptr = parent.lock()) {
        parent_ptr->compute_hash();
    }
}

void MerkleTree::serialize_node(std::ostringstream& oss, const std::shared_ptr<MerkleNode>& node) const {
    if (!node) {
        oss << "null ";
        return;
    }
    
    oss << to_hex(node->hash) << " ";
    oss << (node->is_leaf ? "1 " : "0 ");
    serialize_node(oss, node->left);
    serialize_node(oss, node->right);
}

std::shared_ptr<MerkleNode> MerkleTree::deserialize_node(std::istringstream& iss) const {
    std::string hashHex;
    if (!(iss >> hashHex) || hashHex == "null") {
        return nullptr;
    }
    
    std::string leafFlag;
    iss >> leafFlag;
    bool isLeaf = (leafFlag == "1");
    
    auto node = std::make_shared<MerkleNode>(from_hex(hashHex), isLeaf);
    node->left = deserialize_node(iss);
    node->right = deserialize_node(iss);
    
    if (node->left) node->left->parent = node;
    if (node->right) node->right->parent = node;
    
    return node;
}

void MerkleTree::collect_leaves(const std::shared_ptr<MerkleNode>& node) {
    if (!node) return;
    
    if (node->is_leaf) {
        leaves.push_back(node);
    } else {
        collect_leaves(node->left);
        collect_leaves(node->right);
    }
}

std::vector<std::pair<std::string, bool>> MerkleTree::get_proof(size_t index) const {
    if (index >= leaves.size()) {
        throw std::out_of_range("Leaf index out of range");
    }

    std::vector<std::pair<std::string, bool>> proof; // pair of (hash, isLeft)
    auto node = leaves[index];
    auto parent = node->parent.lock();
    if (parent->left && parent->left == node){
        proof.emplace_back(to_hex(node->hash), true);
    } else{
        proof.emplace_back(to_hex(node->hash), false);
    }

    while (parent) {
        if (parent->left && parent->left != node) {
            // 当前节点是右孩子，所以兄弟是左孩子
            proof.emplace_back(to_hex(parent->left->hash), true);
        } else if (parent->right && parent->right != node) {
            // 当前节点是左孩子，所以兄弟是右孩子
            proof.emplace_back(to_hex(parent->right->hash), false);
        }
        node = parent;
        parent = node->parent.lock();
    }

    return proof;
}

std::shared_ptr<MerkleNode> MerkleTree::build_tree(const std::vector<std::shared_ptr<MerkleNode>>& nodes) {
    if (nodes.empty()) return nullptr;
    if (nodes.size() == 1) return nodes[0];

    std::vector<std::shared_ptr<MerkleNode>> parents;
    for (size_t i = 0; i < nodes.size(); i += 2) {
        if (i + 1 < nodes.size()) {
            parents.push_back(MerkleNode::create_node(nodes[i], nodes[i+1]));
        } else {
            parents.push_back(MerkleNode::create_node(nodes[i], nullptr));
        }
    }
    return build_tree(parents);
}

bool MerkleTree::verify_proof(const std::vector<std::pair<std::string, bool>>& proof, 
    const std::string& rootHash) {
    std::vector<std::byte> currentHash = from_hex(proof[0].first);

    for (int i = 1; i < proof.size(); i++) {

    std::vector<std::byte> proofHash = from_hex(proof[i].first);
    std::vector<std::byte> combined;

    // 根据证明中的位置信息决定组合顺序
    if (proof[i].second) {
        // 证明节点是左兄弟，所以应该放在前面
        combined.insert(combined.end(), proofHash.begin(), proofHash.end());
        combined.insert(combined.end(), currentHash.begin(), currentHash.end());
    } else {
        // 证明节点是右兄弟，所以应该放在后面
        combined.insert(combined.end(), currentHash.begin(), currentHash.end());
        combined.insert(combined.end(), proofHash.begin(), proofHash.end());
    }

    currentHash = sha256(combined);
    }

    return to_hex(currentHash) == rootHash;
}

std::unordered_map<size_t, std::vector<std::pair<std::string, bool>>> 
MerkleTree::batch_get_proofs(const std::vector<size_t>& indices) const {
    std::unordered_map<size_t, std::vector<std::pair<std::string, bool>>> proofs;
    
    for (size_t index : indices) {
        if (index >= leaves.size()) {
            throw std::out_of_range("Leaf index " + std::to_string(index) + 
                                    " out of range [0-" + 
                                    std::to_string(leaves.size()-1) + "]");
        }
        proofs[index] = get_proof(index);
    }
    
    return proofs;
}

bool MerkleTree::batch_verify_proofs(const std::unordered_map<size_t, 
std::vector<std::pair<std::string, bool>>>& proofs, std::string root_hash) {
    std::unordered_map<size_t, bool> results;
    for (const auto& [index, proof] : proofs) {
        if (!verify_proof(proof, root_hash)){return false;}
    }

    return true;
}

std::string MerkleTree::serialize_proof(const std::vector<std::pair<std::string, bool>>& proof) const {
    std::ostringstream oss;
    for (const auto& p : proof) {
        oss << p.first << ":" << (p.second ? "1" : "0") << " ";
    }
    return oss.str();
}

std::vector<std::pair<std::string, bool>> MerkleTree::deserialize_proof(const std::string& serialized) {
    std::vector<std::pair<std::string, bool>> proof;
    std::istringstream iss(serialized);
    std::string item;
    
    while (iss >> item) {
        size_t colon_pos = item.find(':');
        if (colon_pos == std::string::npos) {
            throw std::runtime_error("Invalid proof format");
        }
        
        std::string hash = item.substr(0, colon_pos);
        bool isLeft = (item.substr(colon_pos + 1) == "1");
        proof.emplace_back(hash, isLeft);
    }
    
    return proof;
}

std::string MerkleTree::serialize_batch_proofs(const std::unordered_map<size_t, std::vector<std::pair<std::string, bool>>>& proofs) {
    std::ostringstream oss;
    oss << proofs.size() << "|";  // Header with proof count
    
    for (const auto& [index, proof] : proofs) {
        oss << index << "|" << proof.size() << "|";
        
        for (const auto& [hash, isLeft] : proof) {
            oss << hash << ":" << (isLeft ? '1' : '0') << "|";
        }
    }
    
    return oss.str();
}

std::unordered_map<size_t, std::vector<std::pair<std::string, bool>>> 
MerkleTree::deserialize_batch_proofs(const std::string& serialized) {
    std::unordered_map<size_t, std::vector<std::pair<std::string, bool>>> proofs;
    std::istringstream iss(serialized);
    char delim;
    size_t proof_count;
    
    // Read header
    if (!(iss >> proof_count >> delim) || delim != '|') {
        throw std::invalid_argument("Invalid serialized format (header)");
    }

    for (size_t i = 0; i < proof_count; ++i) {
        // Read index
        size_t index;
        if (!(iss >> index >> delim) || delim != '|') {
            throw std::invalid_argument("Invalid index format");
        }

        // Read proof length
        size_t proof_len;
        if (!(iss >> proof_len >> delim) || delim != '|') {
            throw std::invalid_argument("Invalid proof length format");
        }

        // Read proof items
        std::vector<std::pair<std::string, bool>> proof;
        proof.reserve(proof_len);
        
        for (size_t j = 0; j < proof_len; ++j) {
            std::string hash;
            char dir, sep;
            
            if (!(iss >> hash >> sep >> dir >> delim) || 
                sep != ':' || delim != '|') {
                throw std::invalid_argument("Invalid proof item format");
            }
            
            proof.emplace_back(hash, dir == '1');
        }
        
        proofs[index] = std::move(proof);
    }
    
    return proofs;
}

std::string MerkleTree::serialize() const {
    std::ostringstream oss;
    serialize_node(oss, root);
    return oss.str();
}

void MerkleTree::deserialize(const std::string& serialized) {
    clear();
    std::istringstream iss(serialized);
    root = deserialize_node(iss);
    if (root) {
        collect_leaves(root);
    }
}

void MerkleTree::print_tree() const {
    if (!root) {
        std::cout << "Empty tree" << std::endl;
        return;
    }

    std::vector<std::shared_ptr<MerkleNode>> current_level;
    current_level.push_back(root);

    while (!current_level.empty()) {
        std::vector<std::shared_ptr<MerkleNode>> next_level;
        for (const auto& node : current_level) {
            std::cout << to_hex(node->hash).substr(0,16) << " ";
            if (node->left) next_level.push_back(node->left);
            if (node->right) next_level.push_back(node->right);
        }
        std::cout << std::endl;
        current_level = next_level;
    }
}

void MerkleTree::build_from_file(std::fstream& f, size_t shard_size) {
    if (!f.is_open()) {
        throw std::runtime_error("File is not open");
    }

    // Get file size and calculate number of shards needed
    auto [file_size, shard_count] = get_file_size_and_shard_count(f, shard_size);
    
    if (file_size == 0) {
        clear();  // Handle empty file case
        return;
    }

    std::vector<std::string> shards;
    shards.reserve(shard_count);  // Pre-allocate for efficiency

    // Read each shard and add to the tree
    for (size_t i = 0; i < shard_count; ++i) {
        size_t start_pos = i * shard_size;
        size_t read_size = (i == shard_count - 1) ? (file_size - start_pos) : shard_size;
        
        auto segment = read_file_segment(f, start_pos, read_size);
        shards.emplace_back(segment.data(), segment.size());
    }
    build(shards);
}

std::string to_hex(const std::vector<std::byte>& hash) {
    std::stringstream ss;
    for (std::byte b : hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') 
           << static_cast<int>(b);
    }
    return ss.str();
}

std::vector<std::byte> from_hex(const std::string& hexStr) {
    std::vector<std::byte> result;
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        std::string byteStr = hexStr.substr(i, 2);
        auto byte = static_cast<std::byte>(std::stoi(byteStr, nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

std::vector<std::byte> sha256(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    
    std::vector<std::byte> result;
    result.reserve(SHA256_DIGEST_LENGTH);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        result.push_back(static_cast<std::byte>(hash[i]));
    }
    return result;
}

std::vector<std::byte> sha256(const std::vector<std::byte>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.data(), data.size());
    SHA256_Final(hash, &sha256);
    
    std::vector<std::byte> result;
    result.reserve(SHA256_DIGEST_LENGTH);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        result.push_back(static_cast<std::byte>(hash[i]));
    }
    return result;
}


std::pair<size_t, size_t> get_file_size_and_shard_count(std::fstream& file, size_t shard_size = DEFAULT_SHARD_SIZE) {
    if (!file.is_open()) {
        throw std::runtime_error("File is not open");
    }
    if (shard_size == 0) {
        throw std::runtime_error("Shard size must be greater than 0");
    }

    // 使用共享锁保护文件读取操作
    std::shared_lock<std::shared_mutex> lock(FILE_RW_MUTEX);

    // 保存当前文件位置
    auto original_pos = file.tellg();
    auto buf = file.rdbuf();
    size_t file_size =  buf->pubseekoff(0, std::ios::end);

    // 计算分片数量
    size_t num_shards = (file_size + shard_size - 1) / shard_size;

    return {file_size, num_shards};

}

void sign_message(element_t sk, std::string message, element_t sig) {
    element_t h;
    element_init_G1(h, PAIRING);
    element_from_hash(h, (char*)message.c_str(), message.length());
    element_pow_zn(sig, h, sk);
    element_clear(h);
}

unsigned long vector_to_ulong(
    const std::vector<char>& data,
    char fill_byte,
    bool is_little_endian
) {
    if (data.empty()) {
        throw std::runtime_error("Input data is empty");
    }

    // 复制数据到临时缓冲区，自动填充不足部分
    std::vector<char> bytes(sizeof(unsigned long), fill_byte);
    std::copy_n(
        data.begin(),
        std::min(data.size(), bytes.size()),
        bytes.begin()
    );

    // 处理字节序
    if (!is_little_endian) {
        std::reverse(bytes.begin(), bytes.end());
    }

    // 转换为 unsigned long
    unsigned long result = 0;
    std::memcpy(&result, bytes.data(), sizeof(unsigned long));
    return result;
}

int verify_signature(element_t sig, element_t g, element_t public_key, std::string message) {
    element_t h;
    element_init_G1(h, PAIRING);
    element_from_hash(h, (char*)message.c_str(), message.length());

    element_t temp1, temp2;
    element_init_GT(temp1, PAIRING);
    element_init_GT(temp2, PAIRING);

    element_pairing(temp1, sig, g);
    element_pairing(temp2, h, public_key);

    int result = !element_cmp(temp1, temp2);

    element_clear(h);
    element_clear(temp1);
    element_clear(temp2);

    return result;
}

std::string get_fileName_from_path(const std::string& filePath) {
    // 查找最后一个路径分隔符（支持Windows和Unix风格）
    size_t pos = filePath.find_last_of("/\\");
    
    // 如果找到分隔符，返回分隔符后面的部分
    if (pos != std::string::npos) {
        return filePath.substr(pos + 1);
    }
    
    // 如果没有分隔符，直接返回原字符串
    return filePath;
}

void compress_element(unsigned char **data, int *n, element_t sig, pairing_t PAIRING) {
    *n = pairing_length_in_bytes_compressed_G1(PAIRING);
    element_to_bytes_compressed(*data, sig);
}

void decompress_element(element_t sig, unsigned char *data, int n) {
    element_from_bytes_compressed(sig, data);
}

std::vector<char> read_file_segment(std::fstream& file, size_t start, size_t num) {
    std::shared_lock<std::shared_mutex> lock(FILE_RW_MUTEX);
    
    // 检查文件是否打开
    if (!file.is_open()) {
        throw std::runtime_error("File is not open");
    }

    // 定位到起始位置
    file.seekg(static_cast<std::streamoff>(start));
    if (file.fail()) {  // 检查是否定位失败（如 start 超过文件大小）
        throw std::runtime_error("Seek position exceeds file size");
    }

    // 获取剩余可读字节数
    const auto current_pos = file.tellg();
    file.seekg(0, std::ios::end);
    const auto remaining_bytes = static_cast<size_t>(file.tellg() - current_pos);
    file.seekg(current_pos);  // 恢复位置

    // 调整实际要读取的字节数
    const size_t bytes_to_read = std::min(num, remaining_bytes);
    std::vector<char> buffer(bytes_to_read);

    // 读取数据
    file.read(buffer.data(), static_cast<std::streamsize>(bytes_to_read));

    // 检查是否发生严重错误（非EOF的读取错误）
    if (file.bad()) {
        throw std::runtime_error("Read operation failed");
    }

    // 确保缓冲区大小与实际读取一致（防御性编程）
    buffer.resize(static_cast<size_t>(file.gcount()));
    return buffer;
}