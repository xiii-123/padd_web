/**
 * @file padd.h
 * @brief PADD (Proof of Allocable Data Deduplication) 核心接口定义
 *
 * 本文件定义了PADD协议的核心接口，包括：
 * - 密钥生成和管理
 * - 文件签名
 * - 挑战生成
 * - 证明生成和验证
 * - 元素序列化/反序列化
 *
 * @author PADD Team
 * @date 2025
 */

#pragma once

#include "bls_utils.h"
#include "file_utils.hpp"
#include <utility>
#include <memory>

#define TYPEA_PARAMS                                           \
    "type a\n"                                                 \
    "q 87807107996633125224377819847540498158068831994142082"  \
    "1102865339926647563088022295707862517942266222142315585"  \
    "8769582317459277713367317481324925129998224791\n"         \
    "h 12016012264891146079388821366740534204802954401251311"  \
    "822919615131047207289359704531102844802183906537786776\n" \
    "r 730750818665451621361119245571504901405976559617\n"     \
    "exp2 159\n"                                               \
    "exp1 107\n"                                               \
    "sign1 1\n"                                                \
    "sign0 1\n"

/**
 * @brief PADD证明结构
 *
 * 存储PADD证明的所有必要信息
 */
class Proof {
public:
    element_t mu;                                      ///< μ值（GT元素）
    element_t sigma;                                   ///< σ值（G1元素）
    std::unordered_map<size_t, std::vector<std::pair<std::string, bool>>> merkle_proofs;  ///< Merkle证明
    std::vector<element_t*> required_elements;          ///< 需要的元素
    std::vector<size_t> indices;                        ///< 索引列表
    element_t sig_mht;                                  ///< MHT签名
    std::string root_hash;                              ///< Merkle树根哈希

    /**
     * @brief 默认构造函数
     */
    Proof();

    /**
     * @brief 完整构造函数
     * @param mu μ值
     * @param sigma σ值
     * @param merkle_proofs Merkle证明映射
     * @param required_elements 需要的元素
     * @param root_hash 根哈希
     * @param sig_mht MHT签名
     * @param indices 索引列表
     */
    Proof(element_t* mu, element_t* sigma,
        std::unordered_map<size_t, std::vector<std::pair<std::string, bool>>> &merkle_proofs,
        std::vector<element_t*>& required_elements,
        std::string root_hash,
        element_t* sig_mht, std::vector<size_t>& indices);

    /**
     * @brief 析构函数
     */
    ~Proof();

    /**
     * @brief 序列化证明
     * @return 序列化后的字节数组
     */
    std::vector<std::byte> Proof_serialize();
};

/**
 * @brief 反序列化证明
 * @param buf 序列化的字节数组
 * @return 反序列化后的Proof对象
 */
Proof Proof_deserialize(const std::vector<std::byte>& buf);

/**
 * @brief 初始化签名元素
 * @return 初始化的element_t指针
 */
element_t* sig_init();

/**
 * @brief 构造t值
 * @param pkc BLS密钥对
 * @param file_name 文件名
 * @n 文件分片数量
 * @param u 元素u
 * @return t值（Base64编码的字符串）
 */
std::string construct_t(bls_pkc& pkc, const std::string& file_name, size_t n, element_t u);

/**
 * @brief 计算单个σ值
 * @param f 文件流
 * @param start 起始位置
 * @param num 数量
 * @param pkc BLS密钥对
 * @param u 元素u
 * @param sigma σ值（输出）
 */
void calculate_single_sigma(std::fstream& f, size_t start, size_t num, bls_pkc& pkc, element_t u, element_t sigma);

/**
 * @brief 计算Φ值
 * @param f 文件流
 * @param pkc BLS密钥对
 * @param u 元素u
 * @param shard_size 分片大小
 * @return Φ向量（元素指针向量）
 */
std::vector<element_t *> calculate_phi(std::fstream& f, bls_pkc& pkc, element_t u, size_t shard_size);

/**
 * @brief 释放Φ值
 * @param phi Φ向量
 */
void free_phi(std::vector<element_t *>& phi);

/**
 * @brief 生成签名
 * @param pkc BLS密钥对
 * @param file_name 文件名
 * @param f 文件流
 * @param tree Merkle树
 * @param shard_size 分片大小
 * @return {t值, MHT签名, Φ向量}
 */
std::pair<std::pair<std::string, element_t*>, std::vector <element_t*>>
sig_gen(bls_pkc& pkc, std::string file_name, std::fstream& f, MerkleTree&, size_t shard_size);

/**
 * @brief 反序列化t值
 * @param t t值（字符串）
 * @param g 元素g
 * @param pk 元素pk
 * @return {成功标志, 元素u}
 */
std::pair<bool, element_t*> deserialize_t(std::string t, element_t g, element_t pk);

/**
 * @brief 随机生成挑战
 * @param n 挑战数量
 * @return 挑战向量 {索引, 元素}
 */
std::vector<std::pair<size_t, element_t*>> gen_chal_randomly(size_t n);

/**
 * @brief 从给定索引生成挑战
 * @param indices 索引向量
 * @return 挑战向量 {索引, 元素}
 */
std::vector<std::pair<size_t, element_t*>> gen_chal_from_indices(std::vector<size_t> indices);

/**
 * @brief 释放挑战
 * @param challenges 挑战向量
 */
void free_chal(std::vector<std::pair<size_t, element_t*>>& challenges);

/**
 * @brief 序列化挑战
 * @param chal 挑战向量
 * @return 序列化后的字节数组
 */
std::vector<char> serialize_chal(const std::vector<std::pair<size_t, element_t*>>& chal);

/**
 * @brief 释放BLS密钥对
 * @param pkc BLS密钥对指针
 */
void free_pkc(bls_pkc* pkc);

/**
 * @brief 释放元素指针
 * @param t 元素指针
 */
void free_element_ptr(element_t* t);

/**
 * @brief 生成BLS密钥对
 * @return BLS密钥对指针
 */
bls_pkc* key_gen();

/**
 * @brief 序列化挑战
 * @param challenges 挑战向量
 * @return 序列化后的字节数组
 */
std::vector<std::byte> chal_serialize(const std::vector<std::pair<size_t, element_t*>>& challenges);

/**
 * @brief 反序列化挑战
 * @param buf 序列化的字节数组
 * @return 挑战向量
 */
std::vector<std::pair<size_t, element_t*>> chal_deserialize(const std::vector<std::byte>& buf);

/**
 * @brief 初始化PADD系统
 * @param pk 公钥
 * @param sk 私钥
 * @param g 生成元g
 */
void padd_init(element_t pk, element_t sk, element_t g);

/**
 * @brief 从挑战向量提取索引
 * @param chal 挑战向量
 * @return 索引向量
 */
std::vector<size_t> extract_first(const std::vector<std::pair<size_t, element_t*>>& chal);

/**
 * @brief 生成PADD证明
 * @param f 文件流
 * @param phi Φ向量
 * @param chal 挑战向量
 * @param sig_mht MHT签名
 * @param tree Merkle树
 * @param shard_size 分片大小
 * @return 证明对象
 */
Proof gen_proof(std::fstream& f,
    std::vector<element_t *>& phi,
    std::vector<std::pair<size_t, element_t*>>& chal,
    element_t* sig_mht,
    MerkleTree& tree,
    size_t shard_size
);

/**
 * @brief 验证PADD证明
 * @param pkc BLS密钥对
 * @param chal 挑战向量
 * @param proof 证明对象
 * @param u 元素u
 * @return 验证成功返回true，失败返回false
 */
bool verify(bls_pkc& pkc,
    std::vector<std::pair<size_t, element_t*>>& chal,
    Proof &proof,
    element_t u
);

/**
 * @brief 序列化BLS密钥对
 * @param pkc BLS密钥对指针
 * @return 序列化后的字节数组
 */
std::vector<std::byte> bls_pkc_serialize(bls_pkc* pkc);

/**
 * @brief 反序列化BLS密钥对
 * @param buf 序列化的字节数组
 * @return BLS密钥对指针
 */
bls_pkc* bls_pkc_deserialize(const std::vector<std::byte>& buf);

/**
 * @brief 序列化BLS密钥ID（包含g、v和spk）
 *
 * 序列化g、pk->v和pk->spk三个元素，用作key_id
 *
 * @param pk BLS公钥指针
 * @param g 元素g
 * @return 序列化后的字节数组 {g, v, spk}
 */
std::vector<std::byte> bls_keyid_serialize(bls_pk * pk, element_t g);

/**
 * @brief 反序列化BLS密钥ID（包含g、v和spk）
 *
 * 反序列化g、pk->v和pk->spk三个元素
 *
 * @param pk BLS公钥指针
 * @param g 元素g（输出）
 * @param buf 序列化的字节数组 {g, v, spk}
 * @return 成功返回true，失败返回false
 */
bool bls_keyid_deserialize(
    bls_pk * pk, element_t g,
    const std::vector<std::byte>& buf
);

/**
 * @brief 序列化BLS公钥（仅v和spk）
 *
 * 只序列化pk的v和spk两个元素，不包含g
 *
 * @param pk BLS公钥指针
 * @return 序列化后的字节数组 {v, spk}
 */
std::vector<std::byte> bls_pk_serialize(bls_pk * pk);

/**
 * @brief 反序列化BLS公钥（仅v和spk）
 *
 * 只反序列化pk的v和spk两个元素，不包含g
 *
 * @param pk BLS公钥指针
 * @param buf 序列化的字节数组 {v, spk}
 * @return 成功返回true，失败返回false
 */
bool bls_pk_deserialize(
    bls_pk * pk,
    const std::vector<std::byte>& buf
);

/**
 * @brief 序列化BLS私钥
 * @param sk BLS私钥指针
 * @return 序列化后的字节数组
 */
std::vector<std::byte> bls_sk_serialize(bls_sk* sk);

/**
 * @brief 反序列化BLS私钥
 * @param sk BLS私钥指针
 * @param buf 序列化的字节数组
 * @return 成功返回true，失败返回false
 */
bool bls_sk_deserialize(
    bls_sk* sk,
    const std::vector<std::byte>& buf
);

/**
 * @brief 计算元素列表的字节长度
 * @param e 元素指针向量
 * @return 字节长度
 */
int elements_length_in_bytes(std::vector<element_t*>& e);

/**
 * @brief 将元素列表转换为字节
 * @param data 输出缓冲区
 * @param e 元素指针向量
 * @return 字节长度
 */
int elements_to_bytes(unsigned char *data, std::vector<element_t*>& e);

/**
 * @brief 从字节转换元素列表
 * @param e 元素指针向量（输出）
 * @param data 输入缓冲区
 * @return 成功返回0，失败返回非0
 */
int elements_from_bytes(std::vector<element_t*>& e, unsigned char *data);
