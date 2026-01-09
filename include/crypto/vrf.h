/**
 * @file vrf.h
 * @brief VRF (Verifiable Random Function) 接口定义
 *
 * 本文件定义了可验证随机函数（VRF）的接口，包括：
 * - 密钥对生成
 * - 证明生成
 * - 证明验证
 * - 序列化/反序列化
 * - 从VRF输出生成随机索引
 *
 * @author PADD Team
 * @date 2025
 */

#pragma once

#include <utility>
#include <memory>
#include <pbc/pbc.h>
#include <vector>

/**
 * @brief 生成VRF密钥对
 *
 * 生成随机的私钥sk、生成元g和公钥pk=g^sk
 * 注意：PAIRING需要在调用前初始化
 *
 * @return 密钥对 {sk, {g, pk}}
 *         - sk: 私钥 (Zr元素)
 *         - g: 生成元 (G1元素)
 *         - pk: 公钥 (G1元素, pk = g^sk)
 */
std::pair<element_t*, std::pair<element_t*, element_t*>> gen();

/**
 * @brief 生成VRF证明
 *
 * 给定种子random_seed和私钥sk，生成VRF输出y和证明pi
 *
 * @param x VRF种子字符串
 * @param sk 私钥
 * @param g 生成元
 * @return VRF对 {y, pi}
 *         - y: VRF输出 (GT元素)
 *         - pi: VRF证明 (G1元素)
 */
std::pair<element_t*, element_t*> prove_sk(std::string x, element_t* sk, element_t* g);

/**
 * @brief 验证VRF证明
 *
 * 验证给定的VRF输出y和证明pi是否与公钥pk和种子x匹配
 *
 * @param x VRF种子字符串
 * @param y VRF输出
 * @param pi VRF证明
 * @param pk 公钥
 * @param g 生成元
 * @return 验证成功返回true，失败返回false
 */
bool ver_pk(std::string x, element_t* y, element_t* pi, element_t* pk, element_t* g);

/**
 * @brief 序列化VRF对 (y, pi)
 *
 * 将VRF输出y和证明pi序列化为十六进制字符串
 *
 * @param pair VRF对 {y, pi}
 * @return 十六进制字符串
 */
std::string serialize_vrf_pair(const std::pair<element_t*, element_t*>& pair);

/**
 * @brief 反序列化VRF对 (y, pi)
 *
 * 从十六进制字符串反序列化VRF输出y和证明pi
 *
 * @param str 十六进制字符串
 * @return VRF对 {y, pi}
 */
std::pair<element_t*, element_t*> deserialize_vrf_pair(const std::string& str);

/**
 * @brief 从VRF输出生成随机索引
 *
 * 使用VRF字符串作为种子，从[0, n-1]中选取k个不重复的随机索引
 * 结果按升序排序
 *
 * @param vrf_str VRF字符串（作为种子）
 * @param n 索引范围 [0, n-1]
 * @param k 选取的索引数量
 * @return 排序后的随机索引向量
 */
std::vector<size_t> random_from_vrf(std::string vrf_str, size_t n, size_t k);
