/**
 * @file vrf.cpp
 * @brief VRF (Verifiable Random Function) 实现
 *
 * 本文件实现了可验证随机函数（VRF），包括：
 * - 密钥对生成
 * - 证明生成 (prove_sk)
 * - 证明验证 (ver_pk)
 * - 序列化/反序列化
 * - 从VRF输出生成随机索引
 *
 * @author PADD Team
 * @date 2025
 */

#include "crypto/vrf.h"
#include "crypto/padd.h"
#include <pbc/pbc.h>
#include <vector>
#include <algorithm>
#include <string>
#include <functional>
#include <numeric>
#include <random>
#include <sstream>
#include <iomanip>

/**
 * @brief 生成VRF密钥对
 *
 * 生成随机的私钥sk、生成元g和公钥pk=g^sk
 * PAIRING已在main()中初始化，不再重复初始化
 *
 * @return 密钥对 {sk, {g, pk}}
 */
std::pair<element_t*, std::pair<element_t*, element_t*>> gen()
{
    element_t* sk = (element_t*)malloc(sizeof(element_t));
    element_t* g = (element_t*)malloc(sizeof(element_t));
    element_t* pk = (element_t*)malloc(sizeof(element_t));

    element_init_Zr(*sk, PAIRING);
    element_init_G1(*g, PAIRING);
    element_init_G1(*pk, PAIRING);

    element_random(*sk);
    element_random(*g);
    element_pow_zn(*pk, *g, *sk);

    return std::make_pair(sk, std::make_pair(g, pk));
}

/**
 * @brief 生成VRF证明
 *
 * 给定种子random_seed和私钥sk，生成VRF输出y和证明pi
 *
 * @param random_seed VRF种子
 * @param sk 私钥
 * @param g 生成元
 * @return {y, pi} VRF输出和证明
 */
std::pair<element_t*, element_t*> prove_sk(std::string random_seed, element_t* sk, element_t* g)
{
    element_t x;
    element_t power;
    element_t* y = (element_t*)malloc(sizeof(element_t));
    element_t* pi = (element_t*)malloc(sizeof(element_t));

    element_init_Zr(x, PAIRING);
    element_init_Zr(power, PAIRING);
    element_init_GT(*y, PAIRING);
    element_init_G1(*pi, PAIRING);

    element_from_hash(x, random_seed.data(), random_seed.size());
    element_set1(power);

    element_add(x, x, *sk);
    element_div(power, power, x);

    element_pairing(*y, *g, *g);
    element_pow_zn(*y, *y, power);

    element_pow_zn(*pi, *g, power);

    return std::pair(y, pi);
}

/**
 * @brief 验证VRF证明
 *
 * 验证给定的VRF输出y和证明pi是否正确
 *
 * @param random_seed VRF种子
 * @param y VRF输出
 * @param pi VRF证明
 * @param pk 公钥
 * @param g 生成元
 * @return 验证成功返回true，失败返回false
 */
bool ver_pk(std::string random_seed, element_t* y, element_t* pi, element_t* pk, element_t* g)
{
    element_t x;
    element_t temp1;
    element_t temp2;
    element_t temp3;
    element_t temp4;

    element_init_Zr(x, PAIRING);
    element_init_G1(temp1, PAIRING);
    element_init_GT(temp2, PAIRING);
    element_init_GT(temp3, PAIRING);
    element_init_GT(temp4, PAIRING);

    element_from_hash(x, random_seed.data(), random_seed.size());

    element_pow_zn(temp1, *g, x);
    element_mul(temp1, temp1, *pk);

    element_pairing(temp2, temp1, *pi);

    element_pairing(temp3, *g, *g);

    if (element_cmp(temp2, temp3)) return false;

    element_pairing(temp4, *g, *pi);
    if (element_cmp(*y, temp4)) return false;

    element_clear(x);
    element_clear(temp1);
    element_clear(temp2);
    element_clear(temp3);
    element_clear(temp4);
    return true;
}

/**
 * @brief 序列化VRF对 (y, pi)
 *
 * 将VRF输出y和证明pi序列化为十六进制字符串
 *
 * @param pair VRF对 {y, pi}
 * @return 十六进制字符串
 */
std::string serialize_vrf_pair(const std::pair<element_t*, element_t*>& pair)
{
    size_t y_size = element_length_in_bytes(*pair.first);
    size_t pi_size = element_length_in_bytes(*pair.second);

    std::vector<unsigned char> buffer(y_size + pi_size);
    size_t offset = 0;

    offset += element_to_bytes(buffer.data() + offset, *pair.first);
    offset += element_to_bytes(buffer.data() + offset, *pair.second);

    std::ostringstream oss;
    oss << std::hex;
    for (unsigned char byte : buffer) {
        oss << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    return oss.str();
}

/**
 * @brief 反序列化VRF对 (y, pi)
 *
 * 从十六进制字符串反序列化VRF输出y和证明pi
 *
 * @param str 十六进制字符串
 * @return {y, pi} VRF对
 * @throw std::invalid_argument 字符串长度无效
 * @throw std::runtime_error 反序列化不完整
 */
std::pair<element_t*, element_t*> deserialize_vrf_pair(const std::string& str)
{
    if (str.size() % 2 != 0) {
        throw std::invalid_argument("Invalid serialized string length");
    }

    std::vector<unsigned char> buffer(str.size() / 2);
    for (size_t i = 0; i < buffer.size(); ++i) {
        std::string byte_str = str.substr(2*i, 2);
        buffer[i] = static_cast<unsigned char>(std::stoi(byte_str, nullptr, 16));
    }

    element_t* y = (element_t*)malloc(sizeof(element_t));
    element_t* pi = (element_t*)malloc(sizeof(element_t));
    element_init_GT(*y, PAIRING);
    element_init_G1(*pi, PAIRING);

    size_t offset = 0;
    offset += element_from_bytes(*y, buffer.data() + offset);
    offset += element_from_bytes(*pi, buffer.data() + offset);

    if (offset != buffer.size()) {
        element_clear(*y);
        element_clear(*pi);
        delete y;
        delete pi;
        throw std::runtime_error("Deserialization incomplete");
    }

    return {y, pi};
}

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
std::vector<size_t> random_from_vrf(std::string vrf_str, size_t n, size_t k)
{
    if (n == 0 || k == 0 || k > n) {
        return {};
    }

    std::hash<std::string> hasher;
    size_t seed = hasher(vrf_str);

    std::mt19937_64 engine(seed);

    std::vector<size_t> result(n);
    std::iota(result.begin(), result.end(), 0);

    for (size_t i = 0; i < k; ++i) {
        std::uniform_int_distribution<size_t> dist(i, n - 1);
        size_t j = dist(engine);
        std::swap(result[i], result[j]);
    }

    result.resize(k);
    std::sort(result.begin(), result.end());

    return result;
}
