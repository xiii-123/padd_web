#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace SecureUSB {

using byte = std::uint8_t;
using ByteArray = std::vector<byte>;

/**
 * 初始化USB设备
 * @return true 成功，false 失败
 */
bool init();

/**
 * 存储键值对
 * @param key 键
 * @param value 值（字节数组）
 * @return true 成功，false 失败
 */
bool put(const std::string& key, const ByteArray& value);

/**
 * 获取值
 * @param key 键
 * @param value_out 输出值
 * @return true 成功，false 失败（key不存在）
 */
bool get(const std::string& key, ByteArray& value_out);

/**
 * 删除指定 key
 * @param key 键
 * @return true 成功，false 失败（key不存在）
 */
bool del(const std::string& key);

/**
 * 清除所有键值对
 * @return true 成功，false 失败
 */
bool clean();

/**
 * 关闭连接
 */
void close();

} // namespace SecureUSB
