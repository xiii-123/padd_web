/**
 * @file secure_usb.cpp
 * @brief SecureUSB键值存储实现
 *
 * 本文件实现了基于文件系统的安全键值存储功能。
 * 数据以十六进制格式存储，使用制表符作为分隔符。
 *
 * @author PADD Team
 * @date 2025
 */

#include "secure_usb/secure_usb.h"

#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <string>
#include <cstdlib>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <iostream>

namespace fs = std::filesystem;
namespace SecureUSB {

// 全局状态变量
static fs::path g_usb_path;
static fs::path g_kv_path;
static bool g_initialized = false;

// 常量定义
static const char* DEFAULT_USB_PATH = "/mnt/f";
static const char* FLAG_FILE = "secure_device.flag";
static const char* KV_FILE = "kv_store.db";

/**
 * @brief 将字节数组转换为十六进制字符串
 * @param bytes 字节数组
 * @return 十六进制字符串
 */
static std::string bytes_to_hex(const ByteArray& bytes)
{
    std::ostringstream oss;
    for (byte b : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

/**
 * @brief 将十六进制字符串转换为字节数组
 * @param hex 十六进制字符串
 * @return 字节数组
 */
static ByteArray hex_to_bytes(const std::string& hex)
{
    ByteArray bytes;
    if (hex.length() % 2 != 0) {
        return bytes;
    }

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        try {
            unsigned long b = std::stoul(byteString, nullptr, 16);
            bytes.push_back(static_cast<byte>(b));
        } catch (...) {
            return ByteArray();
        }
    }
    return bytes;
}

/**
 * @brief 解析USB路径
 * @return USB文件系统路径
 */
static fs::path resolve_usb_path()
{
    const char* env = std::getenv("SECURE_USB_PATH");
    if (env && env[0] != '\0') {
        return fs::path(env);
    }
    return fs::path(DEFAULT_USB_PATH);
}

/**
 * @brief 从文件加载键值存储
 * @return 键值映射表
 */
static std::unordered_map<std::string, ByteArray> load_kv()
{
    std::unordered_map<std::string, ByteArray> kv;
    std::ifstream in(g_kv_path);
    if (!in.is_open()) {
        return kv;
    }

    std::string line;
    while (std::getline(in, line)) {
        // 使用 '\t' 作为分隔符，避免与base64中的 '=' 冲突
        auto pos = line.find('\t');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string hex_value = line.substr(pos + 1);
            kv[key] = hex_to_bytes(hex_value);
        }
    }
    return kv;
}

/**
 * @brief 保存键值存储到文件
 * @param kv 键值映射表
 * @return 成功返回true，失败返回false
 */
static bool save_kv(const std::unordered_map<std::string, ByteArray>& kv)
{
    std::ofstream out(g_kv_path, std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }

    for (const auto& [k, v] : kv) {
        // 使用 '\t' 作为分隔符，避免与base64中的 '=' 冲突
        out << k << "\t" << bytes_to_hex(v) << "\n";
    }
    return true;
}

bool init()
{
    if (g_initialized) {
        return true;
    }

    g_usb_path = resolve_usb_path();
    if (g_usb_path.empty() || !fs::exists(g_usb_path)) {
        return false;
    }

    if (!fs::exists(g_usb_path / FLAG_FILE)) {
        return false;
    }

    g_kv_path = g_usb_path / KV_FILE;
    g_initialized = true;
    return true;
}

bool put(const std::string& key, const ByteArray& value)
{
    if (!g_initialized) {
        return false;
    }

    auto kv = load_kv();
    kv[key] = value;

    return save_kv(kv);
}

bool get(const std::string& key, ByteArray& value_out)
{
    if (!g_initialized) {
        return false;
    }

    auto kv = load_kv();
    auto it = kv.find(key);
    if (it == kv.end()) {
        return false;
    }

    value_out = it->second;
    return true;
}

bool del(const std::string& key)
{
    if (!g_initialized) {
        return false;
    }

    auto kv = load_kv();
    auto it = kv.find(key);
    if (it == kv.end()) {
        return false;
    }

    kv.erase(it);
    return save_kv(kv);
}

bool clean()
{
    if (!g_initialized) {
        return false;
    }

    std::ofstream out(g_kv_path, std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }

    return true;
}

void close()
{
    g_initialized = false;
}

} // namespace SecureUSB
