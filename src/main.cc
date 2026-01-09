/**
 * @file main.cc
 * @brief PADD Web Server - HTTP API服务器主文件
 *
 * 本文件实现了基于PADD（Proof of Allocable Data Deduplication）协议的HTTP服务器，
 * 提供密钥生成、文件签名、证明生成和验证等API接口。
 *
 * 主要功能：
 * - BLS密钥对生成和管理
 * - VRF（Verifiable Random Function）密钥生成、挑战生成和验证
 * - 文件签名和Merkle树证明生成
 * - 安全的密钥存储（通过SecureUSB）
 *
 * @author PADD Team
 * @date 2025
 */

#include <iostream>
#include <string>
#include <vector>
#include "tools/base64.h"

#include "httplib.h"
#include "secure_usb/secure_usb.h"
#include <nlohmann/json.hpp>

// crypto
#include "crypto/padd.h"
#include "crypto/file_utils.hpp"
#include "crypto/vrf.h"
#include <filesystem>

using namespace httplib;

/* ============================================================
 * 工具函数：JSON错误响应
 * ============================================================ */

/**
 * @brief 返回JSON格式的错误响应
 * @param res HTTP响应对象
 * @param status HTTP状态码
 * @param msg 错误消息
 */
static void json_error(Response& res, int status, const std::string& msg) {
    res.status = status;
    res.set_header("Content-Type", "application/json");
    res.body = R"({"error": ")" + msg + R"("})";
}

/* ============================================================
 * 主函数
 * ============================================================ */

int main() {
    /* ---------- 初始化 PBC pairing ---------- */
    pairing_init_set_buf(PAIRING, TYPEA_PARAMS, sizeof(TYPEA_PARAMS));

    /* ---------- 初始化 secure_usb ---------- */
    if (!SecureUSB::init()) {
        std::cerr << "secure_usb init failed\n";
        return 1;
    }

    Server svr;

    /* ============================================================
     * POST /api/v1/keygen
     *
     * 生成BLS密钥对
     *
     * 请求体：空
     * 响应体：
     * {
     *   "key_id": "base64编码的公钥",
     *   "public_key": "base64编码的公钥",
     *   "g": "base64编码的生成元g"
     * }
     * ============================================================ */
    svr.Post("/api/v1/keygen", [](const Request& req, Response& res) {
        bls_pkc* pkc = nullptr;

        try {
            /* 1. 生成 BLS key pair */
            pkc = key_gen();
            if (!pkc) {
                json_error(res, 500, "key_gen failed");
                return;
            }

            /* 2. 序列化私钥，存入 secure_usb (key_id = public_key(base64)) */
            auto sk_buf = bls_sk_serialize(pkc->sk);
            auto pk_buf = bls_keyid_serialize(pkc->pk, pkc->g);

            std::string key_id = base64_encode(std::string(
                reinterpret_cast<const char*>(pk_buf.data()), pk_buf.size()
            ));

            // 转换 std::byte -> uint8_t
            SecureUSB::ByteArray sk_bytes;
            sk_bytes.reserve(sk_buf.size());
            for (auto b : sk_buf) {
                sk_bytes.push_back(static_cast<uint8_t>(b));
            }

            if (!SecureUSB::put(key_id, sk_bytes)) {
                free_pkc(pkc);
                json_error(res, 500, "secure_usb_put failed");
                return;
            }

            /* 3. 序列化 pk 和 g */
            
            u_char* g_buf = (u_char*)malloc(element_length_in_bytes(pkc->g));
            int g_len = element_to_bytes(g_buf, pkc->g);
            std::string g_base64 = base64_encode(std::string(
                reinterpret_cast<char*>(g_buf), g_len
            ));
            free(g_buf);

            free_pkc(pkc);

            /* 4. 返回 public info */
            res.set_header("Content-Type", "application/json");
            res.body = "{"
                "\"key_id\":\"" + key_id + "\""
            "}";

        } catch (const std::exception& e) {
            if (pkc) free_pkc(pkc);
            json_error(res, 500, std::string("internal error: ") + e.what());
        } catch (...) {
            if (pkc) free_pkc(pkc);
            json_error(res, 500, "unknown internal error");
        }
    });

    /* ============================================================
     * POST /api/v1/vrfkeygen
     *
     * 生成VRF密钥对，存储私钥到secure_usb，返回公钥
     *
     * 请求体：空
     * 响应体：
     * {
     *   "key_id": "base64编码的公钥(g||pk)"
     * }
     * ============================================================ */
    svr.Post("/api/v1/vrfkeygen", [](const Request& req, Response& res) {
        element_t* sk = nullptr;
        element_t* g = nullptr;
        element_t* pk = nullptr;

        try {
            /* 1. 生成 VRF key pair */
            auto [sk_ptr, pk_pair] = gen();
            sk = sk_ptr;
            g = pk_pair.first;
            pk = pk_pair.second;

            if (!sk || !g || !pk) {
                if (sk) { element_clear(*sk); free(sk); }
                if (g) { element_clear(*g); free(g); }
                if (pk) { element_clear(*pk); free(pk); }
                json_error(res, 500, "vrf gen failed");
                return;
            }

            /* 2. 序列化公钥 (g || pk) 作为 key_id */
            int g_len = element_length_in_bytes(*g);
            int pk_len = element_length_in_bytes(*pk);

            std::vector<unsigned char> pk_buf(g_len + pk_len);
            element_to_bytes(pk_buf.data(), *g);
            element_to_bytes(pk_buf.data() + g_len, *pk);

            std::string key_id = base64_encode(std::string(
                reinterpret_cast<const char*>(pk_buf.data()),
                pk_buf.size()
            ));

            /* 3. 序列化私钥作为 value */
            int sk_len = element_length_in_bytes(*sk);
            std::vector<unsigned char> sk_buf(sk_len);
            element_to_bytes(sk_buf.data(), *sk);

            // 转换 unsigned char -> uint8_t
            SecureUSB::ByteArray sk_bytes;
            sk_bytes.reserve(sk_buf.size());
            for (auto b : sk_buf) {
                sk_bytes.push_back(static_cast<uint8_t>(b));
            }

            /* 4. 存入 secure_usb (key_id为key，私钥为value) */
            if (!SecureUSB::put(key_id, sk_bytes)) {
                element_clear(*sk);
                element_clear(*g);
                element_clear(*pk);
                free(sk);
                free(g);
                free(pk);
                json_error(res, 500, "secure_usb put failed");
                return;
            }

            /* 5. 清理资源 */
            element_clear(*sk);
            element_clear(*g);
            element_clear(*pk);
            free(sk);
            free(g);
            free(pk);

            /* 6. 返回公钥 */
            res.set_header("Content-Type", "application/json");
            res.body = "{"
                "\"key_id\":\"" + key_id + "\""
            "}";

        } catch (const std::exception& e) {
            if (sk) { element_clear(*sk); free(sk); }
            if (g) { element_clear(*g); free(g); }
            if (pk) { element_clear(*pk); free(pk); }
            json_error(res, 500, std::string("internal error: ") + e.what());
        } catch (...) {
            if (sk) { element_clear(*sk); free(sk); }
            if (g) { element_clear(*g); free(g); }
            if (pk) { element_clear(*pk); free(pk); }
            json_error(res, 500, "unknown internal error");
        }
    });

    /* ============================================================
     * POST /api/v1/file/siggen
     *
     * 对文件进行签名，生成Merkle树和Phi值
     *
     * 请求体：
     * {
     *   "key_id": "BLS密钥ID",
     *   "file_name": "文件路径",
     *   "shard_size": 512  // 可选
     * }
     *
     * 响应体：
     * {
     *   "signature": {
     *     "t": "t值",
     *     "mht_sig": "MHT签名的base64"
     *   },
     *   "phi": "Phi值的base64",
     *   "file_hash": "文件Merkle树根哈希"
     * }
     * ============================================================ */
    svr.Post("/api/v1/file/siggen", [](const Request& req, Response& res) {
        bls_pkc* pkc = nullptr;
        u_char* serialized_mht_sig = nullptr;
        u_char* serialized_phi = nullptr;
        std::vector<element_t*> phi;
        element_t* mht_sig = nullptr;

        auto cleanup = [&]() {
            if (!phi.empty()) free_phi(phi);
            if (mht_sig) free_element_ptr(mht_sig);
            if (pkc) {
                if (pkc->pk) free(pkc->pk);
                if (pkc->sk) free(pkc->sk);
                free(pkc);
            }
            if (serialized_mht_sig) free(serialized_mht_sig);
            if (serialized_phi) free(serialized_phi);
        };

        try {
            auto body = nlohmann::json::parse(req.body);

            std::string key_id = body["key_id"];
            std::string file_name = body["file_name"];
            size_t shard_size = 512;

            if (body.contains("shard_size")) {
                shard_size = body["shard_size"];
            }

            /* 1. 从 secure_usb 取私钥 */
            SecureUSB::ByteArray sk_bytes;
            if (!SecureUSB::get(key_id, sk_bytes)) {
                cleanup();
                json_error(res, 404, "key not found");
                return;
            }

            // 转换 uint8_t -> std::byte
            std::vector<std::byte> sk_buf;
            sk_buf.reserve(sk_bytes.size());
            for (auto b : sk_bytes) {
                sk_buf.push_back(static_cast<std::byte>(b));
            }

            /* 2. 反序列化公私钥 */
            pkc = (bls_pkc*)malloc(sizeof(bls_pkc));
            pkc->pk = (bls_pk*)malloc(sizeof(bls_pk));
            pkc->sk = (bls_sk*)malloc(sizeof(bls_sk));
            if (!bls_sk_deserialize(pkc->sk, sk_buf)) {
                cleanup();
                json_error(res, 500, "sk deserialize failed");
                return;
            }

            std::string decoded = base64_decode(key_id);
            std::vector<std::byte> pk_buf(
                reinterpret_cast<const std::byte*>(decoded.data()),
                reinterpret_cast<const std::byte*>(decoded.data() + decoded.size())
            );
            if (!bls_keyid_deserialize(pkc->pk, pkc->g, pk_buf)) {
                cleanup();
                json_error(res, 500, "pk deserialize failed");
                return;
            }

            /* 3. 打开文件 */
            std::fstream f(file_name, std::ios::binary | std::ios::in);
            if (!f.is_open()) {
                cleanup();
                json_error(res, 404, "file not found");
                return;
            }

            /* 4. 构建 Merkle Tree */
            MerkleTree tree;
            tree.build_from_file(f, shard_size);

            /* 5. 签名 */
            auto [pair_result, phi_vec] = sig_gen(
                *pkc,
                std::filesystem::absolute(file_name).string(),
                f,
                tree,
                shard_size
            );
            phi = phi_vec;

            auto [t, mht_sig_ptr] = pair_result;
            mht_sig = mht_sig_ptr;

            /* 6. 序列化mht_sig和phi */
            serialized_mht_sig = (u_char*)malloc(element_length_in_bytes(*mht_sig));
            int serialized_mht_sig_len = element_to_bytes(serialized_mht_sig, *mht_sig);

            serialized_phi = (u_char*)malloc(elements_length_in_bytes(phi));
            int serialized_phi_len = elements_to_bytes(serialized_phi, phi);

            /* 7. 返回结果 */
            res.set_header("Content-Type", "application/json");
            res.body = "{"
                "\"signature\":{"
                    "\"t\":\"" + t + "\","
                    "\"mht_sig\":\"" +
                    base64_encode(std::string(
                        reinterpret_cast<char*>(serialized_mht_sig),
                        serialized_mht_sig_len
                    )) + "\""
                "},"
                "\"phi\":\"" + base64_encode(std::string(
                    reinterpret_cast<char*>(serialized_phi),
                    serialized_phi_len
                )) + "\","
                "\"file_hash\":\"" + tree.get_root_hash() + "\""
            "}";

            cleanup();

        } catch (const std::exception& e) {
            cleanup();
            json_error(res, 400, e.what());
        } catch (...) {
            cleanup();
            json_error(res, 500, "unknown internal error");
        }
    });

    /* ============================================================
     * POST /api/v1/file/genproof
     *
     * 生成文件证明
     *
     * 请求体：
     * {
     *   "key_id": "BLS密钥ID",
     *   "file_name": "文件路径",
     *   "t": "t值字符串",
     *   "chal": "挑战的base64",
     *   "mht_sig": "MHT签名的base64",
     *   "shard_size": 512  // 可选
     * }
     *
     * 响应体：
     * {
     *   "proof": "证明的base64"
     * }
     * ============================================================ */
    svr.Post("/api/v1/file/genproof", [](const Request& req, Response& res) {
        bls_pkc* pkc = nullptr;
        element_t* u = nullptr;
        std::vector<element_t*> phi;
        std::vector<std::pair<size_t, element_t*>> chal;
        element_t* mht_sig = nullptr;
        Proof* proof = nullptr;

        auto cleanup = [&]() {
            if (!phi.empty()) free_phi(phi);
            if (!chal.empty()) free_chal(chal);
            if (mht_sig) free_element_ptr(mht_sig);
            if (pkc) {
                if (pkc->pk) free(pkc->pk);
                if (pkc->sk) free(pkc->sk);
                free(pkc);
            }
            if (u) { element_clear(*u); free(u); }
            if (proof) delete proof;
        };

        try {
            auto body = nlohmann::json::parse(req.body);

            std::string key_id = body["key_id"];
            std::string file_name = body["file_name"];
            std::string chal_b64 = body["chal"];
            std::string mht_sig_b64 = body["mht_sig"];
            size_t shard_size = 512;

            if (body.contains("shard_size")) {
                shard_size = body["shard_size"];
            }

            /* 1. 从 secure_usb 取私钥 */
            SecureUSB::ByteArray sk_bytes;
            if (!SecureUSB::get(key_id, sk_bytes)) {
                cleanup();
                json_error(res, 404, "key not found");
                return;
            }

            // 转换 uint8_t -> std::byte
            std::vector<std::byte> sk_buf;
            sk_buf.reserve(sk_bytes.size());
            for (auto b : sk_bytes) {
                sk_buf.push_back(static_cast<std::byte>(b));
            }

            /* 2. 反序列化公私钥 */
            pkc = (bls_pkc*)malloc(sizeof(bls_pkc));
            pkc->pk = (bls_pk*)malloc(sizeof(bls_pk));
            pkc->sk = (bls_sk*)malloc(sizeof(bls_sk));
            if (!bls_sk_deserialize(pkc->sk, sk_buf)) {
                cleanup();
                json_error(res, 500, "sk deserialize failed");
                return;
            }

            std::string decoded = base64_decode(key_id);
            std::vector<std::byte> pk_buf(
                reinterpret_cast<const std::byte*>(decoded.data()),
                reinterpret_cast<const std::byte*>(decoded.data() + decoded.size())
            );
            if (!bls_keyid_deserialize(pkc->pk, pkc->g, pk_buf)) {
                cleanup();
                json_error(res, 500, "pk deserialize failed");
                return;
            }

            /* 3. 反序列化 t 值得到 u (需要u来计算phi) */
            std::string t = body["t"];
            auto [flag, u_ptr] = deserialize_t(t, pkc->g, pkc->pk->spk);
            u = u_ptr;
            if (!flag) {
                cleanup();
                json_error(res, 500, "t deserialize failed");
                return;
            }

            /* 4. 打开文件，用于后续计算phi和生成证明 */
            std::fstream f(file_name, std::ios::binary | std::ios::in);
            if (!f.is_open()) {
                cleanup();
                json_error(res, 404, "file not found");
                return;
            }

            /* 5. 构建 Merkle Tree */
            MerkleTree tree;
            tree.build_from_file(f, shard_size);

            /* 6. 从文件重新计算phi */
            f.clear();
            f.seekg(0, std::ios::beg);
            phi = calculate_phi(f, *pkc, *u, shard_size);

            /* 7. 反序列化 chal */
            std::string chal_str = base64_decode(chal_b64);
            std::vector<std::byte> chal_buf(
                reinterpret_cast<const std::byte*>(chal_str.data()),
                reinterpret_cast<const std::byte*>(chal_str.data() + chal_str.size())
            );
            chal = chal_deserialize(chal_buf);

            /* 5. 反序列化 mht_sig */
            std::string mht_sig_str = base64_decode(mht_sig_b64);
            std::vector<std::byte> mht_sig_buf(
                reinterpret_cast<const std::byte*>(mht_sig_str.data()),
                reinterpret_cast<const std::byte*>(mht_sig_str.data() + mht_sig_str.size())
            );
            mht_sig = (element_t*)malloc(sizeof(element_t));
            element_init(*mht_sig, pkc->pk->spk->field);

            int mht_sig_len = element_length_in_bytes(*mht_sig);
            std::vector<unsigned char> mht_sig_uchar(mht_sig_buf.size());
            for (size_t i = 0; i < mht_sig_buf.size(); i++) {
                mht_sig_uchar[i] = static_cast<unsigned char>(mht_sig_buf[i]);
            }

            int mht_sig_result = element_from_bytes(*mht_sig, mht_sig_uchar.data());
            if (mht_sig_result != mht_sig_len) {
                cleanup();
                json_error(res, 500, "mht_sig deserialize failed");
                return;
            }

            /* 8. 生成证明 */
            proof = new Proof(gen_proof(f, phi, chal, mht_sig, tree, shard_size));

            /* 9. 序列化证明 */
            std::vector<std::byte> serialized_proof = proof->Proof_serialize();

            // 转换 std::byte -> uint8_t
            SecureUSB::ByteArray proof_bytes;
            proof_bytes.reserve(serialized_proof.size());
            for (auto b : serialized_proof) {
                proof_bytes.push_back(static_cast<uint8_t>(b));
            }

            /* 10. 返回结果 */
            res.set_header("Content-Type", "application/json");
            res.body = "{"
                "\"proof\":\"" + base64_encode(std::string(
                    reinterpret_cast<const char*>(proof_bytes.data()),
                    proof_bytes.size()
                )) + "\""
            "}";

            cleanup();

        } catch (const std::exception& e) {
            cleanup();
            json_error(res, 400, e.what());
        } catch (...) {
            cleanup();
            json_error(res, 500, "unknown internal error");
        }
    });

    /* ============================================================
     * POST /api/v1/vrfchalgen
     *
     * 使用VRF生成挑战
     *
     * 请求体：
     * {
     *   "vrfseed": "VRF种子字符串",
     *   "key_id": "VRF密钥ID",
     *   "n": 随机索引范围参数,
     *   "m": 随机索引数量参数
     * }
     *
     * 响应体：
     * {
     *   "y": "VRF输出的base64",
     *   "pi": "VRF证明的base64",
     *   "chal": "挑战的base64"
     * }
     * ============================================================ */
    svr.Post("/api/v1/vrfchalgen", [](const Request& req, Response& res) {
        element_t* sk = nullptr;
        element_t* g = nullptr;
        element_t* pk = nullptr;
        element_t* y = nullptr;
        element_t* pi = nullptr;
        std::vector<std::pair<size_t, element_t*>> chal;

        auto cleanup = [&]() {
            if (sk) { element_clear(*sk); free(sk); }
            if (g) { element_clear(*g); free(g); }
            if (pk) { element_clear(*pk); free(pk); }
            if (y) { element_clear(*y); free(y); }
            if (pi) { element_clear(*pi); free(pi); }
            if (!chal.empty()) free_chal(chal);
        };

        try {
            auto body = nlohmann::json::parse(req.body);

            std::string vrfseed = body["vrfseed"];
            std::string key_id = body["key_id"];
            size_t n = body["n"];
            size_t m = body["m"];

            /* 1. 从 secure_usb 取私钥 (使用 key_id 作为 key) */
            SecureUSB::ByteArray sk_bytes;
            if (!SecureUSB::get(key_id, sk_bytes)) {
                cleanup();
                json_error(res, 404, "key not found");
                return;
            }

            /* 2. 反序列化私钥 sk */
            sk = (element_t*)malloc(sizeof(element_t));
            element_init_Zr(*sk, PAIRING);

            int expected_sk_len = element_length_in_bytes(*sk);
            std::vector<unsigned char> sk_buf(sk_bytes.begin(), sk_bytes.end());

            if (sk_bytes.size() != static_cast<size_t>(expected_sk_len)) {
                cleanup();
                json_error(res, 500, "sk deserialize failed: length mismatch");
                return;
            }

            int result = element_from_bytes(*sk, sk_buf.data());
            if (result != expected_sk_len) {
                cleanup();
                json_error(res, 500, "sk deserialize failed");
                return;
            }

            /* 3. 反序列化公钥 (key_id 解码后得到 g || pk) */
            g = (element_t*)malloc(sizeof(element_t));
            element_init_G1(*g, PAIRING);
            int g_len = element_length_in_bytes(*g);

            std::string decoded = base64_decode(key_id);
            size_t total_len = decoded.size();

            if (total_len < 2 * static_cast<size_t>(g_len)) {
                cleanup();
                json_error(res, 500, "invalid key_id format");
                return;
            }

            pk = (element_t*)malloc(sizeof(element_t));
            element_init_G1(*pk, PAIRING);
            int pk_len = element_length_in_bytes(*pk);

            int g_result = element_from_bytes(*g, reinterpret_cast<unsigned char*>(decoded.data()));
            if (g_result != g_len) {
                cleanup();
                json_error(res, 500, "g deserialize failed");
                return;
            }

            int pk_result = element_from_bytes(*pk, reinterpret_cast<unsigned char*>(decoded.data() + g_len));
            if (pk_result != pk_len) {
                cleanup();
                json_error(res, 500, "pk deserialize failed");
                return;
            }

            /* 4. 调用 prove_sk 生成 y 和 pi */
            auto [y_ptr, pi_ptr] = prove_sk(vrfseed, sk, g);
            y = y_ptr;
            pi = pi_ptr;

            if (!y || !pi) {
                cleanup();
                json_error(res, 500, "prove_sk failed");
                return;
            }

            /* 5. 序列化 y 和 pi */
            std::string serialized_vrf_pair = serialize_vrf_pair(std::make_pair(y, pi));

            /* 6. 利用 random_from_vrf 生成 random_indices */
            std::vector<size_t> random_indices = random_from_vrf(serialized_vrf_pair, n, m);

            /* 7. 调用 gen_chal_from_indices 生成 chal */
            chal = gen_chal_from_indices(random_indices);

            /* 8. 序列化 chal */
            std::vector<std::byte> chal_buf = chal_serialize(chal);

            /* 9. 序列化 y 和 pi 为 base64 */
            int y_len = element_length_in_bytes(*y);
            int pi_len = element_length_in_bytes(*pi);

            std::vector<unsigned char> y_bytes(y_len);
            std::vector<unsigned char> pi_bytes(pi_len);

            element_to_bytes(y_bytes.data(), *y);
            element_to_bytes(pi_bytes.data(), *pi);

            std::string y_base64 = base64_encode(std::string(
                reinterpret_cast<const char*>(y_bytes.data()),
                y_bytes.size()
            ));
            std::string pi_base64 = base64_encode(std::string(
                reinterpret_cast<const char*>(pi_bytes.data()),
                pi_bytes.size()
            ));

            /* 10. 返回结果 */
            res.set_header("Content-Type", "application/json");
            res.body = "{"
                "\"y\":\"" + y_base64 + "\","
                "\"pi\":\"" + pi_base64 + "\","
                "\"chal\":\"" + base64_encode(std::string(
                    reinterpret_cast<const char*>(chal_buf.data()),
                    chal_buf.size()
                )) + "\""
            "}";

            cleanup();

        } catch (const std::exception& e) {
            cleanup();
            json_error(res, 400, e.what());
        } catch (...) {
            cleanup();
            json_error(res, 500, "unknown internal error");
        }
    });

    /* ============================================================
     * POST /api/v1/vrfverify
     *
     * 验证VRF证明
     *
     * 请求体：
     * {
     *   "vrfseed": "VRF种子字符串",
     *   "y": "VRF输出的base64",
     *   "pi": "VRF证明的base64",
     *   "key_id": "VRF密钥ID"
     * }
     *
     * 响应体：
     * {
     *   "result": 1  // 1表示验证成功，0表示验证失败
     * }
     * ============================================================ */
    svr.Post("/api/v1/vrfverify", [](const Request& req, Response& res) {
        element_t* g = nullptr;
        element_t* pk = nullptr;
        element_t* y = nullptr;
        element_t* pi = nullptr;

        auto cleanup = [&]() {
            if (g) { element_clear(*g); free(g); }
            if (pk) { element_clear(*pk); free(pk); }
            if (y) { element_clear(*y); free(y); }
            if (pi) { element_clear(*pi); free(pi); }
        };

        try {
            auto body = nlohmann::json::parse(req.body);

            std::string vrfseed = body["vrfseed"];
            std::string y_base64 = body["y"];
            std::string pi_base64 = body["pi"];
            std::string key_id = body["key_id"];

            /* 1. 反序列化公钥 (key_id 解码后得到 g || pk) */
            g = (element_t*)malloc(sizeof(element_t));
            element_init_G1(*g, PAIRING);
            int g_len = element_length_in_bytes(*g);

            std::string decoded = base64_decode(key_id);
            size_t total_len = decoded.size();

            if (total_len < 2 * static_cast<size_t>(g_len)) {
                cleanup();
                json_error(res, 500, "invalid key_id format");
                return;
            }

            pk = (element_t*)malloc(sizeof(element_t));
            element_init_G1(*pk, PAIRING);
            int pk_len = element_length_in_bytes(*pk);

            int g_result = element_from_bytes(*g, reinterpret_cast<unsigned char*>(decoded.data()));
            if (g_result != g_len) {
                cleanup();
                json_error(res, 500, "g deserialize failed");
                return;
            }

            int pk_result = element_from_bytes(*pk, reinterpret_cast<unsigned char*>(decoded.data() + g_len));
            if (pk_result != pk_len) {
                cleanup();
                json_error(res, 500, "pk deserialize failed");
                return;
            }

            /* 2. 反序列化 y */
            std::string y_str = base64_decode(y_base64);
            y = (element_t*)malloc(sizeof(element_t));
            element_init_GT(*y, PAIRING);

            std::vector<unsigned char> y_uchar(y_str.size());
            for (size_t i = 0; i < y_str.size(); i++) {
                y_uchar[i] = static_cast<unsigned char>(y_str[i]);
            }
            int y_result = element_from_bytes(*y, y_uchar.data());
            int y_len = element_length_in_bytes(*y);
            if (y_result != y_len) {
                cleanup();
                json_error(res, 500, "y deserialize failed");
                return;
            }

            /* 3. 反序列化 pi */
            std::string pi_str = base64_decode(pi_base64);
            pi = (element_t*)malloc(sizeof(element_t));
            element_init_G1(*pi, PAIRING);

            std::vector<unsigned char> pi_uchar(pi_str.size());
            for (size_t i = 0; i < pi_str.size(); i++) {
                pi_uchar[i] = static_cast<unsigned char>(pi_str[i]);
            }
            int pi_result = element_from_bytes(*pi, pi_uchar.data());
            int pi_len = element_length_in_bytes(*pi);
            if (pi_result != pi_len) {
                cleanup();
                json_error(res, 500, "pi deserialize failed");
                return;
            }

            /* 4. 调用 ver_pk 验证 */
            bool result = ver_pk(vrfseed, y, pi, pk, g);

            /* 5. 返回结果 */
            res.set_header("Content-Type", "application/json");
            res.body = "{"
                "\"result\":" + std::string(result ? "1" : "0") +
            "}";

            cleanup();

        } catch (const std::exception& e) {
            cleanup();
            json_error(res, 400, e.what());
        } catch (...) {
            cleanup();
            json_error(res, 500, "unknown internal error");
        }
    });

    /* ============================================================
     * POST /api/v1/file/verify
     *
     * 验证PADD证明
     *
     * 请求体：
     * {
     *   "key_id": "BLS密钥ID的base64编码 (g||v||spk)",
     *   "t": "t值字符串",
     *   "chal": "挑战的base64编码",
     *   "proof": "证明的base64编码"
     * }
     *
     * 响应体：
     * {
     *   "result": 1  // 1表示验证成功，0表示验证失败
     * }
     * ============================================================ */
    svr.Post("/api/v1/file/verify", [](const Request& req, Response& res) {
        bls_pkc* pkc = nullptr;
        element_t* u = nullptr;
        std::vector<std::pair<size_t, element_t*>> chal;
        Proof* proof = nullptr;

        auto cleanup = [&]() {
            if (pkc) {
                if (pkc->pk) {
                    element_clear(pkc->pk->v);
                    element_clear(pkc->pk->spk);
                    free(pkc->pk);
                }
                element_clear(pkc->g);
                free(pkc);
            }
            if (u) { element_clear(*u); free(u); }
            if (!chal.empty()) free_chal(chal);
            if (proof) delete proof;
        };

        try {
            auto body = nlohmann::json::parse(req.body);

            std::string key_id = body["key_id"];
            std::string t = body["t"];
            std::string chal_b64 = body["chal"];
            std::string proof_b64 = body["proof"];

            /* 1. 反序列化密钥ID (包含g、v、spk) */
            std::string keyid_str = base64_decode(key_id);
            std::vector<std::byte> keyid_buf(
                reinterpret_cast<const std::byte*>(keyid_str.data()),
                reinterpret_cast<const std::byte*>(keyid_str.data() + keyid_str.size())
            );

            pkc = (bls_pkc*)malloc(sizeof(bls_pkc));
            pkc->pk = (bls_pk*)malloc(sizeof(bls_pk));


            if (!bls_keyid_deserialize(pkc->pk, pkc->g, keyid_buf)) {
                cleanup();
                json_error(res, 500, "key_id deserialize failed");
                return;
            }

            /* 2. 反序列化t值得到u */
            auto [flag, u_ptr] = deserialize_t(t, pkc->g, pkc->pk->spk);
            u = u_ptr;
            if (!flag) {
                cleanup();
                json_error(res, 500, "t deserialize failed");
                return;
            }

            /* 3. 反序列化挑战 */
            std::string chal_str = base64_decode(chal_b64);
            std::vector<std::byte> chal_buf(
                reinterpret_cast<const std::byte*>(chal_str.data()),
                reinterpret_cast<const std::byte*>(chal_str.data() + chal_str.size())
            );
            chal = chal_deserialize(chal_buf);

            /* 4. 反序列化证明 */
            std::string proof_str = base64_decode(proof_b64);
            std::vector<std::byte> proof_buf(
                reinterpret_cast<const std::byte*>(proof_str.data()),
                reinterpret_cast<const std::byte*>(proof_str.data() + proof_str.size())
            );
            proof = new Proof(Proof_deserialize(proof_buf));

            /* 5. 调用verify验证 */
            bool result = verify(*pkc, chal, *proof, *u);

            /* 6. 返回结果 */
            res.set_header("Content-Type", "application/json");
            res.body = "{"
                "\"result\":" + std::string(result ? "1" : "0") +
            "}";

            cleanup();

        } catch (const std::exception& e) {
            cleanup();
            json_error(res, 400, e.what());
        } catch (...) {
            cleanup();
            json_error(res, 500, "unknown internal error");
        }
    });

    /* ============================================================
     * 启动 HTTP 服务
     * ============================================================ */
    std::cout << "HTTP server listening on 0.0.0.0:8080\n";
    svr.listen("0.0.0.0", 8080);

    SecureUSB::close();
    return 0;
}
