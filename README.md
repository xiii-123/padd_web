# PADD Web Server

<div align="center">

![PADD Logo](https://img.shields.io/badge/PADD-Proof%20of%20Allocable%20Data%20Deduplication-blue)
![C++](https://img.shields.io/badge/C++-17-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**A high-performance web server implementing PADD protocol with BLS signatures and VRF**

[Features](#features) • [Quick Start](#quick-start) • [API Documentation](#api-documentation) • [Architecture](#architecture)

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Documentation](#api-documentation)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Security Considerations](#security-considerations)
- [Performance](#performance)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

PADD (Proof of Allocable Data Deduplication) Web Server is a secure, high-performance HTTP server that implements cryptographic proofs for data deduplication. It combines advanced cryptographic primitives including BLS (Boneh-Lynn-Shacham) signatures, VRF (Verifiable Random Functions), and Merkle trees to provide efficient and verifiable data integrity proofs.

## ✨ Features

### Core Cryptographic Primitives
- **BLS Signatures**: Boneh-Lynn-Shacham signature scheme for efficient aggregate signatures
- **VRF**: Verifiable Random Functions for verifiable challenge generation
- **Merkle Trees**: Efficient integrity verification with batch proof support
- **Pairing-Based Cryptography**: Built on PBC library with Type A pairing parameters

### API Endpoints
- 🔑 **Key Management**: Generate and manage BLS key pairs
- 📝 **File Signing**: Sign files with PADD protocol
- 🔐 **Proof Generation**: Generate cryptographic proofs for data integrity
- ✅ **Proof Verification**: Verify PADD proofs efficiently
- 🎲 **VRF Operations**: Generate and verify VRF proofs

### Security Features
- Secure key storage with SecureUSB abstraction
- Base64 encoding for all binary data transmission
- Comprehensive error handling and validation
- Memory-safe resource management with RAII patterns

## 📦 Prerequisites

### System Requirements
- **OS**: Linux (tested on WSL2, Ubuntu 20.04+)
- **Compiler**: GCC 9.0+ or Clang 10.0+ with C++17 support
- **CMake**: Version 3.15 or higher
- **RAM**: 512MB minimum, 2GB recommended

### Dependencies

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    libpbc-dev \
    libgmp-dev \
    libssl-dev \
    nlohmann-json3-dev

# Fedora/RHEL
sudo dnf install -y \
    gcc-c++ \
    cmake \
    pbc-devel \
    gmp-devel \
    openssl-devel \
    json-devel
```

### Library Versions
- **PBC Library**: 0.5.14+
- **OpenSSL**: 1.1.1+
- **nlohmann/json**: 3.9.0+
- **HTTP Server**: CPP-HTTPLIB (bundled)

## 🚀 Installation

### Clone the Repository

```bash
git clone https://github.com/yourusername/padd_web.git
cd padd_web
```

### Build from Source

```bash
# Create build directory
mkdir build && cd build

# Configure with CMake
cmake ..

# Build (uses 4 threads by default)
make -j$(nproc)

# Optional: Run tests
make test

# Optional: Install system-wide
sudo make install
```

### Build Options

```bash
# Debug build
cmake -DCMAKE_BUILD_TYPE=Debug ..

# Release build with optimizations
cmake -DCMAKE_BUILD_TYPE=Release ..

# Custom install prefix
cmake -DCMAKE_INSTALL_PREFIX=/opt/padd ..
```

## ⚡ Quick Start

### 1. Start the Server

```bash
cd build
./bin/crypto_httpd
```

The server will start listening on `0.0.0.0:8080`.

### 2. Generate Keys

```bash
curl -X POST http://localhost:8080/api/v1/keygen \
  -H "Content-Type: application/json" \
  -d '{}'
```

Response:
```json
{
  "key_id": "gAR7iN...base64...",
  "pk": "vXYZ9...base64...",
  "g": "hK2mN...base64..."
}
```

### 3. Sign a File

```bash
curl -X POST http://localhost:8080/api/v1/file/siggen \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "gAR7iN...base64...",
    "file_name": "/path/to/your/file",
    "shard_size": 512
  }'
```

### 4. Generate Proof

```bash
curl -X POST http://localhost:8080/api/v1/file/genproof \
  -H "Content-Type: application/json" \
  -d '{
    "key_id": "gAR7iN...base64...",
    "file_name": "/path/to/your/file",
    "t": "t_value_string",
    "chal": "challenge_base64",
    "mht_sig": "mht_signature_base64",
    "shard_size": 512
  }'
```

### 5. Verify Proof

```bash
curl -X POST http://localhost:8080/api/v1/file/verify \
  -H "Content-Type: application/json" \
  - d '{
    "key_id": "gAR7iN...base64...",
    "t": "t_value_string",
    "chal": "challenge_base64",
    "proof": "proof_base64"
  }'
```

## 📚 API Documentation

### Key Management

#### `POST /api/v1/keygen`
Generate a new BLS key pair.

**Request Body**: Empty JSON `{}`

**Response**:
```json
{
  "key_id": "base64_encoded_key_id",
  "pk": "base64_encoded_public_key",
  "g": "base64_encoded_generator"
}
```

#### `POST /api/v1/vrfkeygen`
Generate a new VRF key pair.

**Request Body**: Empty JSON `{}`

**Response**:
```json
{
  "key_id": "base64_encoded_key_id"
}
```

### File Operations

#### `POST /api/v1/file/siggen`
Sign a file with PADD protocol.

**Request**:
```json
{
  "key_id": "base64_encoded_key_id",
  "file_name": "/path/to/file",
  "shard_size": 512
}
```

**Response**:
```json
{
  "signature": {
    "t": "t_value",
    "mht_sig": "base64_mht_signature"
  },
  "phi": "base64_phi",
  "file_hash": "merkle_root_hash"
}
```

#### `POST /api/v1/file/genproof`
Generate a PADD proof for a file.

**Request**:
```json
{
  "key_id": "base64_encoded_key_id",
  "file_name": "/path/to/file",
  "t": "t_value",
  "chal": "base64_challenge",
  "mht_sig": "base64_mht_signature",
  "shard_size": 512
}
```

**Response**:
```json
{
  "proof": "base64_encoded_proof"
}
```

#### `POST /api/v1/file/verify`
Verify a PADD proof.

**Request**:
```json
{
  "key_id": "base64_encoded_key_id",
  "t": "t_value",
  "chal": "base64_challenge",
  "proof": "base64_proof"
}
```

**Response**:
```json
{
  "result": 1
}
```

### VRF Operations

#### `POST /api/v1/vrfchalgen`
Generate VRF-based challenge.

**Request**:
```json
{
  "vrfseed": "random_seed_string",
  "key_id": "base64_encoded_key_id",
  "n": 1000,
  "m": 10
}
```

**Response**:
```json
{
  "y": "base64_vrf_output",
  "pi": "base64_vrf_proof",
  "chal": "base64_challenge"
}
```

#### `POST /api/v1/vrfverify`
Verify VRF proof.

**Request**:
```json
{
  "vrfseed": "random_seed_string",
  "y": "base64_vrf_output",
  "pi": "base64_vrf_proof",
  "key_id": "base64_encoded_key_id"
}
```

**Response**:
```json
{
  "result": 1
}
```

## 🏗️ Architecture

### Cryptographic Stack

```
┌─────────────────────────────────────────┐
│          HTTP API Layer                 │
│  (RESTful endpoints with JSON)          │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│      PADD Protocol Implementation       │
│  - Key Generation                       │
│  - File Signing                         │
│  - Proof Generation & Verification      │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│     Cryptographic Primitives Layer      │
│  - BLS Signatures (bls_utils)           │
│  - VRF (vrf)                            │
│  - Merkle Trees (merkle_tree)           │
└────────────────┬────────────────────────┘
                 │
┌────────────────▼────────────────────────┐
│       PBC Library (Pairing-Based Crypto)│
│  Type A Pairing Parameters              │
└─────────────────────────────────────────┘
```

### Key Components

- **`src/main.cc`**: HTTP server with all API endpoints
- **`src/crypto/padd_01.cpp`**: Core PADD protocol implementation
- **`src/crypto/vrf.cpp`**: Verifiable Random Function implementation
- **`src/secure_usb/`**: Secure key-value storage abstraction
- **`include/crypto/`**: Header files for all cryptographic modules

## 📁 Project Structure

```
padd_web/
├── build/                 # Build output directory
│   ├── bin/              # Executables
│   └── lib/              # Shared libraries
├── include/
│   └── crypto/           # Public header files
│       ├── padd.h        # PADD protocol interface
│       ├── bls_utils.h   # BLS signature utilities
│       ├── vrf.h         # VRF interface
│       └── file_utils.hpp# File processing utilities
├── src/
│   ├── main.cc           # HTTP server main entry
│   └── crypto/           # Implementation files
│       ├── padd_01.cpp   # PADD protocol
│       ├── vrf.cpp       # VRF implementation
│       └── bls_utils.cpp # BLS utilities
├── src/secure_usb/       # Secure key storage
│   ├── secure_usb.cpp
│   └── secure_usb.hpp
├── tests/                # Unit tests
├── CMakeLists.txt        # Build configuration
├── README.md             # This file
└── .gitignore           # Git ignore rules
```

## 🔒 Security Considerations

- **Key Storage**: Private keys are stored securely using the SecureUSB abstraction layer
- **Memory Safety**: All cryptographic elements are properly initialized and cleared
- **Input Validation**: All inputs are validated before processing
- **Error Handling**: Comprehensive error handling prevents information leakage
- **Base64 Encoding**: All binary data is base64-encoded for safe transmission

## ⚡ Performance

- **Proof Generation**: O(k) where k is the challenge size
- **Proof Verification**: O(k) with efficient pairing operations
- **Concurrent Requests**: Multi-threaded HTTP server using CPP-HTTPLIB
- **Memory Efficiency**: RAII-based resource management prevents memory leaks

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Code Style
- Follow C++17 best practices
- Use clang-format for code formatting
- Add unit tests for new features
- Update documentation as needed

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **PBC Library**: For pairing-based cryptography primitives
- **nlohmann/json**: For excellent JSON library
- **CPP-HTTPLIB**: for the lightweight HTTP server

## 📞 Contact

- Project Home: [https://github.com/yourusername/padd_web](https://github.com/yourusername/padd_web)
- Issues: [https://github.com/yourusername/padd_web/issues](https://github.com/yourusername/padd_web/issues)
- Email: your.email@example.com

---

<div align="center">

**Built with ❤️ using C++17 and PBC Library**

[⬆ Back to Top](#padd-web-server)

</div>
