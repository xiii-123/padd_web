#include <iostream>
#include <fstream>
#include <filesystem>
#include <ctime>

namespace fs = std::filesystem;

void createMarkerFile(const std::string& mountPoint) {
    std::string markerPath = mountPoint + "/.security_device_marker";
    std::ofstream file(markerPath);
    
    if (file.is_open()) {
        std::time_t now = std::time(nullptr);
        char timeStr[100];
        std::strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
        
        file << "Security Hardware Device Marker" << std::endl;
        file << "Created: " << timeStr << std::endl;
        file << "Version: 1.0.0" << std::endl;
        file.close();
        
        std::cout << "已在 " << mountPoint << " 创建安全硬件标记文件" << std::endl;
        std::cout << "标记文件路径: " << markerPath << std::endl;
    } else {
        std::cerr << "无法在 " << mountPoint << " 创建标记文件" << std::endl;
        std::cerr << "请检查:" << std::endl;
        std::cerr << "1. U盘是否已挂载" << std::endl;
        std::cerr << "2. 是否有写入权限" << std::endl;
    }
}

int main() {
    std::cout << "=== U盘安全硬件初始化工具 ===" << std::endl;
    std::cout << "注意: 请确保U盘已经挂载" << std::endl << std::endl;
    
    std::string mountPoint;
    std::cout << "请输入U盘挂载点路径 (如 /media/username/USB_DISK): ";
    std::getline(std::cin, mountPoint);
    
    // 检查挂载点是否存在
    if (!fs::exists(mountPoint)) {
        std::cerr << "错误: 指定的路径不存在" << std::endl;
        return 1;
    }
    
    // 检查是否是目录
    if (!fs::is_directory(mountPoint)) {
        std::cerr << "错误: 指定的路径不是目录" << std::endl;
        return 1;
    }
    
    createMarkerFile(mountPoint);
    return 0;
}