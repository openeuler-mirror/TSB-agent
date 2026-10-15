# 简介

virtrust 是面向 openEuler 24.03 LTS SP2/SP3 的可信虚拟机管理项目，提供虚拟化可信计算模块（vTPCM）支持，专注于虚拟机域管理和可信度量功能。本仓库实现了可信虚拟机生命周期管理、安全迁移以及相关工具链。依赖的 TSB-agent 组件目前仅支持 SP2；SP3 的真实依赖与全栈部署须另行验收。

## 项目概述

### 核心功能

- **可信虚拟机管理**：提供虚拟机完整的生命周期管理，包括创建、启动、停止、销毁和迁移操作
- **可信计算支持**：基于国密 SM3 算法的信任链验证，支持 vTPCM（虚拟化可信计算模块）管理
- **安全迁移**：支持虚拟机在不同主机间的安全迁移，具备证书验证和完整性检查
- **开发工具**：提供命令行工具 virtrust-sh和守护进程 libvirtrustd，方便用户操作和系统集成

## 环境要求

### 支持的操作系统

- VIRTRUST：openEuler 24.03 LTS SP2/SP3
- 依赖的 TSB-agent 组件：目前仅支持 SP2；在 SP3 上使用 mock 库测试通过，不能证明真实 TSB-agent 组件可用，正式部署前须使用真实组件完成验证

### 用户权限

命令行工具`virtrust-sh`和守护进程`libvirtrustd`都需以`root`权限运行。

### 编译依赖

```bash
# 基础编译工具
sudo dnf install gcc g++ cmake make

# 开发库
sudo dnf install grpc grpc-devel grpc-plugins protobuf-devel protobuf-compiler
sudo dnf install libboundscheck

# 运行时依赖
sudo dnf install libxml2-devel libguestfs-devel openssl-devel libvirt-devel rapidjson-devel spdlog-devel

# 其他依赖（项目会自动下载）
# - gtest（测试框架）
```

注意：由于 edk2-aarch64 性能问题，建议用户使用 openEuler 24.03 SP2 操作系统时，执行以下操作

```bash
sudo dnf remove edk2-aarch64
wget https://dl-cdn.openeuler.openatom.cn/openEuler-24.03-LTS-SP1/OS/aarch64/Packages/edk2-aarch64-202308-17.oe2403sp1.noarch.rpm
sudo dnf install ./edk2-aarch64-202308-17.oe2403sp1.noarch.rpm
```

## 编译指南

### 使用 CMake 直接编译

```bash
# 创建构建目录
mkdir -p build && cd build

# 配置构建（Release 构建）
cmake ..

# 配置构建（指定构建类型）
cmake -DCMAKE_BUILD_TYPE=Debug ..          # 调试构建
cmake -DCMAKE_BUILD_TYPE=Coverage ..       # 覆盖率构建
cmake -DCMAKE_BUILD_TYPE=Asan ..           # 地址消毒构建

# 配置选项
cmake -DBUILD_TEST=On ..                   # 启用测试（默认开启）

# 编译
cmake --build . -j$(nproc)
```

`make install`/`cmake --install` 不是完整部署步骤：当前 CMake 安装规则不会把 `libvirtrustd` 和 `libvirtrust-shared.so` 安装到服务所需的系统路径。守护进程部署及已有文件的核验要求见[守护进程管理手册](004-virtrustd.md#源码编译安装步骤)。

### 使用构建脚本

```bash
# 默认构建（Release，禁用测试）
./build.sh

# 指定构建目标
./build.sh cicd_default
```

## 单元测试

### 运行所有测试

```bash
cd build

# 运行所有测试
ctest --output-on-failure

# 生成覆盖率报告（需要 Coverage 构建）
make coverage
```

## 产出物

### 库文件

- **`libvirtrust-shared.so`** - 项目共享库，提供核心功能
- **`libinterfac.so`** - 模拟 TSB 代理共享库，仅用于受控测试；生成文件不等于守护进程会自动加载它

### 可执行文件

- **`virtrust-sh`** - 命令行工具，用于管理虚拟机
- **`libvirtrustd`** - 守护进程，提供后台服务

### 测试可执行文件

在 `build/bin/` 目录下生成所有测试程序：

- `domain_test`
- `custom_logger_test`
- `sm3_test`
- `str_utils_test`
- `exception_test`
- 以及其他模块的测试程序

### 配置和运行时文件

- **日志文件**：命令行工具在当前工作目录写入 `virtrust.log`；守护进程使用 `/var/log/virtrustd.log`
- **本地 gRPC 套接字**：固定为 `/run/virtrust/rpc.sock`，客户端和守护进程使用相同端点；不兼容旧 `/tmp/grpc.sock` 配置。生产运行目录要求 root 拥有且权限为 `0700`，本地访问仅面向 root。
- **覆盖率报告**：`build/coverage/index.html`（Coverage 构建）

## 开发指南

### 代码风格

项目使用自动化代码格式化：

```bash
# 格式化所有代码
./format-all.sh
```

- 使用 clang-format 格式化 C++ 代码
- 使用 cmake-format 格式化 CMake 文件
- 配置文件：`.clang-format`

### 开发测试与生产部署

- **开发测试**：

  - 可使用模拟 TSB 代理库；构建该库不代表守护进程默认加载它，实际加载来源取决于 `libinterfac.so` 的库搜索结果
  - 直接使用 CMake 配置时，`BUILD_TEST` 默认开启；`./build.sh` 默认关闭测试
  - 便于开发和调试
  - RPM 中测试库位于 `/opt/test_virtrust_dir/libinterfac.so`。仅在 mock 测试环境中，确认系统库搜索路径内不存在需要保留的真实 `libinterfac.so` 后，才由管理员手动将测试库放到受控的系统库目录（例如 `/usr/lib64`）；不得无条件覆盖同名库。放置后核对实际加载来源及文件、祖先目录的属主和写权限。测试库不能替代真实组件验收，部署约束见[守护进程管理手册](004-virtrustd.md)。
- **生产部署**：

  - 使用真实 TSB 代理
  - 可用 `-DBUILD_TEST=Off` 省略测试目标；这不会选择实际加载的 TSB 库
  - 用于生产环境部署
  - 需要联系[业务管理员](https://gitcode.com/strong-wangzhuang)获取`libinterfac.so`，然后拷贝到库文件搜索路径，例，`/usr/lib64`

### 调试支持

- **Debug 构建**：包含调试信息，支持 gdb
- **Asan 构建**：启用地址消毒，检测内存错误
- **Coverage 构建**：生成代码覆盖率报告
