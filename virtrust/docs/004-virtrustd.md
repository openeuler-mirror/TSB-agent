# Virtrust Daemon (virtrustd) 管理手册

## 概述

Virtrust Daemon (virtrustd) 是 virtrust 项目的守护进程服务，提供基于 gRPC 的远程 API 服务。它作为后端服务运行，接受来自客户端的虚拟机管理请求，并通过 virtrust API 库执行相应的操作。

- **默认服务器地址**：127.0.0.1
- **默认服务器端口**：5031
- **固定 Unix Socket**：`/run/virtrust/rpc.sock`（不接受自定义路径）
- **默认日志文件**：/var/log/virtrustd.log

## 系统架构

### 服务组件

```
virtrustd 守护进程
├── gRPC Server          # gRPC 服务器
├── LinkConfig          # 链接配置管理
├── 信号处理器          # SIGINT, SIGTERM, SIGPIPE 处理
├── 日志系统            # 服务日志记录
└── virtrust API        # 虚拟机管理 API 调用
```

### 通信流程

```
客户端应用
    ↓ (gRPC/TLS)
virtrustd 守护进程
    ↓ (virtrust API)
libvirt 虚拟化层
```

## 安装和部署

### 系统要求

- **操作系统**：VIRTRUST 支持 openEuler 24.03 LTS SP2/SP3；依赖的 TSB-agent 组件目前仅支持 SP2。在 SP3 上使用 mock 库测试通过，不能证明真实 TSB-agent 组件可用，正式部署前须使用真实组件完成验证
- **权限**：生产守护进程及本地客户端以 root 运行；不要将服务运行用户替换为普通用户
- **依赖**：libvirt、gRPC 相关库

root-only 是本项目的部署约束，不是 libvirt 对所有客户端的通用限制；libvirt 的用户会话和系统级连接具有不同的认证授权策略。本节描述支持范围，不表示所有平台的真实依赖、部署和通信验收均已完成。

### 源码编译安装步骤

1. **编译并手动部署守护进程**：

```bash
# 在 virtrust 项目目录下
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

未指定 `CMAKE_INSTALL_PREFIX` 时，项目将构建目录作为默认前缀，程序和库分别输出到其 `bin`、库目录下。当前 `libvirtrustd` 和 `libvirtrust-shared.so` 没有对应的 CMake 安装规则，执行 `cmake --install build` 不会将它们安装到系统目录；服务脚本则固定使用 `/usr/bin/libvirtrustd` 和 `/usr/lib64/libvirtrust-shared.so`，需要管理员手动部署。

先核对 `build/CMakeCache.txt` 中的 `CMAKE_INSTALL_PREFIX`、`CMAKE_INSTALL_BINDIR` 和 `CMAKE_INSTALL_LIBDIR`，以及实际生成的文件。下面以默认前缀为 `build`、库目录为 `lib64` 为例；若使用了其他构建目录或输出位置，请相应调整源路径。不要仅为安装而将前缀改成 `/usr`，当前项目还会把该前缀用于构建输出。

确认目标文件及父目录可信后执行以下手动安装命令。已有部署须先确认无在途业务、停止服务并备份待替换文件；由 RPM 管理的文件应通过 RPM 更新，避免手动替换后与包版本不一致。

```bash
# 在 virtrust 项目目录下，将本次构建的程序和共享库部署到服务脚本要求的位置
sudo install -o root -g root -m 0550 build/bin/libvirtrustd /usr/bin/libvirtrustd
sudo install -o root -g root -m 0550 build/lib64/libvirtrust-shared.so /usr/lib64/libvirtrust-shared.so
sudo ldconfig
```

上述步骤部署守护进程及其项目共享库。启动前还须完成下文的配置文件、证书、可信组件库及服务单元准备；`libinterfac.so` 的测试/生产来源和手动放置要求见后文。

2. **创建配置文件**：

先检查 `/etc/virtrust` 及目标配置的类型、属主和权限。已有配置应先备份并人工核对，不用示例覆盖；目标是符号链接（包括悬空链接）或状态无法确认时，停止安装并排查。

仅在确认首次安装、目标不存在且父目录不受低权限用户控制后，才复制 `test/data/config.json` 到 `/etc/virtrust/config.json`，并核验目录为 `root:root 0750`、配置为 `root:root 0640`。此处不提供“检查失败即复制”的自动命令，也不保证抵御并发路径替换。

3. **创建日志目录**：

确认 `/var/log` 是可信系统目录，已有 `/var/log/virtrustd.log` 不是符号链接或低权限用户控制的对象。日志文件由日志组件打开或创建，打开回调设置权限为 `0600`；已有文件仍需核验属主为 root，`chmod` 不会改变属主。不要用手工 `touch/chmod` 掩盖来源不明的已有文件。

4. **安装并按需使能 libvirtrustd 服务单元**：

以下为未使用 RPM 的源码部署示例，不应整段无条件执行。脚本和 RPM 使用同一份 [service 模板](../src/libvirtrustd/libvirtrustd.service)，都将单元安装到 `/usr/lib/systemd/system/libvirtrustd.service`，权限为 `0644`；单个节点不能混用两种单元管理方式。脚本会查询 RPM 数据库：`TSB-agent` 已安装、目标路径归任何 RPM 包所有，或所有权无法确认时，安装和卸载均在停止服务前报错。即使单元文件已丢失，RPM 文件清单中的所有权仍需遵守。脚本只更新或删除带有脚本来源标记的单元；未知来源的文件由管理员核验。执行有状态操作前还会查询 systemd 当前生效的主单元路径；查询失败或被 `/run` 等其他目录的同名单元覆盖时，拒绝自动安装或卸载。

`install` 不是只读检查：先在目标同目录准备来源标记和完整模板并设置权限，目标已有脚本单元时再尝试停止服务，成功后通过重命名替换单元，随后执行 `daemon-reload`。目标为符号链接或其他非普通文件时拒绝安装。准备或停止失败时保留原单元，并清理暂存文件；停止失败不代表停止动作没有产生影响，仍须核对实际服务状态。替换成功但 `daemon-reload` 失败时，文件已经更新，脚本明确报错，不自动回滚或启动服务。文件替换不保证断电持久性，SIGKILL 或断电也可能留下暂存文件。

安装和卸载通过 `daemon-reload` 重载单元定义，不调用 `daemon-reexec` 重新执行 systemd 管理器。已有部署须先确认无在途业务、备份单元并安排维护窗口，不能把重复安装当作无副作用操作。脚本在替换或删除前会再次核验目标及 RPM 所有权，但核验与文件操作不是同一个原子事务，不能与 RPM 安装、升级或其他管理员操作并发运行。以上流程依赖可信的系统单元目录，不替代对目录属主和权限的核验。

`uninstall` 只处理带脚本标记且未被 RPM 管理的 `/usr/lib/systemd/system/libvirtrustd.service`，依次执行停止、禁用开机自启、删除文件和 `daemon-reload`。任一步失败均保留错误信息并返回非零，不继续后续步骤。停止或禁用失败时不删除单元；这些命令失败仍可能已产生部分影响，应核对服务实际状态。文件删除后重载失败会明确报告该阶段，不自动恢复已执行的操作。RPM 安装的服务单元文件只能通过 RPM 更新或卸载；服务的启动、停止和状态查询仍可通过 `systemctl` 操作。

管理脚本的 `logs [n]` 缺省跟踪最近 50 行日志；显式提供时，`n` 只能是一个正十进制整数。非法或多余参数会报错，且不会调用 `journalctl`。

```bash
# libvirtrustd使用systemd管理，管理脚本见 src/libvirtrustd/virtrustd-service.sh

# 用法: virtrustd-service.sh {install|uninstall|start|stop|restart|reload|status|logs|enable|disable|help}
# 示例:
sudo bash src/libvirtrustd/virtrustd-service.sh install   # 安装服务，不自动启用或启动
sudo bash src/libvirtrustd/virtrustd-service.sh enable    # 需要开机自启时显式启用
sudo bash src/libvirtrustd/virtrustd-service.sh start     # 配置及依赖就绪后启动
sudo bash src/libvirtrustd/virtrustd-service.sh status    # 查看状态
sudo bash src/libvirtrustd/virtrustd-service.sh logs 100  # 查看最近100行并跟随日志
```


### RPM 编译安装步骤（libvirtrustd默认通过systemd管理）

1. **构建 RPM 包**

```bash
bash rpm/build_rpm.sh
```

2. **首次安装**

构建脚本将二进制 RPM 输出到 `~/rpmbuild/RPMS`，并在结束时打印产物目录。按实际构建结果选择名称为 `TSB-agent`、架构与目标系统匹配的运行包；不要选用源码包或 `devel` 等子包代替运行包。版本、发行号和架构以实际包信息为准，不照抄固定文件名。

下面的路径必须替换为实际生成的 RPM 路径。先查看包信息，确认名称、版本及架构后，再执行首次安装命令；已有部署的升级应另行安排维护步骤。

```bash
rpm -qip /实际路径/TSB-agent-实际版本.实际架构.rpm
sudo rpm -ivh /实际路径/TSB-agent-实际版本.实际架构.rpm
```

RPM 安装服务单元，并在安装事务后尝试执行 `systemctl daemon-reload`；首次安装不会自动启用开机启动或启动守护进程。完成证书、配置及可信组件库准备后，再按“系统服务管理”章节手动启动，需要开机自启时再执行 `enable`。

启动前需要完成以下证书和配置准备：
```
a、参考 安全配置-TLS证书管理 章节，生成证书

b、参考 配置管理-配置文件格式 章节，将 a 步骤生成的证书路径配置到 config.json 配置文件中
```

安装完成后，可在以下位置找到可执行文件、头文件、库文件和配置文件：

```shell
# 可执行文件
/usr/bin/libvirtrustd
/usr/bin/virtrust-sh

# 头文件目录
/usr/include/virtrust/

# 库文件
/usr/lib64/libvirtrust-shared.so

# 测试验证版TSB库文件（RPM定义的路径；不是生产真实组件验收）
/opt/test_virtrust_dir/libinterfac.so

# 示例配置文件
/etc/virtrust/config.json

# systemd服务文件
/usr/lib/systemd/system/libvirtrustd.service
```

`libinterfac.so` 按库名动态加载，安装到上述目录不等于该目录已进入加载器搜索路径。仅在 mock 测试环境中，先确认系统库搜索路径内不存在需要保留的真实同名库，再由管理员手动将 `/opt/test_virtrust_dir/libinterfac.so` 放到受控的系统库目录（例如 `/usr/lib64`）；不得无条件覆盖已有库。放置后须核对实际加载来源、库文件及所有祖先目录的属主/写权限；不要把低权限用户可写目录加入 root 进程的库搜索路径，也不要用 mock 库替代真实组件验收。

当前服务单元模板虽设置 `TSB_AGENT_SO_MODE=mock`，本仓库代码不读取该变量来选择 mock 或真实库；它不能证明实际加载了哪一个 `libinterfac.so`。生产部署须核验动态加载器选中的库及其来源。外部组件是否自行读取该变量，须单独核查。

3. **卸载**

```shell
rpm -e TSB-agent
```

## 配置管理

### 配置文件格式

配置文件使用 JSON 格式，当前为示例内容，实际使用时需要根据证书的路径适配修改，包含以下字段：

```json
{
    "caPath": "/etc/virtrust/certs/ca-cert.pem",
    "certPath": "/etc/virtrust/certs/server-cert.pem",
    "skPath": "/etc/virtrust/certs/server-key.pem",
    "ip": "127.0.0.1",
    "port": 5031,
    "udsPath": "/run/virtrust/rpc.sock",
    "sourceCleanupMaxAttempts": 3,
    "rpcRetryMaxAttempts": 3,
    "rpcRetryInitialBackoffMs": 100,
    "rpcRetryMaxBackoffMs": 1000
}
```

#### 配置字段说明

- `caPath`：CA 证书文件路径，缺省为 `/etc/virtrust/certs/ca-cert.pem`
- `certPath`：服务器证书文件路径，缺省为 `/etc/virtrust/certs/server-cert.pem`
- `skPath`：服务器私钥文件路径，缺省为 `/etc/virtrust/certs/server-key.pem`
- `ip`：服务器监听地址，默认为 "127.0.0.1"
- `port`：TCP 监听端口，缺省为 `5031`；修改时还须核对对端配置
- `udsPath`：可以省略，或显式填写 `/run/virtrust/rpc.sock`；其他值（包括旧 `/tmp/grpc.sock`、空串及非字符串）使配置加载失败，不会静默替换
- `sourceCleanupMaxAttempts`：迁移目的端确认成功后，源端删除 VRoot 和取消 libvirt 定义各自的最大总尝试次数；缺省为 `3`，显式值只接受整数 `1`–`10`。次数有界不保证单次底层调用有时间上限
- `rpcRetryMaxAttempts`：源端发起的每个节点间迁移 RPC 网络失败最大总尝试次数（含首次）；缺省 `3`，显式值 `1`–`10`。只重试临时 `UNAVAILABLE`，不重发整次迁移；目的端明确返回“原请求仍在处理”时可在同一阶段总期限内继续查询，不计入此次数
- `rpcRetryInitialBackoffMs`：首次重试退避毫秒数，缺省 `100`，显式值 `1`–`1000`
- `rpcRetryMaxBackoffMs`：指数退避的毫秒上限，缺省 `1000`，显式值 `1`–`5000` 且不得小于起始值；实际等待有 ±20% 抖动。信令阶段仍共用 5 秒、传输阶段仍共用 20 秒总期限，重试不叠加期限

字段名区分大小写，使用上面的驼峰名称，不使用 `ca_path` 等下划线名称。缺省证书路径是绝对路径；需要启用 TLS 时，三份证书文件仍须实际存在且可读，也可以显式配置其他可读的绝对路径。仅省略证书字段不会关闭 TLS。

TCP 的三个证书路径全部非空时启用双向 TLS，读取失败或凭据无效不会回退为明文；部分为空时拒绝启动。当前实现允许三个路径全部显式设为空字符串时使用非 TLS TCP，该模式不提供证书认证或传输加密，不应当作安全部署方式。UDS 始终是本地非 TLS 通道，依靠文件系统权限限制访问。

### 运行目录和实例资格

守护进程在任何 Socket 清理或监听前获取 `/run/virtrust` 下的实例锁。缺失目录由实例资格流程创建；已有目录须由 root 拥有且权限严格为 `0700`，不符合时拒绝启动，不自动修复权限。客户端使用同一固定 UDS 路径，不读取此配置来选择其他端点。

启动及本层 Socket 清理前还会检查父目录链的属主、写权限和符号链接约束。不要通过放宽目录权限开放普通用户访问，也不要在服务运行时删除或替换实例锁文件。实例互斥限于相同锁文件命名空间，不保证独立容器之间的物理节点唯一性；路径检查不保证抵御同权限进程替换，也不约束 gRPC 自身的内部清理。

## 运行和管理

### libvirtrustd运行管理
**启动命令**

```bash
# 基础启动
sudo libvirtrustd --config /etc/virtrust/config.json

# 调试模式启动
sudo libvirtrustd -d --config /etc/virtrust/config.json
```

**命令行选项**

| 选项   | 长选项         | 参数   | 描述         |
| ---- | ----------- | ---- | ---------- |
| `-c` | `--config`  | 文件路径 | 正常启动时必需的配置文件路径 |
| `-d` | `--debug`   | 无    | 启用调试模式     |
| `-h` | `--help`    | 无    | 显示帮助信息     |
| `-v` | `--version` | 无    | 显示版本信息     |

### 系统服务管理

**systemd 服务文件**：
见 [libvirtrustd.service](../src/libvirtrustd/libvirtrustd.service)。服务名为 `libvirtrustd`，不是 `virtrustd`。RPM spec 与非 RPM 管理脚本均以 `/usr/lib/systemd/system/libvirtrustd.service` 为目标，但不能交叉更新或卸载对方管理的文件。可用 `systemctl show -p FragmentPath libvirtrustd` 核对当前生效的主单元路径。

当前程序未实现 SIGHUP 配置热重载，唯一服务单元模板不声明 `ExecReload`；管理脚本的 `reload` 命令明确报错并返回非零，不发送信号或自动重启。修改配置后的受控重启需要先确认无在途业务；自动拉起进程不等于迁移任务能够恢复。`systemctl daemon-reload` 只重新加载 systemd 单元定义，不会让守护进程重新读取业务配置。

已有部署中的 `/etc/systemd/system/libvirtrustd.service`（包括符号链接）优先于 `/usr/lib` 的同名单元，脚本检测到它会拒绝安装或卸载，不会自动删除。其他高优先级目录中的生效同名单元也会被拒绝，但检查与后续操作并非原子事务，不能与其他特权部署并发。管理员须在无在途业务的维护窗口核对 `systemctl cat libvirtrustd` 与 `FragmentPath`，备份旧单元及 drop-in，确认实际管理来源后人工移除旧单元，执行 `systemctl daemon-reload`，再次确认生效路径为 `/usr/lib/systemd/system/libvirtrustd.service`，然后按需启动或启用服务。旧单元或 drop-in 仍可能包含 `ExecReload`，不能仅凭仓库模板判断线上行为。RPM 部署须通过 RPM 更新，不要运行脚本 `install` 覆盖其文件；从脚本部署改为 RPM 前也须先人工清理旧的脚本部署。

**服务管理命令**：

```bash
# 重新加载 systemd 配置
sudo systemctl daemon-reload

# 启动服务
sudo systemctl start libvirtrustd

# 停止服务
sudo systemctl stop libvirtrustd

# 重启服务
sudo systemctl restart libvirtrustd

# 查看服务状态
sudo systemctl status libvirtrustd

# 开机自启
sudo systemctl enable libvirtrustd

# 禁用开机自启
sudo systemctl disable libvirtrustd
```

**服务状态监控**

```bash
# 检查服务是否运行
sudo systemctl is-active libvirtrustd

# 查看服务日志
sudo journalctl -u libvirtrustd -f

# 查看最近的错误日志
sudo journalctl -u libvirtrustd --since "1 hour ago" -p err
```

## 日志管理

### 日志文件位置

- **日志文件**：`/var/log/virtrustd.log`
- **系统日志**：通过 systemd journal 记录

### 日志级别

- **默认级别**：INFO
- **调试模式**：DEBUG（使用 `--debug` 选项启用）

### 日志轮转注意事项

当前日志适配层使用 spdlog 的 rotating file sink 进行文件轮转（见 `src/virtrust/base/log_adapt.cpp`）。

不要使用 `systemctl reload` 作为日志轮转后的文件重开手段，当前守护进程没有对应的 SIGHUP 处理。外部轮转方案应先核对日志实现并单独验证，不能直接套用依赖热重载的 logrotate 配置。

## 安全配置

### TLS 证书管理

以下仅是生成 gRPC 测试证书的示例，不是完整的生产密钥部署方案。示例私钥没有口令保护，不能以“开源规范允许”作为安全依据；生成前须选择可信的私有工作目录，限制访问权限。不要在低权限用户可写的共享目录中以 root 执行。

下面的命令只在私有工作目录生成测试凭据，不自动安装到 `/etc/virtrust/certs`。部署前须核验该目录及祖先目录的类型、属主和权限；已有证书或私钥须先备份并确认更新方案，不得用示例文件无条件覆盖。首次部署由管理员创建 `root:root 0700` 的专用证书目录，并以受控方式安装所需文件；安装后核验私钥为 `root:root 0600`，证书和 CA 信任文件不得被低权限用户修改。CA 私钥应单独保管，不随服务证书分发。以下示例未覆盖完整身份用途、权限验收或全部失败处理，实际部署须按环境补充并验证。

```bash
#!/bin/bash
openssl genrsa -out ca-key.pem 2048

# 创建 CA 证书
openssl req -new -x509 -days 365 -key ca-key.pem -out ca-cert.pem \
  -subj "/C=CN/ST=State/L=City/O=Organization/CN=Virtrust-CA"

# 生成服务器私钥
openssl genrsa -out server-key.pem 2048

# 生成证书签名请求
openssl req -new -key server-key.pem -out server-req.pem \
  -subj "/C=CN/ST=State/L=City/O=Organization/CN=virtrustd-server"

# 签发服务器证书: 以下的ip1,ip2需要替换为服务器的ip列表
openssl x509 -req -days 365 -in server-req.pem -CA ca-cert.pem \
  -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -extfile <(printf "subjectAltName=IP:ip1,IP:ip2,DNS:localhost")

# 生成的文件留在当前私有工作目录，核验后再由管理员安排部署。
```

```
 注意：只按节点身份分发所需证书和对应私钥，不批量复制 CA 私钥或共用同一节点私钥。
```

### libvirt证书

```bash
# 该脚本仅提供证书及私钥生成的示例，不对安全性负责。
# 以下方式生成的私钥文件未使用口令保护，有安全性问题，若需要口令保护请修改脚本。
#!/bin/bash

# 证书生成工具脚本（基于GnuTLS certtool）
# 功能：创建CA、服务器和客户端证书

set -e  # 遇到错误立即退出
set -u  # 使用未定义变量时报错

# 全局配置
CA_ORG="HW"
SERVER_HOST="compute1.libvirt.org"
SERVER_DNS=("compute1" "compute1.libvirt.org")
if [ $# -eq 0 ]; then
    read -p "请输入服务器 IP: " SERVER_IP
    SERVER_IPS=("$SERVER_IP")
else
    SERVER_IPS=("$@")  # 使用所有传入的参数作为 IP 列表
fi
CLIENT_CN="client1"
CLIENT_COUNTRY="CN"
CLIENT_STATE="XIAN"
CLIENT_LOCALITY="XIAN"

# 安装目录（根据需要修改）
CA_CERT_PATH="/etc/pki/CA/cacert.pem"
SERVER_KEY_PATH="/etc/pki/libvirt/private/serverkey.pem"
SERVER_CERT_PATH="/etc/pki/libvirt/servercert.pem"
CLIENT_KEY_PATH="/etc/pki/libvirt/private/clientkey.pem"
CLIENT_CERT_PATH="/etc/pki/libvirt/clientcert.pem"

# 检查certtool是否安装
if ! command -v certtool &> /dev/null; then
    echo "错误：certtool未安装。请安装gnutls-utils包："
    echo "  Fedora/RHEL: sudo dnf install gnutls-utils"
    echo "  Debian/Ubuntu: sudo apt-get install gnutls-bin"
    exit 1
fi

# 创建临时目录
TMP_DIR=./libvirt_tlscerts
mkdir -p "$TMP_DIR"

# 1. 创建CA证书
echo "===== 创建CA证书 ====="
cat > "$TMP_DIR/ca.info" <<EOF
cn = $CA_ORG
ca
cert_signing_key
EOF

certtool --generate-privkey > "$TMP_DIR/cakey.pem"
certtool --generate-self-signed \
    --load-privkey "$TMP_DIR/cakey.pem" \
    --template "$TMP_DIR/ca.info" \
    --outfile "$TMP_DIR/cacert.pem"

echo "CA证书已生成："
certtool -i --infile "$TMP_DIR/cacert.pem" | grep -E "Subject:|Validity:"

# 2. 创建服务器证书
echo -e "\n===== 创建服务器证书 ====="
cat > "$TMP_DIR/server.info" <<EOF
organization = $CA_ORG
cn = $SERVER_HOST
EOF

# 添加DNS名称
for dns in "${SERVER_DNS[@]}"; do
    echo "dns_name = $dns" >> "$TMP_DIR/server.info"
done

# 添加IP地址
for ip in "${SERVER_IPS[@]}"; do
    echo "ip_address = $ip" >> "$TMP_DIR/server.info"
done

# 添加扩展字段
cat >> "$TMP_DIR/server.info" <<EOF
tls_www_server
signing_key
encryption_key
EOF

certtool --generate-privkey > "$TMP_DIR/serverkey.pem"
certtool --generate-certificate \
    --load-privkey "$TMP_DIR/serverkey.pem" \
    --load-ca-certificate "$TMP_DIR/cacert.pem" \
    --load-ca-privkey "$TMP_DIR/cakey.pem" \
    --template "$TMP_DIR/server.info" \
    --outfile "$TMP_DIR/servercert.pem"

echo "服务器证书已生成："
certtool -i --infile "$TMP_DIR/servercert.pem" | grep -E "Subject:|Subject Alternative Name"

# 3. 创建客户端证书
echo -e "\n===== 创建客户端证书 ====="
cat > "$TMP_DIR/client.info" <<EOF
country = $CLIENT_COUNTRY
state = $CLIENT_STATE
locality = $CLIENT_LOCALITY
organization = $CA_ORG
cn = $CLIENT_CN
tls_www_client
signing_key
encryption_key
EOF

certtool --generate-privkey > "$TMP_DIR/clientkey.pem"
certtool --generate-certificate \
    --load-privkey "$TMP_DIR/clientkey.pem" \
    --load-ca-certificate "$TMP_DIR/cacert.pem" \
    --load-ca-privkey "$TMP_DIR/cakey.pem" \
    --template "$TMP_DIR/client.info" \
    --outfile "$TMP_DIR/clientcert.pem"

echo "客户端证书已生成："
certtool -i --infile "$TMP_DIR/clientcert.pem" | grep -E "Subject:"

# 5. 验证证书链（可选）
echo -e "\n验证证书链..."
certtool --verify --infile "$TMP_DIR/servercert.pem" \
    --load-ca-certificate "$TMP_DIR/cacert.pem"

echo -e "\n生成证书完成，位置： $TMP_DIR，需手动将证书复制到客户端和服务端如下位置："
echo "服务端和客户端：CA证书 -> $CA_CERT_PATH"
echo "服务端：服务器私钥 -> $SERVER_KEY_PATH"
echo "服务端：服务器证书 -> $SERVER_CERT_PATH"
echo "客户端：客户端私钥 -> $CLIENT_KEY_PATH"
echo "客户端：客户端证书 -> $CLIENT_CERT_PATH"
```

```
  生成的证书之后，证书应放置的路径如下
服务端和客户端：CA证书 -> /etc/pki/CA/cacert.pem
服务端：服务器私钥 -> /etc/pki/libvirt/private/serverkey.pem
服务端：服务器证书 -> /etc/pki/libvirt/servercert.pem
客户端：客户端私钥 -> /etc/pki/libvirt/private/clientkey.pem
客户端：客户端证书 -> /etc/pki/libvirt/clientcert.pem
```

### 防火墙配置

```bash
# 开放 gRPC 服务端口
sudo firewall-cmd --permanent --add-port=5031/tcp
# 开放 libvirt tls方式端口
sudo firewall-cmd --permanent --add-port=16514/tcp
sudo firewall-cmd --reload
```

### 通信矩阵

以下描述通信通道，不代表完成了真实握手或部署验收。5031 是本服务默认 TCP 端口；16514 是 libvirt TLS 通道的默认端口，实际端口及 TLS 参数以部署配置为准。本地 UDS 不经过 TCP 防火墙规则。

| Source Device | Source IP      | Source Port                         | Destination Device | Destination IP      | Destination Port | Protocol | Is Listening Port Configurable | Authentication | Encryption  |
| ------------- | -------------- | ----------------------------------- | ------------------ | ------------------- | ---------------- | -------- | ------------------------------ | -------------- | ----------- |
| Source Node   | Source host IP | Random port allocated by the system | Destination Node   | Destination host IP | 5031（默认）     | TCP      | Yes（port）                    | 双向证书认证（TLS模式） | TLS（具体版本依赖底层配置） |
| Source Node   | Source host IP | Random port allocated by the system | Destination Node   | Destination host IP | 16514（默认）    | TCP      | Yes（libvirt配置）             | 按libvirt TLS认证配置 | TLS（具体版本依赖底层配置） |
| 本地root客户端 | 本机 | 不适用 | 本地libvirtrustd | 本机 | /run/virtrust/rpc.sock | UDS | No | 文件系统访问权限 | 无TLS |

TCP 第一行描述双向 TLS 模式；若显式将三个证书路径全部置空，当前实现允许非 TLS TCP，此时没有表中的证书认证和加密能力。不要将该模式用于需要安全通信的部署。

