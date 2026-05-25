# Feature (#58): 第三方 TLS 支持（HTTP / WebSocket / HttpClient）

## 概述

sws 目前仅支持明文 HTTP/WS，`HttpClient` 解析 `https://` URL 即返回 `error.TlsNotSupported`。需要接入第三方 TLS 库，使三个组件均支持加密传输：

| 组件 | 入站/出站 | 协议 | 当前状态 |
|------|----------|------|---------|
| HTTPS Server | 入站 | HTTP/1.1 over TLS | 未实现 |
| WSS Server | 入站 | WebSocket over TLS | 未实现 |
| HttpClient | 出站 | HTTPS (outbound) | `TlsNotSupported` |

## 设计原则

### 1. 无 TLS 证书时不影响现有功能

TLS 必须**可选、可降级**。用户不传证书/密钥时，服务器行为与当前完全一致（纯 HTTP），不出错、不打印 warning。只有显式配置了证书时，才在 accept 之后进入 TLS 握手。

### 2. 非阻塞保证（io_uring 环境的硬约束）

TLS 集成**绝对不能**在 IO 线程或 client ring 线程中阻塞。逐项审计：

| 操作 | 阻塞风险 | 保证方式 |
|------|---------|---------|
| 证书/私钥文件加载 | 磁盘 I/O | 仅在 `init()` 阶段执行（事件循环启动前），使用常规 blocking read，不占 io_uring |
| TLS 握手消息收发 | socket I/O | 全部经 io_uring SQE/CQE 异步驱动，零阻塞 |
| `SSL_do_handshake()` 内部 I/O | TLS 库自身 | 使用 `BIO_s_mem()`（内存 BIO），TLS 库内部所有读写操作只与内存 buffer 交互，永远不碰 socket fd |
| `SSL_read()` / `SSL_write()` 加解密 | CPU only | 内存 BIO 隔离，纯 CPU 计算。RSA 2048 ≈ 1ms，ECDSA ≈ 0.1ms，不会阻塞事件循环 |
| BoringSSL 随机数 | `/dev/urandom` | TLS 库在 `SSL_CTX_new()` 时（init 阶段）完成 RNG 初始化，per-handshake 不触发熵收集 |
| CRL / OCSP 吊销检查 | 网络 I/O | **本次不实现**，列为非目标 |
| SQ ring 满时握手写 SQE 提交 | 后退 | 握手输出 buffer 保留密文，下次事件循环重试（参考 `queuePendingWrite`） |
| TLS 重新协商 | 协议层 | 禁用（`SSL_set_options(SSL_OP_NO_RENEGOTIATION)`） |

### 3. 三层系统约束不变

- **io_uring 层**：TLS 握手/加解密全部在 IO 线程内以非阻塞模式执行。TLS 握手不是单次同步调用，而是**跨 CQE 的异步状态机** — 每次收到 CQE 推进一个阶段，完成后立即提交下一个 SQE。IO 线程不等待、不 poll、不 `submit_and_wait` 握手中途的单个 CQE。
- **Fiber 调度层**：TLS 握手期间 fiber 不参与（握手在 IO 线程 inline 驱动，与当前 TCP read 解析 header 的模式一致）。
- **连接状态机**：新增 `.tls_handshaking` 状态。Accept 后若配置 TLS → `conn.state = .tls_handshaking`。握手成功 → `.reading`（进入 HTTP）。握手失败 → `.closing`。

### 4. TLS 握手异步状态机

TLS 握手跨多轮 CQE，在 `dispatchCqes` 中新增 `.tls_handshaking` 分支。

BoringSSL 通过内存 BIO 驱动：IO 线程从 io_uring CQE 取到的密文 → `BIO_write(in_bio, ciphertext)` → `SSL_do_handshake()` → `BIO_read(out_bio, handshake_output)` → `submitWrite`。一次 `tlsHandshakeAdvance()` 内部是循环：反复调用 `SSL_do_handshake()` 直到返回 `WANT_READ`（需要更多输入）或 `WANT_WRITE`（有输出待发送）或完成。

```
                                     ┌───────────────────────────────┐
TLS accept ──► submitRead ──► CQE ──►│ 密文 → BIO_write(in_bio)      │
                                     │ while SSL_do_handshake():      │
                                     │   WANT_WRITE → BIO_read(out)  │
                                     │   → handshake_out_buf          │
                                     │                                │
                                     │ submitWrite(handshake_out)     │
                                     │ ──► CQE                        │──► ServerHello
                                     │                                │    + Certificate
                                     │ submitRead ──► CQE             │
                                     │ 密文 → BIO_write(in_bio)       │
                                     │ while SSL_do_handshake() → done│
                                     │                                │
                                     │ → .reading                     │──► 握手完成
                                     │ OR → .closing                  │──► 握手失败
                                     └───────────────────────────────┘
```

握手期间的缓冲策略：

- **读缓冲**：复用现有 io_uring provided buffer（`BUFFER_SIZE = 4096`），CQE 返回的 bid 在握手完成后补 `markReplenish`
- **写缓冲**：`TlsStream` 内嵌固定大小 `handshake_out_buf: [16384]u8`。TLS 握手最大消息（Certificate chain < 16KB）。若 SQ ring 满导致 `submitWrite` 失败，buffer 保留密文不变，标记为 pending，下轮事件循环重试

### 5. 库选择

优先考虑通过 Zig C interop 接入：

- **BoringSSL**（Google fork of OpenSSL，API 稳定，广泛用于 nginx/envoy）
- 备选：libressl、mbedtls

通过 `build.zig` 的 feature flag 控制编译（默认关闭），用 `linkSystemLibrary` 或源码编译链接。

### 6. 安全基线

- 最低 TLS 1.2，优先 TLS 1.3
- 禁用 SSLv3、TLS 1.0、TLS 1.1
- 禁用重协商（`SSL_OP_NO_RENEGOTIATION`）
- 使用安全密码套件默认值（库自身推荐配置）
- 证书/私钥加载失败 → `init()` 返回 error（启动即失败）

## 实现任务

### A. 基础设施

- [ ] `build.zig` 添加 `tls` feature flag（默认关闭），链接 TLS 库
- [ ] 新增 `src/tls/` 目录，封装 TLS 库 API：
  - `TlsConfig` — 持有 `SSL_CTX*`（全局一份），server 和 client 共用
  - `TlsStream` — 持有 `SSL*` session handle（堆分配），内存 BIO pair（`in_bio` / `out_bio`），握手输出 buffer
  - `tlsConfigInit(cert_path, key_path, is_server) !TlsConfig` — **调用 BoringSSL 证书加载 API（阻塞文件 I/O，仅在 init 阶段执行）**
  - `tlsStreamNew(config: *TlsConfig) !TlsStream` — 创建 session + 内存 BIO pair
  - `tlsHandshakeAdvance(self: *TlsStream, in_data: []const u8) !HandshakeStep`
    - 内部循环调用 `SSL_do_handshake()` 直到 `WANT_READ` / `WANT_WRITE` / done / error
    - 返回 `.want_read`：需要更多密文输入，调用方应 `submitRead`
    - 返回 `.want_write`：输出在 `self.handshake_out_buf[0..self.handshake_out_len]`，调用方应 `submitWrite`
    - 返回 `.done`：握手完成，连接可进入加密传输
    - 返回 `.error`：握手失败，关连接
  - `tlsRead(stream: *TlsStream, ciphertext: []const u8, plaintext: []u8) !usize`
  - `tlsWrite(stream: *TlsStream, plaintext: []const u8, ciphertext: []u8) !usize`
  - `tlsStreamFree(self: *TlsStream) void` — 释放 `SSL*` + BIO pair

### B. StackSlot / Connection 扩展

- [ ] `Connection` 新增 `tls: ?*TlsStream` 字段（8 字节指针，null = 明文连接）
- [ ] `StackSlot` 不增加 TLS 字段（384/400B 预算已紧张），TLS 状态通过 `conn.tls` 间接访问

### C. HTTP Server

- [ ] `AsyncServer.init()` 新增参数：
  ```zig
  tls_config: ?struct { cert_path: []const u8, key_path: []const u8 }
  ```
  - `null` → 无 TLS，行为与当前完全一致
  - 提供 → init 阶段调用 `tlsConfigInit` 加载证书对，失败则返回 error
  - 后续扩展为 `[]struct { sni_host, cert_path, key_path }` 支持多证书
- [ ] `onAcceptComplete`：若配置了 TLS → `conn.state = .tls_handshaking` → 创建 `TlsStream`，挂到 `conn.tls` → `submitRead`
- [ ] `dispatchCqes` 新增 `.tls_handshaking` 分支：
  - 读 CQE → 取 buffer → `tlsHandshakeAdvance(conn.tls, buf[0..n])`
  - `want_read` → `submitRead`
  - `want_write` → 密文在 `conn.tls.handshake_out_buf` → `submitWrite`（失败则保留 buffer 待重试）
  - `done` → `conn.state = .reading` → 进入标准 HTTP 解析（后续 read/write 全部经 `tlsRead`/`tlsWrite` 加解密）
  - `error` → `closeConn`
- [ ] `onReadComplete`：若 `conn.tls != null` → `tlsRead(conn.tls, ciphertext, plaintext)` → 用解密后的 plaintext 继续 HTTP 解析
- [ ] `submitWrite` / `onWriteComplete`：若 `conn.tls != null` → 写入前 `tlsWrite(plaintext → ciphertext)`，写入密文
- [ ] 握手超时：`.tls_handshaking` 状态下 `last_active_ms` 超过 `WRITE_TIMEOUT_MS` → `closeConn`

### D. WebSocket

- [ ] WSS 复用 HTTP Server 的 TLS 层
- [ ] WS 升级在 TLS 握手完成之后进行，升级后 `conn.state` 流转与当前 WS 完全一致
- [ ] WS 帧读写经过 `conn.tls` 加解密（`onWsFrame` 的 read path + `submitWsWrite` 的 write path）
- [ ] 用户层面无感知 — `ws("/echo", handler)` 在 TLS server 上自动运行于 wss 模式

### E. HttpClient

- [ ] `parseUrl` 不再拒绝 `https://` scheme；`ParsedUrl` 新增 `.tls: bool`
- [ ] TCP 建连成功后，若 `.tls == true`：
  - 创建客户端 `TlsStream`（`is_server = false`，无需客户端证书）
  - 异步握手状态机（与 Server 侧相同模式，在 client ring 线程内执行）
  - 握手超时 5s → 返回 `502 Bad Gateway`
- [ ] 后续 `RingSharedClient.write()` / `Pipe.read()` 经 `tlsWrite`/`tlsRead` 加解密
- [ ] 连接池 `TinyCache` key 从 `(host, port)` 扩展为 `(host, port, tls: bool)`，TLS 与明文连接隔离
- [ ] `buildRequest` / `parseResponse` / `responseCompleteLen` 逻辑不变（HTTP 层面与明文完全一致）

## 非目标（本次不实现）

- mTLS（双向 TLS 认证）
- TLS 1.3 0-RTT
- kTLS (kernel TLS offload, `IORING_OP_SENDMSG` with TLS)
- ALPN 协商 HTTP/2（仅设置 ALPN = `["http/1.1"]`）
- TLS 会话票据/缓存（session ticket / session ID 复用）
- SNI 多证书（初版单证书对，API 层预留扩展点）
- CRL / OCSP 吊销检查（涉及网络 I/O，与单线程事件循环冲突）

## 迭代规则

若实现过程中发现本 issue 存在**架构设计错误**（如：选型不兼容 io_uring、状态机有死锁路径、buffer 生命周期与 CQE 时序冲突等），不得在原 issue 上直接覆盖修改。应按以下流程处理：

1. **修改本 issue (#58)** — 在对应章节追加勘误标记 `> **勘误 [日期]**：<错误描述>`，并注明修正方案
2. **签发新 issue** — 标题格式：`fix(tls): <修正点>`，正文引用 `ref #58`，描述修正后的设计
3. **关联** — 新 issue 的 body 开头写 `Depends on #58` 或 `ref #58`

示例：
```
> **勘误 2028-01-15**：初版设计将 tlsRead 的 plaintext 输出到栈上局部变量，
> 但 HTTP parser 需要跨 TLS 记录边界重组 header（与当前 TCP 短读重组同机制），
> 栈 buffer 的生命周期无法持有跨 CQE 的 header 片段。
> 修正方案：plaintext 复用 io_uring provided buffer 原地解密，见 ref #58。
```

## 参考

- 当前 `parseUrl` 拒绝逻辑：`src/client/http_client.zig:89`
- 客户端异步架构：`src/client/README.md` / `README_CN.md`
- 连接状态机：`src/http/connection.zig:ConnState`
- 连接槽位布局：`src/stack_pool.zig`（StackSlot 384B / 400B budget）
- CQE 分发：`src/http/event_loop.zig:dispatchCqes()`
- SQ 背压模式：`src/http/event_loop.zig:retryPendingWrites()` / `queuePendingWrite()`
