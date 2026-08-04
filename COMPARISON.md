# sws vs httpx.zig 比较分析

> **分析日期**: 2026-07-13
> **sws 版本**: v0.5.0
> **httpx.zig 版本**: v0.1.3
> **httpx.zig 仓库**: (本地) `d:\myy\httpx.zig`

---

## 一、基本定位

| 维度 | sws | httpx.zig |
|------|-----|-----------|
| 定位 | 单线程超高并发 HTTP 服务器 | 跨平台 HTTP 客户端 + 服务器库 |
| 目标场景 | 1M 并发长连接 (IM/游戏/实时推送) | 通用 Web 应用、API 网关、反向代理 |
| 平台 | Linux only (io_uring 内核态) | Linux / Windows / macOS |
| 协议 | HTTP/1.1 + WebSocket + TLS | HTTP/1.1 + HTTP/2 + HTTP/3 + WebSocket |
| 并发模型 | 单 IO 线程 + 用户态 fiber + WorkerPool | 传统 fd socket + 线程池 executor |
| I/O 模型 | io_uring (SQE/CQE, submit_and_wait) | 同步/异步 socket (send/recv) |
| TLS | 纯 Zig TLS 1.3 (自研, lib/tls.zig) | std.crypto.tls.Client 封装 |
| DNS | 自建 io_uring UDP DNS + TTL 缓存 | getaddrinfo / 自定义 resolve |
| 对外发布 | example server 形式构建 | 标准 Zig 库 (libhttpx.a, zig fetch) |
| 代码量 | ~14,300 行 | ~20,400 行 |
| 依赖 | libc, tls.zig (bundled) | 零外部依赖 |

---

## 二、sws 独有的优势

### 2.1 io_uring 驱动的事件循环
- 全部操作 (accept/read/write/close) 通过 io_uring SQE 提交，CQE 轮询
- `submit_and_wait(1)` 零忙等，单核可驱动百万连接
- httpx.zig 使用传统 epoll/select socket 模型，无法达到同级别并发

### 2.2 用户态 Fiber (协程)
- x86_64/ARM64 自研 fiber 实现，共享栈 256KB
- handler 在 IO 线程上顺序执行，零锁竞争，零上下文切换开销
- httpx.zig 的 server handler 跑在 OS 线程上，有完整的调度器开销

### 2.3 O(1) 连接池 (StackPool)
- 100 万预分配槽位，每个槽 384 字节，5 个 cache-line 对齐子结构
- gen_id 幽灵事件防御机制
- httpx.zig 的连接池是动态 ArrayList，无预分配

### 2.4 Deferred Response + Hook 系统
- 工作线程通过 CAS 无锁调用队列安全投递响应到 IO 线程
- 支持 MMO 级服务器：tick hook 在每次事件循环执行自定义逻辑
- httpx.zig 无等效机制

### 2.5 Pipe 抽象
- Push-to-pull 适配器，让同步风格的协议库能在 IO 线程 fiber 上运行
- 读阻塞时 fiber yield，数据到达时 resume
- httpx.zig 无等效抽象

### 2.6 分层缓冲池
- io_uring provided buffer slab (16K x 4KB = 64MB)
- 8 个大小级别的写缓冲池 (512B-64KB)，freelist 复用
- LargeBufferPool: 64 x 1MB 处理超大请求体
- httpx.zig 的 Buffer 只有 3 种通用实现，无分级缓存

### 2.7 连接管理
- io_uring fixed-file 注册，减少 fd 查找开销
- 连接关闭保护 (write-in-flight 检查)
- 按需重连和优雅关闭

---

## 三、sws 已识别的 Bug / 问题

### 3.1 高危 — tcp_write.zig pool_idx 越界

**位置**: `src/http/tcp_write.zig:39` 和 `src/http/tcp_write.zig:185`

`submitWrite` 和 TLS 写入路径中，`const slot = &self.pool.slots[conn.pool_idx]` 在访问前未校验 `conn.pool_idx != 0xFFFFFFFF`。当连接未使用池化 slot (pool_idx == 0xFFFFFFFF) 时，会导致数组越界访问。

```zig
// src/http/tcp_write.zig:39 — 缺少 guard
const slot = &self.pool.slots[conn.pool_idx];
```

**修复**: 在访问 slots 前添加 `if (conn.pool_idx == 0xFFFFFFFF) return` 的守卫检查。

### 3.2 中危 — retryPendingWrites 提前退出

**位置**: `src/http/event_loop.zig:255`

遇到第一个 `WriteInFlight` 错误时 `break` 整个循环，导致同一批次中排在后面的其他 pending write 被跳过一整个事件循环迭代。在 1M broadcast 场景下会放大写延迟。

**修复**: 将 `break` 改为 `continue`，仅跳过当前出错条目。

### 3.3 中危 — HttpClient OOM 风险

**位置**: `src/client/http_client.zig`

`parseResponseForMethod` 使用 `allocator.dupe` 一次性将完整响应体读入内存。对于大文件下载或流式 API，会导致 OOM。

**修复**: 实现流式 body reader，或对 body 大小添加上限检查。

### 3.4 中危 — Pipe read_buf 无上限

**位置**: `src/next/pipe.zig` (已记录于 STRESS_TEST.md)

Pipe 内部的 `read_buf` 在数据产生速度快于消费速度时会无限增长，最终 OOM。

**修复**: 添加 `max_buffer_size` 上限和背压机制。

### 3.5 低危 — 代码重复

| 重复函数 | 位置 1 | 位置 2 |
|----------|--------|--------|
| `requestLineIsHttp11` | `src/http/http_helpers.zig:45` | `src/http/tcp_read.zig:714` |
| `getPathFromRequest` | `src/http/http_helpers.zig` | `src/http/tcp_read.zig` (getPathFromRequestWithLimit) |

**修复**: 统一到 http_helpers.zig，删除 tcp_read.zig 中的重复实现。

### 3.6 低危 — 死代码

**位置**: `src/tls/boring.zig`

完整的 BoringSSL FFI 声明但从未被引用。当前 TLS 走纯 Zig tls.zig 路径。

**修复**: 删除或移至条件编译分支 `if (use_boringssl)`。

### 3.7 设计风险 — 共享 Fiber 栈

**位置**: `src/next/fiber.zig`

256KB 共享栈意味着递归 handler 或调用栈深时栈溢出并静默破坏内存。

**缓解**: 已有文档提示，但缺少运行时栈溢出检测（如 canary 页）。

### 3.8 设计风险 — WorkerPool freelist O(n) 释放

**位置**: `src/next/next.zig`

`releaseStack` 中的 `for self.stack_pool, 0..` 是 O(n) 扫描。多 worker 场景下，配合 mutex 虽然线程安全，但释放效率低。

---

## 四、httpx.zig 值得借签的设计

### 4.1 增量状态机 HTTP 解析器

**来源**: `src/protocol/parser.zig` (535 行)

- `feed(bytes)` 返回已消费字节数，解析器不感知 socket
- 自动处理 Content-Length / chunked / connection-close 三种定界方式
- 内置上限保护 (header 8KB, header 数量 100)

**借签价值**: sws 的解析逻辑嵌在 `tcp_read.zig` (919 行) 中，与 I/O 逻辑耦合。抽取独立的
增量解析器可以:
- 降低 tcp_read.zig 复杂度
- 让解析器可独立测试
- 便于未来支持 HTTP/2 stream frame

### 4.2 路径参数路由

**来源**: `src/server/router.zig` (416 行)

- 支持 `:id` 参数化路径段和 `*` 通配符
- 匹配时使用栈上 `[16]RouteParam` 固定 buffer，零堆分配
- `allowedMethods()` 自动生成 405 + Allow 响应头

**借签价值**: sws 目前只有 ant-style 通配符中间件 (`/user/*`)，无法提取路径参数。
大多数 Web 框架的用户都期望 `/user/:id` 语法。

### 4.3 内置中间件生态

**来源**: `src/server/middleware.zig` (531 行)

| 中间件 | 功能 |
|--------|------|
| CORS | 跨域策略配置 |
| Helmet | 安全响应头 (HSTS, X-Frame-Options, X-Content-Type-Options) |
| RateLimit | 令牌桶限流 |
| BasicAuth | HTTP Basic 认证 (支持文件/函数验证) |
| Logger | 请求日志 (时间戳/状态码/耗时) |
| Compression | 响应压缩 |
| HealthCheck | 健康检查端点 |
| ReverseProxy | 反向代理 |

**借签价值**: sws 的 hook_system 提供了底层粘合点 (deferred/tick hooks)，但缺少开箱即用的中间件。
建议基于 hook_system 实现 CORS 和 RateLimit 作为首批中间件。

### 4.4 链式 ResponseBuilder API

**来源**: `src/core/response.zig`

```zig
ctx.response()
    .status(200)
    .header("X-Custom", "value")
    .json(data);
```

**借签价值**: sws 当前的 `ctx.respond()` / `ctx.respondJson()` 各自独立，状态码通过额外参数传入。
链式 API 对开发者更友好，且可减少多态函数的数量。

### 4.5 SOCKS5h 代理支持

**来源**: `src/client/proxy.zig` (131 行)

- HTTP CONNECT 隧道
- SOCKS5h 完整握手 (含用户名/密码认证)
- IPv4/IPv6/主机名 三种地址类型

**借签价值**: sws 的 HttpClient 无代理支持。如果场景涉及内网穿透，可直接移植该模块。

### 4.6 原子计数器 Metrics

**来源**: `src/util/metrics.zig` (294 行)

- `std.atomic.Value(u64)` lock-free 计数器
- 追踪: 请求/响应总数、按状态码分类、字节数、活跃连接、错误、延迟极值
- `MetricsEvent` 回调集成

**借签价值**: sws 目前无 metrics 收集。给 StackPool、event loop、buffer pool 加上 atomic metrics
可极大提升生产环境的可观测性。

### 4.7 零依赖库发布模式

**来源**: `build.zig.zon`

```zon
.{
    .name = "httpx",
    .version = "0.1.3",
    .dependencies = .{},  // 零依赖
    .minimum_zig_version = "0.16.0",
}
```

**借签价值**: sws 目前以 example server 形式构建，不作为库发布。如果未来希望被其他项目通过
`zig fetch` 引用，需要将核心抽成 lib + 独立的 example 可执行文件。

### 4.8 分批编译示例防止 OOM

**来源**: `build.zig` (217 行)

35 个 example 使用编译步骤链式依赖 (`prev_run.step.dependOn(&current_compile.step)`)，防止 Zig 编译器并行编译时内存溢出。

**借签价值**: sws 目前 example 较少，但随着增长，该技巧可直接复用。

---

## 五、HTTP/2 & HTTP/3 协议栈分析

httpx.zig 最显著的技术亮点是全自研的 HTTP/2 和 HTTP/3 实现:

| 模块 | 行数 | RFC | 功能 |
|------|------|-----|------|
| `protocol/hpack.zig` | 957 | RFC 7541 | HTTP/2 头部压缩 (Huffman + 静态/动态表) |
| `protocol/stream.zig` | 854 | RFC 7540 | HTTP/2 流管理 (多路复用/流控/优先级) |
| `protocol/qpack.zig` | 1006 | RFC 9204 | HTTP/3 头部压缩 (QPACK) |
| `protocol/quic.zig` | 997 | RFC 9000 | QUIC 传输层 (帧类型/连接迁移/0-RTT) |
| `protocol/http.zig` | 928 | — | HTTP/1.x + HTTP/2 + HTTP/3 帧格式化 |

**对 sws 的参考意义**:

- HTTP/2 多路复用对 WebSocket 长连接场景价值有限 (ws 本身已是双向流)
- HTTP/3 (QUIC) 在移动网络下有明显优势: 连接迁移、0-RTT、弱网优化
- sws 的架构 (单 IO 线程 + fiber) 天然适合 HTTP/2 stream 模型: 每个 stream 映射到一个 fiber
- 短期不建议引入 HTTP/2/3，但 hpack+qpack 的实现可作为长期技术储备

---

## 六、行动计划 (优先级排序)

### 立即修复 (bug)

- [ ] `tcp_write.zig:39` — pool_idx OOB 守卫
- [ ] `tcp_write.zig:185` — TLS 写入路径 pool_idx 守卫
- [ ] `event_loop.zig:255` — retryPendingWrites 用 continue 替代 break

### 短期改进 (功能增强)

- [ ] 新增路径参数路由 (`/user/:id`)
- [ ] 基于 hook_system 实现 CORS 中间件
- [ ] 基于 hook_system 实现 RateLimit 中间件 (令牌桶)
- [ ] 添加 `response.status(200).json(data)` 链式 API

### 中期重构

- [ ] 抽取独立的增量 HTTP 解析器 (参考 httpx parser.zig)
- [ ] 统一 `requestLineIsHttp11` / `getPathFromRequest` 到 http_helpers.zig
- [ ] 删除 `src/tls/boring.zig`
- [ ] Pipe 添加 max_buffer_size 背压
- [ ] HttpClient 添加流式 body reader

### 长期探索

- [ ] 评估 HTTP/2 多路复用 (参考 hpack.zig + stream.zig)
- [ ] 添加原子计数器 metrics (参考 metrics.zig)
- [ ] 库化发布: core lib + example binary 分离
- [ ] SOCKS5h 代理支持
