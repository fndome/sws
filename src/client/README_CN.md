# sws/client — 内建 io_uring HTTP 客户端

## 为什么 sws 自带 HTTP 客户端

大多数 web 框架中，HTTP server 和出站 HTTP client 是分离的。sws 不同：
**HTTP 客户端的存在是为了守护 sws 的性能模型**，而不是因为出站 HTTP
天然属于框架职责。

单线程 io_uring 事件循环中，任何在 IO 线程上执行的阻塞 syscall 都会导致
整个服务器停滞。handler 中发起的每次出站 HTTP 请求都可能成为那个阻塞点
——DNS 解析、TCP 建连、TLS 握手、响应读取都必须是非阻塞的。

Zig 生态中没有现成的 io_uring 原生 HTTP 客户端。如果 sws 不提供，每个
应用只能二选一：

1. 把每次出站调用丢给 worker 线程（每次请求都付出"线程切换 + 上下文投递"
   的额外代价），或
2. 手写 `linux.socket()` + `getaddrinfo()`（在 IO 线程上阻塞 DNS 和 connect，
   正是必须避免的）。

两者都会破坏 sws 赖以存在的单线程事件循环性能。

## io_uring + TinyCache 组合

### RingB（HttpRing）

一个独立的 io_uring ring，具备：

- **异步 DNS** — io_uring UDP SQE，解析期间 fiber yield，IO 线程零阻塞
- **异步 TCP 建连** — `IORING_OP_CONNECT` + `IORING_OP_LINK_TIMEOUT`
  （默认 5s），fiber yield 等待 CQE
- **异步读写** — `IORING_OP_READ` / `IORING_OP_WRITE`，非阻塞
- **跨线程投递** — `InvokeQueue` 实现调用方 → ring 线程的请求分发
- **独立 OS 线程** — 自行驱动 `submit_and_wait` 循环，IO 线程延迟
  不受出站请求量影响

### TinyCache（连接池）

一个 per-(host, port) keep-alive 连接池，具备：

- 基于 TTL 的过期淘汰（可配置，默认 2000ms）
- 单目标连接数上限（`MAX_CONNS_PER_HOST = 12`）
- 透明的 acquire / release / evict 生命周期
- 无需线程同步（单 ring 线程）

### 为什么第三方 io_uring HTTP 客户端不够

即使 Zig 生态中有了单独的 io_uring HTTP 客户端，仍有一个关键缺口：
**连接池不是附加功能——它是负载下持续性能的前提。**

每次冷 HTTP 请求的代价：

- DNS 解析（~1-5ms 异步）
- TCP 三次握手（数据中心内 ~100µs，跨可用区 ~1ms）
- TLS 握手（~1-5ms，sws 尚未实现）

单次请求可忽略。但如果 handler 在每条 WebSocket 消息上都调用外部服务
（20K msg/s），每次请求都建连 + 断开会让出站 ring 的 SQE 预算被
`IORING_OP_CONNECT` 耗尽，P99 延迟飙升数个量级。

TinyCache 通过跨请求保持空闲连接来吸收这个成本。一个每秒调用同一
filter/db/auth 服务 10 万次的 handler，只在首次冷调用时付出连接代价，
其余 99,999 次直接复用。没有连接池，io_uring ring 的大部分 SQE 预算
会消耗在 `IORING_OP_CONNECT` 上，而非 `IORING_OP_WRITE`。

**没有连接池的 io_uring HTTP 客户端只是 benchmark 玩具。**
它会跑出漂亮的单连接吞吐数字，然后在生产环境的扇出负载下崩塌。
io_uring 传输 + per-host 连接池的组合，才是 sws 出站路径在规模下可行的基础。

```
handler（IO 线程 fiber）
  │
  ├── HttpClient.request("POST", "http://filter.svc/check", body)
  │     │
  │     ├── invoke.push → RingB 线程接管
  │     │
  │     ├── RingB 线程
  │     │     ├── cache.acquire(host, port)
  │     │     │     ├── HIT  → 复用连接（跳过 DNS，跳过 TCP）
  │     │     │     └── MISS → dns.resolve() → connectRawTimeout() → fiber-yield
  │     │     ├── write request → fiber-yield
  │     │     ├── readPipe.read() → fiber-yield
  │     │     ├── cache.release(pipe) 或 cache.evictPipe(pipe)
  │     │     └── notify → 调用方线程唤醒
  │     │
  │     └── 返回 response
  │
  └── IO 线程继续处理其他连接（永不阻塞）
```

没有 TinyCache，每次出站调用都付出 DNS + TCP 建连延迟。
没有 io_uring 原生客户端，每次出站调用要么切线程，要么阻塞。
两者结合，确保 sws 的 IO 线程永不等待外部服务，且同一目标的重复调用
以近乎零成本复用连接。

## 用法

```zig
var client = try sws.HttpClient.init(alloc, &ring_b);
try client.start(); // 启动独立 ring 线程
defer client.deinit();

const resp = try client.get("http://api.example.com/data");
defer resp.deinit();
```

## 何时不启用

如果你的 handler 从不发起出站 HTTP 调用，不要初始化 `HttpClient`。
ring、线程和连接池在 `start()` 被调用前零开销。没有隐藏依赖或自动实例化。
