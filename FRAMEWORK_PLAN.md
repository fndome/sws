# 框架级升级计划

> 本文件是**方案**，未改代码。目标是参照 `lib/tls.zig`（tls_zig）的架构，把 `sws` 从「能跑的服务」升级到「可复用、可配置、可测试的框架级库」。
>
> 参照物选择：`lib/tls.zig` 是 `sws` 直接依赖的第三方库，同为 Zig、同为 io_uring 场景（sws 的 TLS 层），且其 API 设计（config / nonblock / 依赖注入）是成熟的框架级范式。

---

## 0. 参照物（tls.zig）的核心范式

| 范式 | tls.zig 做法 | 价值 |
|---|---|---|
| 类型化配置 | 单一 `config.Client`/`config.Server` Options struct，字段全类型化 + 默认值 | 调用点无魔法数、编译期校验 |
| 依赖注入 | `rng`/`now`/`root_ca`/`host` 全部经 Options 注入，零全局状态 | 可替换、可测试 |
| 非阻塞状态机 | `nonblock.Client.run(in, out)` 增量驱动、显式 short-read，与 IO backend 解耦 | 可在任意环境单测 |
| API 分组 | `root.zig` 按 `config`/`nonblock`/`Cipher`/`Ktls` 分组 re-export | 稳定公开 API 边界 |
| 具名错误 | `error.TlsNoApplicationProtocol` 等语义化错误 | 调用方可编程分支 |

---

## 1. 现状差距（对照 sws）

### 1.1 配置系统：类型擦除 + 魔法数位置参数

- `async_server.zig:245`：`init(allocator, io, listen_addr, app_ctx, fiber_stack_size_kb: u16, tls_auth, init_cfg)` —— 7 个位置参数，`fiber_stack_size_kb` 是魔法数位置参数（调用点 `AsyncServer.init(..., 64, ...)`）。
- `Config`（16 字段，有默认值）与 `InitConfig`（3 字段）职责重叠，同一概念两处定义。
- `ConfigKey` enum + `config(key, value: i32)`（`async_server.zig:225`）—— 类型擦除 setter：全部走 `i32`，`idle_timeout_ms`(u64) 被 `@intCast`，`io_cpu: ?u6` 用「负数表 null」编码。

**问题**：无编译期类型安全、调用点不透明、配置分散三处。

### 1.2 全局可变状态：隐式单例

- `next.zig:15`：`var default_next: ?*Next` 全局；`Next.go`/`submit`/`trySubmit`/`goWithStackConfigurable` 都靠 `setDefault()` 设的全局单例。
- `fiber.zig`：`threadlocal` 全局 `saved_call`/`parked_ctx`/`parked_poll`/`parked_poll_ctx` 当 yield 的「出参通道」。

**问题**：隐式耦合，一个进程只能有一个 Next，fiber 状态藏在全局里难推理。

### 1.3 API 分层：root.zig 平铺

- `src/root.zig` 60+ 行扁平 `pub const X = @import(...)`，无「配置层 / 协议层 / 传输层」分组。

**问题**：无稳定公开 API 边界，内部模块变化即破坏对外接口。

### 1.4 协议状态机与 io_uring 耦合

- `onReadComplete`/`onWsFrame`/body 流 等状态机直接耦合 `AsyncServer`/`io_uring`，只能 Linux 编译、无法脱离 io_uring 单测。

**问题**：核心协议逻辑不可测、不可复用（对比 tls 的 nonblock 只吃/吐字节）。

### 1.5 错误语义：通用 error + 静默

- 大量 `error.InvalidResponse`/`InvalidHeader` 等通用错误，缺少可编程判定的具名错误。

---

## 2. 升级方案（按优先级）

### 阶段 A —— 统一配置（硬门槛，先做）

1. 合并 `Config` + `InitConfig` 为单一 `Config`（`large_pool_capacity`、`fiber_stack_size_kb` 并入，全字段带默认值）。
2. `init` 改为 `init(allocator: Allocator, io: std.Io, config: Config) !Self`，删位置参数。
3. 删除 `ConfigKey` + `config(key, value)`，改为直接字段访问（`server.cfg.idle_timeout_ms = 30000`）。
4. 更新所有调用点（`example/main.zig`、`example/dev_main.zig`、`src/example.zig` 等）。

验收：`grep -n "config(" src` 为空；`init` 只接受 `Config`；`zig build -Dtarget=x86_64-linux` 绿。

### 阶段 B —— 去除全局单例

1. `Next`：`go`/`submit`/`trySubmit` 从「读 `default_next` 全局」改为实例方法（或显式传 `*Next`）；删除 `setDefault`/`default_next`。
2. `Fiber`：yield 出参从 `threadlocal` 全局改为返回值 struct（如 `YieldInfo{ ctx, poll, poll_ctx }`）。
3. 更新 `http_routing`/`tcp_read`/`ws_handler` 等调用点。

验收：`grep -n "default_next\|setDefault" src` 为空；`grep -n "threadlocal" src/next/fiber.zig` 为空或仅剩局部缓存。

### 阶段 C —— 协议状态机解耦（最大重构，价值最高）

1. 抽「纯协议状态机」：HTTP 读解析、WS 帧、body 流 → 「进字节、出动作」的无 io_uring 状态机（参照 tls `nonblock`）。
2. io_uring 只做字节搬运 + 驱动状态机。
3. 状态机成为 host 可测（`zig test`），覆盖 short-read / 分片 / 畸形输入。

验收：核心协议状态机可在 Windows host `zig test`；io_uring 文件不再含协议解析逻辑。

### 阶段 D —— API 分层 + 错误语义

1. `root.zig` 按 `config` / `server` / `http` / `ws` / `client` / `next` 分组 re-export。
2. 关键协议边界用具名错误（HTTP 解析 / WS 帧 / DNS），替换通用 error。

---

## 3. 明确不做 / 依赖

- 多包拆分（`sw-core`/`sw-httpclient`/`sws`）：等 Zig 1.0，见 `ROADMAP.md`。
- 阶段 C 若与 io_uring 深度交织，可拆分多步、每步 `zig build` 验证；不追求一次到位。

---

## 4. 验收标准（框架级达成时）

1. `AsyncServer.init` 只接受类型化 `Config`，无位置魔法数。
2. 无全局单例 / threadlocal 协议状态。
3. 核心协议状态机 host 可测，io_uring 与协议逻辑解耦。
4. `root.zig` 有清晰分组 API；关键错误具名、可编程判定。
