# sws — 单线程服务器

基于 Linux `io_uring` 的单线程 HTTP + WebSocket 服务器，Zig 0.16.0。

## 项目目标

`sws` 不应该只被理解成一个 `req/s` 演示。它更像是一个 Linux 专用的
轻量网络运行时：用 Zig、`io_uring`、fiber、显式 buffer 所有权和单 IO
线程事件循环，把 HTTP、WebSocket、DNS、出站 HTTP client、连接池这些路径
放在一个可审计的底层框架里。

当前目标按优先级分三层：

1. **正确性优先**：HTTP/1.1、WebSocket、DNS、keep-alive、请求/响应头、
   body 边界和异常请求必须有清晰行为。
2. **可验证**：固定自测覆盖 `GET/POST/PUT/PATCH/DELETE`、JSON body、
   keep-alive、WebSocket、非法请求、DNS 异常和小规模 benchmark。
3. **有清晰定位**：Linux + `io_uring` 专用，HTTP/1.1 + WebSocket + 出站
   HTTP client；暂不内建 TLS，需要前置 TLS 代理或后续单独实现 TLS 层。

本机自测里的 QPS 只能说明“小规模正确性和稳定性”。客户端和服务端在同一台
机器上竞争 CPU，默认 benchmark 也只有 `50 x 100` 个 keep-alive 请求。要做
更接近性能上限的测试，请使用 ReleaseFast 并显式放大连接数和请求数：

```bash
zig build -Doptimize=ReleaseFast
SWS_BENCH_CONNS=500 SWS_BENCH_REQS_PER_CONN=1000 ./zig-out/bin/im-bench
```

```
IO 线程（io_uring Ring A + fiber）:
  ├── accept/read/write CQE → fiber → handler → 发响应
  ├── drainNextTasks（Next.go ringbuffer 任务）
  ├── drainDeferred / InvokeQueue → 发响应
  ├── drainTick（DNS tick + invoke.drain + tick_hooks）
  └── TTL 增量扫描（StackPool 活跃表）

Worker 线程池（可选，仅 CPU 密集任务）:
  └── Next.submit() → worker 线程 → 计算 → InvokeQueue → IO 线程回调
```

Handler 默认作为 **fiber 运行在 IO 线程上**。
- `Next.go()` — IO 线程 fiber，零线程切换。用于 DB io_uring、异步 I/O。
- `Next.submit()` — 线程池。将 CPU 重活、GPU 推理、同步阻塞 I/O 卸离 IO 线程。

## 环境要求

- Linux 5.1+（io_uring）
- Zig 0.16.0

## 重要使用警告

**严禁在 sws handler 代码中通过内核块设备层进行文件读写。** IO 线程的
io_uring 事件循环运行在单线程上，任何阻塞调用线程的操作都会导致整个服务
器陷入停滞，波及所有活跃连接。

### 禁止通过文件 I/O 使用的存储后端

以下后端会经过内核块设备层，即使挂载为本地路径也会阻塞 IO 线程：

- **FUSE** — 任何通过 FUSE 挂载的文件系统（s3fs、gcsfuse 等）
- **Longhorn v1** — 内核 iSCSI initiator → engine → replica，同步复制
  quorum 在内核 I/O 路径内等待
- **Ceph RBD（内核模式）** — 内核块设备等待 OSD 确认
- 任何通过标准内核文件系统栈挂载的网络块设备（NFS、iSCSI、同步模式 DRBD）

### 可安全使用的存储后端

- **local_pv** — 直接挂载的 NVMe/SSD，页缓存写入延迟极低
- **基于 SPDK 的用户态存储** — 完全绕过内核块设备层的存储引擎，使用轮询
  模式 NVMe 驱动与 vhost-user 共享内存。例如：**OpenEBS Mayastor**、
  Longhorn v2（SPDK 后端）。

SPDK 存储之所以安全，是因为 I/O 路径全程不进入内核——数据通过 DMA 直接从
NVMe 传输到用户态环形缓冲区，轮询模式驱动永不阻塞调用线程。

### 远端对象存储

请使用 **io_uring 层面非阻塞网络 Socket**，直接向远端 API 端点发出
`OP_SEND` / `OP_RECV`：

```
handler → OP_SEND / OP_RECV → S3/OSS/MinIO HTTP API
           ↑ io_uring 原生非阻塞
```

不要通过 FUSE 挂载 S3/OSS 然后进行文件读写。

## 快速开始

```bash
git clone https://github.com/fndome/sws
cd sws
zig build run
```

## 作为库使用

```zig
const sws = @import("sws");

pub fn main() !void {
    var server = try sws.AsyncServer.init(alloc, io, "0.0.0.0:9090", null, 0);
    defer server.deinit();

    server.GET("/hello", myHandler);
    try server.run();
}
```

## 架构

### 单 IO 线程 + fiber

整个事件循环跑在**一个 IO 线程**上。Handler 作为 **fiber**（用户态协程）在同一线程中执行。

```
IO 线程（单线程）:
  io_uring.submit_and_wait(1)
    → CQE 分发（通过 StackPool sticker）
    → fiber → handler → ctx.text/json/html
    → drainPendingResumes（fiber 恢复队列）
    → drainNextTasks（Next.go ringbuffer 任务）
    → drainTick（DNS tick + invoke.drain + tick_hooks）
    → TTL 扫描（StackPool 活跃表，增量滑窗）
    → 循环
```

除非显式调用 `server.initPool4NextSubmit(n)`，不会启动任何后台线程。

### StackPool — O(1) 连接池

连接存储于**预分配数组**（非哈希表）。freelist 支持 O(1) 获取/释放。

```
StackPool<StackSlot, 1_048_576>
  ├── slots: [1M]StackSlot — 连续内存，缓存行对齐
  ├── freelist: [1M]u32 — O(1) 压入/弹出
  ├── live: []u32 — 活跃槽位索引表（TTL 扫描源）
  └── warmup() — 触碰所有页消除冷启动 Page Fault
```

#### StackSlot（384 字节，5 条缓存行）

每个连接槽位按独立缓存行拆分，热路径无竞争：

```
line1（64B）：fd、gen_id、state、write_offset、req_count — CQE 分发（最热）
line2（64B）：conn_id、last_active_ms、active_list_pos — TTL 扫描
line3（64B）：fiber_context、large_buf_ptr — 异步锚点、Worker Pool、超大报文
line4（128B）：writev_in_flight、response_buf、write_iovs、ws_write_queue — 写路径（低频）
line5（64B）：sentinel（0x53574153）+ workspace 联合体 — HTTP/WS/Compute 视图
```

**幽灵事件防御：** `user_data = (gen_id << 32) | idx`。关闭连接时清零 gen_id。任何在途 CQE 到达时 gen_id 不匹配 → 静默丢弃。

**视图切换：** `line5.ws` 联合体根据连接状态在 `HttpWork`、`WsWork`、`ComputeWork` 之间切换——协议解析状态零堆分配。

### Ring A + 独立线程出站

**Ring A**（内置）：主服务器 `io_uring` ring — accept、连接读写、DNS、invoke。
**出站 ring**（Ring B, HTTP 客户端）：运行在独立 OS 线程上的 `io_uring` ring。IO 线程不受出站 I/O 影响。参见 [src/client/README.md](src/client/README.md) 了解为什么 HTTP 客户端内建在 sws 中。

```
Ring A（主服务器，IO 线程）:
  ├── accept / read / write / close
  ├── io_registry（客户端回调注册表）
  ├── dns_resolver（异步 UDP DNS）
  └── rs.invoke（跨线程推送 → IO 线程回调）

Ring B（HTTP 客户端，独立线程）:
  ├── ring.submit_and_wait(1)
  ├── tick → dns.tick + invoke.drain + copy_cqes + dispatch
  ├── IORegistry
  ├── DnsResolver
  ├── InvokeQueue
  └── TinyCache（per-host keep-alive 连接池）
```

### 初始化

```zig
var server = try AsyncServer.init(alloc, io, "0.0.0.0:9090", app_ctx, fiber_stack_size_kb);
//                                                                    ↑ 0 = 256KB
```

首次注册 handler/middleware 时 `ensureNext()` 自动创建 `Next`（ringbuffer）+ `setDefault()`。

内部 `AsyncServer.init()` 创建：
- `pool`: StackPool — O(1) 连续数组连接池
- `large_pool`: LargeBufferPool(64) — 64 × 1MB 超大报文缓冲
- `rs`: RingShared — 单 ring 共享资源（ring + registry + invoke）
- `io_registry`: IORegistry — 出站客户端连接注册表
- `dns_resolver`: DnsResolver — 异步 UDP DNS + TTL 缓存

添加内建 HTTP 客户端：

```zig
// RingB 内建 1s TinyCache TTL：
var ring_b = try sws.HttpRing.init(alloc, io, server.ring.fd, 1000);
defer ring_b.deinit();

// HttpClient 自动使用 RingB 内建缓存 — keep-alive 零配置
var http_client = try sws.HttpClient.init(alloc, &ring_b);
try http_client.start(); // 启动独立 ring 线程
defer http_client.deinit();
```

### Handler — 同步（跑在 IO 线程）

```zig
fn hello(allocator: Allocator, ctx: *Context) anyerror!void {
    ctx.text(200, "hello");
}
```

### Handler — `Next.go`（fiber，IO 线程，不切线程）

用于异步 I/O（DB io_uring、HTTP Client 等）：

```zig
const Ctx = struct { allocator: Allocator, resp: *DeferredResponse };

fn exec(c: *Ctx, complete: *const fn (?*anyopaque, []const u8) void) void {
    defer c.allocator.destroy(c);
    defer c.allocator.destroy(c.resp);
    c.resp.json(200, "[{\"id\":1}]");
    complete(c, "");
}

fn myHandler(allocator: Allocator, ctx: *Context) anyerror!void {
    const s: *AsyncServer = @ptrCast(@alignCast(ctx.server.?));
    const resp = try allocator.create(DeferredResponse);
    resp.* = .{ .server = s, .conn_id = ctx.conn_id, .allocator = allocator };
    ctx.deferred = true;
    Next.go(Ctx, .{ .allocator = allocator, .resp = resp }, exec);
}
```

### Handler — `Next.submit`（线程池，切线程）

用于卸货（加解密、压缩、LLM/GPU 推理、阻塞 I/O）：

```zig
const Ctx = struct { allocator: Allocator, resp: *DeferredResponse };

fn exec(c: *Ctx, complete: *const fn (?*anyopaque, []const u8) void) void {
    defer c.allocator.destroy(c);
    defer c.allocator.destroy(c.resp);
    // 卸货逻辑放这里（CPU/GPU/阻塞 I/O）...
    c.resp.json(200, "{\"done\": true}");
    complete(c, "");
}

fn myHandler(allocator: Allocator, ctx: *Context) anyerror!void {
    const s: *AsyncServer = @ptrCast(@alignCast(ctx.server.?));
    const resp = try allocator.create(DeferredResponse);
    resp.* = .{ .server = s, .conn_id = ctx.conn_id, .allocator = allocator };
    ctx.deferred = true;
    Next.submit(Ctx, .{ .allocator = allocator, .resp = resp }, exec);
}
```

### Worker 线程池（Next.submit 用）

```zig
try server.initPool4NextSubmit(1); // 1 个 worker 线程（推荐）
```

**推荐配置：**
- `1` — 默认，加解密、压缩、CPU 推理够用
- `N/2`（8 核设 4）— 持续 CPU 推理或阻塞 I/O
- GPU 推理：`1` — 目前 GPU 不支持 io_uring，1 个 worker + fiber 即可复用 N 个并发任务

### DeferredResponse

从任意线程发 HTTP 响应（CAS 无锁链表推送到 IO 线程）：

```zig
resp.json(200, "{\"ok\":true}");
resp.text(200, "plain");
```

### Deferred 钩子、Tick 钩子

在每次延迟响应发送前执行自定义逻辑，跑在 IO 线程上。
MMORPG / 实时场景必需（更新游戏状态、排行榜、广播）：

```zig
fn updateGameState(server: *AsyncServer, node: *DeferredNode) void {
    const world: *GameWorld = @ptrCast(@alignCast(server.app_ctx.?));
    world.update(node.body);
}

try server.addHookDeferred(updateGameState);
```

**规则：**
- 按注册顺序在 IO 线程执行——可安全访问 IO 线程独占数据
- `node.body` 在钩子执行期间有效，**禁止释放**
- **禁止保存** `node` 指针——钩子返回后 node 被销毁
- 必须不能 panic（用 log 记录错误）

#### 房间自动战场示例

倒计时 → 自动开战，支持数百人混战。两个钩子协作：
`addHookTick` 每轮 IO 循环检查截止时间（无需 deferred 节点）；
`addHookDeferred` 处理玩家指令。
战斗 CPU 重活通过 `Next.submit` 卸到线程池。全程零锁——游戏状态都在 IO 线程。

```zig
const Room = struct {
    id: u64,
    state: enum { waiting, fighting, settle },
    deadline: i64,                  // 单调时间戳
    teams: [2]std.ArrayList(*Player),
};

const Player = struct { id: u64, hp: u32, atk: u32 };

const BattleCtx = struct {
    blue_team: []PlayerSnapshot,
    red_team:  []PlayerSnapshot,
};

const PlayerSnapshot = struct { hp: u32, atk: u32 };
```

```zig
fn roomTick(server: *AsyncServer) void {
    const app: *GameApp = @ptrCast(@alignCast(server.app_ctx.?));
    for (app.rooms.items) |*room| {
        if (room.state == .waiting and server.monotonic_ms() >= room.deadline) {
            room.state = .fighting;
            startBattle(server, room);
        }
    }
}

fn roomCommand(server: *AsyncServer, node: *DeferredNode) void {
    const app: *GameApp = @ptrCast(@alignCast(server.app_ctx.?));
    app.processCommand(node.body);  // 进房 / 准备 / 操作
}

fn startBattle(server: *AsyncServer, room: *Room) void {
    const ctx = server.allocator.create(BattleCtx) catch return;
    ctx.blue_team = snapshotTeam(&room.teams[0], server.allocator) catch return;
    ctx.red_team  = snapshotTeam(&room.teams[1], server.allocator) catch return;
    Next.submit(BattleCtx, ctx, doBattle);
}

fn doBattle(ctx: *BattleCtx, complete: *const fn (?*anyopaque, []const u8) void) void {
    const result = simulateCombat(ctx.blue_team, ctx.red_team);
    var buf: [4096]u8 = undefined;
    const json = result.toJson(&buf);
    server.sendDeferredResponse(room_id, 200, .json, json);
    _ = complete;
}

try server.addHookTick(roomTick);        // tick: 每轮 IO 循环必触发
try server.addHookDeferred(roomCommand); // deferred: 每条玩家指令触发一次
```

### Next.go / Next.submit

```zig
Next.go(Ctx, ctx, exec);       // IO 线程 fiber（io_uring I/O）
Next.submit(Ctx, ctx, exec);   // 线程池（卸货）
```

都是静态方法。`Next.go` 开箱即用（首次路由自动 `setDefault`）。`Next.submit` 需要 `server.initPool4NextSubmit(n)`。

#### GPU / 重型计算

GPU 计算用 `Next.submit` — worker 线程调 CUDA / CANN / Vulkan runtime。
io_uring 直连 GPU 受限于 Linux 内核驱动（compute queue 尚未接 `IORING_OP_URING_CMD`，
NVIDIA / 华为还未发布）。

一旦驱动支持，`IORegistry` 零改动接管 GPU — 同一份 `register(id, ptr, on_cqe)` →
提交 SQE → CQE 回调模式。

**当前：fiber + worker 池**

Worker 池始终支持 fiber。GPU 任务提交 kernel 后调 `Fiber.workerYield(poll, ctx)`
释放 worker 线程去处理其他任务，GPU 在后台计算。worker tick 轮询 parked fiber，
kernel 完成后自动 resume。

```zig
// CPU 任务 — 不 yield，跑到结束
Next.submit(CpuCtx, ctx, struct {
    fn exec(c: *CpuCtx, complete: ...) void {
        const result = heavyCompute(c.input);
        complete(c, result);
    }
}.exec);

// GPU 任务 — 提交 kernel 后必须调 workerYield
//                              ↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
Next.submit(GpuCtx, ctx, struct {
    fn exec(c: *GpuCtx, complete: ...) void {
        cudaLaunchKernel(kernel, stream, args);
        Fiber.workerYield(            // ← 这一行决定它是 GPU 任务
            struct { fn poll(s: *anyopaque) bool {
                return cuStreamQuery(@ptrCast(@alignCast(s))) == CUDA_SUCCESS;
            }}.poll,
            @ptrCast(stream),
        );
        // resume 点 — GPU 计算完成
        complete(c, output);
    }
}.exec);
```

**CPU 与 GPU 的唯一区别：** GPU 任务调 `Fiber.workerYield`。
不调这行 = worker 线程同步阻塞等 kernel 结束 = fiber 复用失效。

> ⚠️ **GPU 任务只能用 `Next.submit`，禁止用 `Next.go`。**
>
> `Next.go` 跑在 IO 线程。两种死法：
> - **不调 `workerYield`：** `cuStreamSynchronize` 同步阻塞 IO 线程 —
>   io_uring CQE 停摆，整个服务器冻结。
> - **调了 `workerYield`：** fiber 正常挂起，IO 线程继续跑 — 但 fiber 永远不醒。
>   IO 线程没有 poll tick，只响应 io_uring CQE。GPU kernel 不产生 CQE，
>   所以 IO 线程永远不会知道 kernel 完成了。
>
> Worker 线程有内置 poll tick（`while poll_fn() try resume`），GPU 能工作正是
> 因为这个：`workerYield` → park → tick → poll → resume。

**注意：GPU 推理用 `initPool4NextSubmit(1)`。**
GPU 驱动内置异步执行，1 个 worker + fiber 即可提交 N 个 stream 并轮询完成，
无需额外线程池。

### TinyCache（内建在 RingB 中）

出站连接缓存基石。**由 RingB 持有**——全部生命周期（init、tick、evict、deinit）自动管理。
使用 `HttpClient` 即可免费获得同 host:port 的连接复用。

- 同 host:port 未过期时自动复用 TCP 连接和 Pipe
- 过期条目由 `RingB.tick()` 每轮自动淘汰
- 连接阶段允许重试，读写阶段禁止重试（内核 TCP 栈保证 SQE 级写入）

### Pipe

将 RingSharedClient 的推模型适配为拉模型（`reader.read` / `writer.write`）。
使同步风格的协议库（pgz、myzql）通过 fiber yield/resume 直接跑在 IO 线程——
无需 worker 线程，全程零锁。

### LargeBufferPool

超大报文缓冲池。256KB 共享栈无法容纳的请求（Content-Length > 32KB）由此接管。
每块 1MB，预分配 64 块。O(1) acquire/release，freelist 驱动。每块附带原子
**IDLE/BUSY 状态机** — release 通过 CAS 做幂等释放，防止 io_uring 内核重试
或 TTL 关闭 vs CQE 碰撞路径下的双重释放。

```zig
const LargeBufferPool = @import("sws").LargeBufferPool;

// 64 块 × 1MB = 64MB，AsyncServer 内置
// 在超长报文路径中使用：
const buf = self.large_pool.acquire() orelse return error.OutOfLargeBuffers;
// io_uring READ CQE 直接写 buf.ptr
// ... 处理 body ...
self.large_pool.release(buf);
```

### IO_QUANTUM — Next 任务公平调度

`drainNextTasks` 每轮 IO 循环最多消费 64 个任务（`IO_QUANTUM`），防止深度优先偏向：
handler 中调 `Next.go()` 产生的新任务不会挤占 ReadyQueue 后续就绪任务和 CQE 收割。
P99 尾延迟在高负载下保持均匀。

### Fiber

sws 内置极简 fiber（x86_64 + ARM64 Linux）。所有 handler fiber **共享一块预分配栈**（存储在 `AsyncServer.shared_fiber_stack`，默认 256KB）——顺序执行，无 per-request 分配，零竞争。

> ⚠️ **严禁在 handler 中使用 `std.Io.async()` / `future.await()`。**
>
> Zig 的 `Future` 是**基于线程（thread）设计**，而非基于 fiber：
> - `async()` → `std.Thread.spawn` + 投入 OS 线程池 (`Threaded.zig:2112`)
> - `await()` → `Thread.futexWait` — 阻塞 **OS 线程** (`Threaded.zig:2436`)
>
> 在 IO 线程上阻塞意味着：
> - io_uring CQE 处理停摆——不接收新连接、不读写
> - 整个服务器卡死
>
> ### 为什么不能 patch vtable 让 Future 跑在 fiber 上？
>
> `future.await()` 要求调用者的**栈帧在暂停期间保持存活**：
> ```
> var future = io.async(work, .{data});
> const result = future.await(io);   // fiber 在此 yield — 栈必须保留
> ctx.json(200, result);              // 在此恢复 — 依赖栈上数据
> ```
>
> SWS 使用**共享栈**（一块 256KB buffer，所有 fiber 复用）。当 fiber 在 `await()`
> 中 yield，下一个 fiber 的执行会覆盖同一块内存。恢复后的 fiber 栈帧已损坏。
>
> 换成 per-fiber 独立栈可以解决，但内存代价巨大：
>
> | 并发请求数 | 独立栈 | 共享栈 |
> |---|---:|---:|
> | 1K | 16 MB | 256 KB |
> | 2 万 | 320 MB | 256 KB |
> | 20 万 | 3.2 GB | 256 KB |
> | 100 万 | 16 GB | 256 KB |
>
> *(独立栈按 16KB 计算，HTTP handler 的最低可行值)*
>
> 按生产环境常见的 20 万并发计算，共享栈节省约 3GB 内存。
> 更小的内存占用直接提升系统稳定性和运维可靠性。
>
> 这就是根本取舍：**Future API 的语义 vs. 百万连接的内存模型**。
> SWS 选择了后者。所有异步通过 `Next.go`/`Next.submit` + 回调完成，而非 `await` 式暂停恢复。
> - fiber 是协作式切换，OS 线程是抢占式调度。两者互不兼容。
>
> | Zig 模式 | sws 替代 |
> |---|---|
> | `io.async(cpuWork)` + `future.await(io)` | `Next.submit(Ctx, ctx, exec)` + `DeferredResponse` |
> | `io.async(ioWork)` + `future.await(io)` | `Next.go(Ctx, ctx, exec)`（IO 线程 fiber）|
>
> **用法**：
> ```zig
> // ❌ 不要在 handler 里这样做——阻塞 IO 线程：
> // var future = io.async(heavyWork, .{data});
> // const result = future.await(io);
>
> // ✅ 应该这样——IO 线程永不阻塞：
> fn myHandler(allocator: Allocator, ctx: *Context) anyerror!void {
>     ctx.deferred = true;
>     const resp = try allocator.create(DeferredResponse);
>     resp.* = .{ .server = server, .conn_id = ctx.conn_id, .allocator = allocator };
>     Next.submit(Ctx, .{ .resp = resp, .data = data }, exec);
> }
> ```
>
> 完整 API 见上方 `Next.submit` 章节。

### 路由 / 中间件 / WebSocket / Context

见 `example/` 和 `src/example.zig`。

## 内存模型（目标百万连接）

| 组件 | 大小 | 说明 |
|------|------|------|
| StackSlot（每连接） | 384 字节 | 5 条独立缓存行子结构 |
| StackPool（1M 槽位） | ~384 MB | 连续数组，warmup 预热 |
| Connection hashmap（1M 条目） | ~160 MB | AutoHashMap(u64, Connection) |
| Freelist + live 列表 | ~8 MB | 2 × [1M]u32，O(1) 获取/释放 |
| 读缓冲区（空闲时） | 0 字节 | io_uring 提供缓冲区，空闲时归还 |
| io_uring 读缓冲 slab | 64 MB | 16384 × 4KB 块，内核回收 |
| 分层写缓冲池 | 动态 | 8 个尺寸类别（512B–64KB），freelist 循环复用 |
| 共享 fiber 栈 | 256 KB | 所有 fiber 共用一块预分配栈 |
| LargeBufferPool | 64 MB | 64 × 1MB 超大报文缓冲 |
| **100 万空闲连接** | **~680 MB** | 无线程栈开销 |

和 [greatws](https://github.com/antlabs/greatws) 一样，空闲连接消耗零缓冲内存。

### 缓存行布局原理

384 字节 StackSlot 按独立缓存行拆分：

- **line1（64B）：** fd、gen_id、state、write_offset — CQE 分发只触及此缓存行
- **line2（64B）：** conn_id、last_active_ms、active_list_pos — TTL 扫描只触及此缓存行
- **line3（64B）：** fiber_context、large_buf_ptr — 异步锚点（Worker Pool / 超大报文）
- **line4（128B）：** writev_in_flight、response_buf、write_iovs、WS 队列 — 写路径，不在热路径上
- **line5（64B）：** sentinel + workspace 联合体 — 协议解析暂存，零额外分配

IO 循环最热路径（CQE 分发 → slot 查询）仅触及 line1。TTL 扫描仅触及 line2。不同操作之间无缓存行竞争。

### WebSocket 帧负载拷贝

WS handler 可将帧数据异步卸出，因此帧负载在 handler 返回后仍需有效。**WS 帧负载永不做零拷贝优化**——始终 `dupe` 一份。

**性能影响（100 字节文本帧）：**

| 操作 | 耗时 | 说明 |
|------|------|------|
| memcpy(100B) | ~10ns | 拷贝帧负载 |
| GeneralPurposeAllocator alloc/free | ~100ns | 每帧一次分配释放 |

**每帧额外开销 ~110ns**。1M 连接、1% 活跃、每连接每秒 10 条消息 = 100K msg/s：
- CPU：100K × 110ns = **11ms/s = 1.1% 单核**

## 配置

| key | 默认值 | 说明 |
|-----|--------|------|
| `fiber_stack_size_kb` | 256 | fiber 栈大小（KB），0 自动变 256 |
| `io_cpu` | null | IO 线程绑核 |
| `idle_timeout_ms` | 30000 | 关闭空闲连接 |
| `write_timeout_ms` | 5000 | 写超时关闭连接 |
| `buffer_size` | 4096 | io_uring 缓冲区块大小 |
| `buffer_pool_size` | 16384 | 缓冲区块数量 |
| `max_fixed_files` | 65535 | 注册固定文件槽位数（超出后回退到普通 fd I/O） |

## invokeOnIoThread

任意线程安全回调到 IO 线程执行。

```zig
server.invokeOnIoThread(MyCtx, ctx, struct {
    fn run(allocator, c: *MyCtx) void {
        // IO 线程执行 — 安全访问 ring/registry
        c.client.write("PUB ...");
        allocator.free(c.data);
    }
}.run);
```

底层是 `rs.invoke` (CAS 无锁链表)，`drainTick` 自动清空。

## 进阶：io_uring 原生 DB 连接池

直接把 DB driver 的 TCP fd 接入 io_uring：

```
handler（IO 线程上的 fiber）:
  └── db.query(sql)
        └── io_uring write(fd, query) → CQE → io_uring read(fd) → CQE → 解析
              → ctx.json(200, result)
```

连接池只需维护已连接 TCP fd 集合（ringbuffer 或 free list）。handler 拿 fd → io_uring 发 `write(sql)` + `read()` → 解析结果 → 放回 fd。

## HttpRing + HttpClient（Ring B，内建 TinyCache）

HttpRing（独立 io_uring Ring B）内建 `TinyCache` 连接缓存。`ATTACH_WQ` 共享 Ring A 的内核 io-wq 线程池。同 host:port 连接在 TTL 窗口内自动复用，`RingB.tick()` 每轮自动淘汰过期条目，用
户无需手动管理缓存。

**用法：**

```zig
// Ring B init（1s 缓存 TTL）：
const ring_b = try sws.HttpRing.init(allocator, io, server.ring.fd, 1000);
defer ring_b.deinit();

// HttpClient 自动使用 RingB 内建缓存 — 独立线程驱动
const client = try sws.HttpClient.init(allocator, &ring_b);
try client.start();
defer client.deinit();
const resp = try client.get("http://api.example.com/data");
defer resp.deinit();
```

### c-ares 异步 DNS（可选）

内置 `DnsResolver` 满足基本需求（A 记录 + 缓存）。如需处理截断 UDP（TC 位 → TCP 重试）或 SRV 记录，可切换到 c-ares：

```bash
# Linux
sudo apt install libc-ares-dev

# 源码编译
git clone https://github.com/c-ares/c-ares && cd c-ares
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc) && sudo make install
```

安装后在 `build.zig` 添加链接：

```zig
exe.linkSystemLibrary("cares");
```

切换代码（将 `HttpRing` 的 `DnsResolver` 替换为 `CaresDns`）：

```zig
const HttpCaresDns = sws.HttpCaresDns;
// ring.dns = HttpCaresDns.init(alloc, ring.rs);
```

## License

MIT
