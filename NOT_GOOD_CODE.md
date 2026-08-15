# NOT_GOOD_CODE.md

本项目（`sws`）代码风格审查记录。以下列出可复现、带定位的「不良编码习惯」，按类别归类，并给出改进建议。非 bug 清单，而是可维护性/一致性层面的问题。

---

## 1. 魔法数字（Magic Numbers）

### 1.1 io_uring opcode 直接硬编码数字（并已导致实际错误）

opcode 用 `@enumFromInt(N)` 硬编码，只有行尾注释说明。更糟的是，有两处的数字与注释、与实际枚举值对不上——这是魔数写法直接造成的 bug。

`linux.IORING_OP`（Zig 0.16 `std/os/linux.zig:6605`）实际顺序：`CONNECT=16, CLOSE=19, LINK_TIMEOUT=15, RECVMSG=10, RECV=27, OPENAT2=28`。

| 位置 | 代码写 | 注释声称 | 实际枚举值 | 结论 |
|---|---|---|---|---|
| `src/shared/tcp_stream.zig:196` | `@enumFromInt(27)` | `IORING_OP_CONNECT` | `RECV` | ❌ 疑似 bug（应为 16=CONNECT） |
| `src/dns/resolver.zig:207` | `@enumFromInt(28)` | `IORING_OP_RECV` | `OPENAT2` | ❌ 疑似 bug（应为 27=RECV） |
| `src/shared/tcp_stream.zig:206` | `@enumFromInt(15)` | `IORING_OP_LINK_TIMEOUT` | `LINK_TIMEOUT` | ✓ |
| `src/http/connection_mgr.zig:166` | `@enumFromInt(19)` | （无注释） | `CLOSE` | ✓ |
| `src/udp/server.zig:145` | `@enumFromInt(10)` | （无注释） | `RECVMSG` | ✓ |

建议：改用 `linux.IORING_OP.CONNECT` / `.RECV` 等命名枚举，或直接用 std 库的 `prep_connect` / `prep_recv` / `prep_close` / `prep_link_timeout`（`io_uring_sqe.zig` 已提供），彻底消除手写数字。

> 注：其中两处错误（`tcp_stream` 的 CONNECT、`resolver` 的 RECV）已在本轮修复为命名枚举；这也正是魔数写法的直接代价——两个 opcode 值写错后，出站 connect 与 DNS 收包实际从未正确工作。

### 1.2 魔数 Tag / 哨兵（无定义、无文档）

- `0x48540001`（"HT"+ver）——`HttpTaskCtx.tag`：`http_fiber.zig:34,167,209`、`http_routing.zig:463`、`tcp_read.zig:627`
- `0x57530001`（"WS"+ver）——`WsTaskCtx.tag`：`fiber_task.zig:23,34,60`、`ws_handler.zig:357`
- `0x53574153`（"SWAS" 小端）——slot 越界哨兵：`stack_pool.zig:48,194`、`stack_pool_sticker.zig:67,259`

这些魔数散落多处、靠 `std.debug.assert` 比对，缺少命名常量与说明（"HT"/"WS" 缩写含义在代码里找不到）。

> ✅ 已修复：新增 `HTTP_TASK_TAG` / `WS_TASK_TAG` / `WORKSPACE_SENTINEL` 命名常量并全局替换。

### 1.3 语义重复的 `0xFFFF` / `0xFFFFFFFF` 哨兵

同一值在不同字段里含义不同，极易混淆：

- `Connection.fixed_index: u16 = 0xFFFF`（"未注册 fixed file"）
- `Connection.pool_idx: u32 = 0xFFFFFFFF`（"未入池"）
- `Connection.active_list_pos: u32 = 0xFFFFFFFF`（"不在 live 表"）
- `slotAlloc` 返回 `.idx = 0xFFFFFFFF`（"池满"）

这些哨兵没有各自的命名常量，全文靠 `!= 0xFFFFFFFF` / `!= 0xFFFF` 字面量判断（见第 3 节）。

> ✅ 已修复：新增 `NO_FIXED_FILE` / `NO_POOL_SLOT` / `NO_LIVE_POS` 命名常量并全局替换（`ws/frame.zig` 的 `0xFFFF` 是 WS 帧长度分界，非哨兵，保持原样）。

### 1.4 散落的硬编码常量

`512`（ttlScan 窗口，`stack_pool_sticker.zig:119` 调用点）、`16384`/`4096`（buffer 大小）、`64`（IO_QUANTUM）、`max_ciphertext = 16384 + 2048`（`tcp_write.zig:229`）等，部分已收进 `constants.zig`，部分仍散落在逻辑里（如 `tcp_stream.zig` 的 `CLIENT_READ_BUF = 16384`）。

---

## 2. 错误处理反模式

### 2.1 `catch {}` 静默吞错

大量错误被静默丢弃，出问题时无日志无痕迹：

- `src/dns/resolver.zig:177,185,213,281` —— `cache.put(...) catch {}`、`ring.submit() catch {}`、`results.put(...) catch {}`
- `src/shared/ring_shared.zig`（`tcp_stream.zig:202,216,562`）—— `_ = ring.submit() catch {}`
- `src/client/ring.zig:107`、`src/client/http_client.zig:449` —— `submit() catch {}`
- `src/http/connection_mgr.zig:149`、`tcp_accept.zig:96`、`tcp_handler.zig:66` —— `register_files_update(...) catch {}`
- `src/stack_pool_sticker.zig:160` —— TTL 扫描 `out.append(...) catch {}`（扫描结果静默丢失）
- `src/async_logger.zig:50` —— `sched_setaffinity catch {}`

部分地方有注释说明「非致命」，但多数没有；`ring.submit() catch {}` 在 SQ 满/失败时会让请求静默挂起。

### 2.2 生产路径用 `@panic("OOM")`

初始化/构造路径对 OOM 直接 panic，而非返回 error 让调用方决定：

- `src/client/tiny_cache.zig:35`
- `src/http/async_server.zig:374`（`ttl_scan_out` initCapacity 512）
- `src/next/next.zig:298,305`
- `src/next/queue.zig:36`

建议统一返回 `error.OutOfMemory`，由最外层决定策略。

### 2.3 生产代码用 `catch unreachable`

- `src/next/pipe.zig:95,104` —— `read_buf.replaceRange(...) catch unreachable`

`replaceRange` 在 shrink 时理论上可能分配失败，这里假定绝不失败，风险未注释充分。

### 2.4 `_ = ... catch {}` / `catch null` 混合忽略

- `ws_handler.zig:71` —— `dupe(u8, token) catch null`（升级失败静默无 token）
- `http_client.zig:330` —— `p.feed(data) catch {}`
- `http_fiber.zig:74,112,121,124,128` —— `ctx.text(...) catch {}`

---

## 3. 重复代码（Duplication）

### 3.1 `pool_idx != 0xFFFFFFFF` / `fixed_index != 0xFFFF` 守卫重复数百次

`if (conn.pool_idx != 0xFFFFFFFF) { ... }` 与 `if (conn.fixed_index != 0xFFFF) ...` 在几乎每个读写路径重复出现（`tcp_write.zig`、`tcp_read.zig`、`ws_handler.zig`、`tcp_handler.zig`、`http_body.zig` 等共约 70+ 处）。

建议：封装 `Connection.hasPoolSlot()` / `poolSlot(conn) ?*StackSlot` 之类的访问器，把哨兵判断收敛到一处。

### 3.2 四个写完成处理器高度雷同

`onWriteComplete` / `onTlsWriteComplete`（`tcp_write.zig`）、`onWsWriteComplete`（`ws_handler.zig`）、`onTcpWriteComplete`（`tcp_handler.zig`）各自重复：

- `write_offset += res` + `write_retries` 上限判断
- `writev_in_flight` 清零
- `response_buf` 释放
- keep-alive 分支里 `write_start_ms` / `last_active_ms` / `submitRead` 的重复（本次排查中我正是因为这四处重复才需要挨个修同一处 bug）

建议：抽一个共用的 `completeWrite(self, conn_id, conn, res, is_tls) bool` 或状态机。

### 3.3 `markReplenish` 的 `read_bid != sentinel` 守卫重复

`closeConn`（`connection_mgr.zig:50`）、`httpTaskRecycle`（`http_fiber.zig:175`）、`wsTaskRecycle`（`fiber_task.zig:40`）三处语义完全一致，靠注释复制粘贴保证同步。

---

## 4. 命名与注释一致性

### 4.1 中英注释混用

`修改原因：...`（中文）与英文注释在同一文件、同一函数内混排。例如 `tcp_read.zig` 有 22 处 `修改原因`，`http_client.zig` 35 处，而其余大量是英文注释。

建议：统一一种语言，或明确「`修改原因` 用于解释非显而易见的历史决策」这一约定（目前是半自觉的）。

### 4.2 `blk:` 标签滥用

复杂内联块用 `blk:` 标签在 if/else 中拼表达式，可读性差：

- `tcp_stream.zig:132` —— `break :blk dns.resolve(host) catch return ...`
- `http_client.zig:114` —— `break :blk std.fmt.parseInt(...) catch return ...`
- `tcp_read.zig:147-148` —— 带 `blk:` 的 `break :blk hw.pending_len > 0 and ...`

建议：抽出带名字的辅助函数，替代内联 `blk:`。

### 4.3 `@ptrCast(@alignCast(...))` / `@intFromPtr` 泛滥

堆指针与 `u64`/`u32` 互转大量使用（`stack_pool_sticker.zig` 的 `line3.pending_buffer_ptr`、`stream_ptr`、`large_buf_ptr` 等），缺乏类型安全封装，靠注释约束「谁持有谁释放」。

---

## 5. 大文件与职责

### 5.1 巨型单文件

| 文件 | 行数 |
|---|---|
| `src/client/http_client.zig` | 1088 |
| `src/http/tcp_read.zig` | 705 |
| `src/http/async_server.zig` | 705 |
| `src/shared/tcp_stream.zig` | 608 |
| `src/http/ws_handler.zig` | 579 |
| `src/http/http_routing.zig` | 556 |
| `src/next/next.zig` | 547 |

`tcp_read.zig` 的 `onReadComplete` 一个函数就承载了读完成、TLS 解密、header 重组、body 分派、流式读等职责；`async_server.zig` 混有 struct 定义、init/deinit、路由注册、udp/tcp/ws 入口。

建议：按职责拆分（read 解析 vs body 流 vs 路由 vs 生命周期）。

### 5.2 `getReadBuf(bid)` 依赖 `assert(bid < block_count)`

`buffer_pool.zig:70` 用断言保护越界，而调用方传入的 bid 来自 CQE，理论上应保证有效；但 sentinel（`0xFFFF`）一旦误传入会直接 panic。建议对非热路径做显式校验。

---

## 6. 其它

### 6.1 测试覆盖不均衡

`tcp_read.zig`、`http_client.zig`、`stack_pool_sticker.zig` 测试较多，但 `ws_handler.zig`、`tcp_stream.zig`、`next/`、`dns/resolver.zig` 的核心状态机（帧分片、连接状态迁移、DNS 超时重试）几乎没有单元测试；且测试二进制只能跨编译到 linux-musl、无法在 Windows 本机运行（见 `build.zig`），导致多数测试在日常开发中跑不起来。

### 6.2 `errdefer` 链的脆弱性

`async_server.zig:init` 里存在长达数层的 `errdefer`（`allocator.destroy(dns_resolver)` + `dns_resolver.deinit()` 等），依赖 reverse-order 语义保证顺序，缺注释时易在新增资源时插错位置（本次排查的 DNS rebind 边界即源自此）。

### 6.3 同值不同义的 `0xFFFF` 边界（非哨兵）

`src/ws/frame.zig:33` `if (payload_len <= 0xFFFF) return error.InvalidFrame;` 与 `frame.zig:160/201` 用 `0xFFFF` 作为 WS payload 长度边界（125/65535 分界），与第 1.3 节的哨兵语义无关，却用了同一个字面量，易误读为「未初始化」哨兵。

---

## 总结（优先改进顺序）

1. **去掉静默吞错**（`catch {}` → 至少 log），尤其是 `ring.submit()` / TTL `append`。
2. **收敛哨兵与守卫**：`pool_idx`/`fixed_index`/`active_list_pos` 各建命名常量 + 访问器，消除 ~70 处重复判断。
3. **opcode / Tag 魔数命名化**，`@enumFromInt(27)` 之类全部换成常量。
4. **合并四个写完成处理器**，避免同一 bug 修四处（本次已踩）。
5. **`@panic("OOM")` / `catch unreachable` 改为 error 传播**。
6. 统一注释语言；拆分 `tcp_read.zig` / `http_client.zig` 等巨型文件。
