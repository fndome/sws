const std = @import("std");
const linux = std.os.linux;
const IORegistry = @import("io_registry.zig").IORegistry;
const CqeDispatchFn = @import("io_registry.zig").CqeDispatchFn;
const InvokeQueue = @import("io_invoke.zig").InvokeQueue;

/// 单 ring 共享资源。注入到 server 和各 client，一切平等。
pub const RingShared = struct {
    ring: *linux.IoUring,
    registry: *IORegistry,
    invoke: InvokeQueue,

    pub fn bind(ring: *linux.IoUring, registry: *IORegistry) RingShared {
        return .{
            .ring = ring,
            .registry = registry,
            .invoke = .{},
        };
    }

    /// Re-point ring/registry after the owning struct has moved to its final
    /// address (e.g. AsyncServer/RingB are returned by value, so a bind() done
    /// inside init stores pointers to the init frame). Preserves invoke (which
    /// may already hold cross-thread items).
    pub fn rebind(self: *RingShared, ring: *linux.IoUring, registry: *IORegistry) void {
        self.ring = ring;
        self.registry = registry;
    }

    /// 获取 ring。ring 未开启 SINGLE_ISSUER，可跨线程 submit（server 的
    /// connect 在 main、run 在 IO 线程；RingB 的 init 在 setup、驱动在 client
    /// 线程），因此这里不做单线程断言。
    pub fn ringPtr(self: *const RingShared) *linux.IoUring {
        return self.ring;
    }

    /// 获取 registry。register/remove 合法地在 init/deinit（setup）线程与
    /// IO 线程之间先后发生（init 在 start 前、deinit 在 join 后），并非并发。
    pub fn registryPtr(self: *const RingShared) *IORegistry {
        return self.registry;
    }

    pub fn allocUserData(self: *const RingShared) u64 {
        return self.registryPtr().allocUserData();
    }

    pub fn register(self: *const RingShared, ud: u64, ptr: *anyopaque, cb: CqeDispatchFn) !void {
        try self.registryPtr().register(ud, ptr, cb);
    }

    pub fn remove(self: *const RingShared, ud: u64) void {
        self.registryPtr().remove(ud);
    }

    pub fn alloc(self: *const RingShared, ptr: *anyopaque, cb: CqeDispatchFn) !u64 {
        const ud = self.registryPtr().allocUserData();
        try self.registryPtr().register(ud, ptr, cb);
        return ud;
    }
};
