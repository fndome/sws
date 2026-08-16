const std = @import("std");
const linux = std.os.linux;
const IORegistry = @import("io_registry.zig").IORegistry;
const CqeDispatchFn = @import("io_registry.zig").CqeDispatchFn;
const InvokeQueue = @import("io_invoke.zig").InvokeQueue;

/// Shared resources for a single ring. Injected into the server and every client alike.
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

    /// Get the ring. The ring does not enable SINGLE_ISSUER, so it can submit across threads (the server's
    /// connect runs on main while run runs on the IO thread; RingB's init is in setup and its driver on the client
    /// thread), so no single-thread assertion is made here.
    pub fn ringPtr(self: *const RingShared) *linux.IoUring {
        return self.ring;
    }

    /// Get the registry. register/remove legitimately happen between the init/deinit (setup) thread and
    /// the IO thread in sequence (init before start, deinit after join), not concurrently.
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
