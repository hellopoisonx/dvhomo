//! Linux system integration.
//!
//! `polkit` talks to the PolicyKit authority over D-Bus with goose. An
//! authorization request with `allow_user_interaction` is handed by polkitd to
//! the authentication agent registered for the subject's session, and that
//! agent raises the password prompt.
//!
//! `systemd` drives the system manager on the same connection: `StartUnit`
//! launches a unit under the manager's privileged identity instead of as a
//! child of this unprivileged process. The caller still owns the bus
//! connection.

const std = @import("std");
const goose = @import("goose");

const GStr = goose.core.value.GStr;
const GPath = goose.core.value.GPath;
const GVariant = goose.core.value.GVariant;

/// Opens a private connection to the system bus, where polkitd and the system
/// manager live.
pub fn connectSystemBus(
    allocator: std.mem.Allocator,
    io: std.Io,
    environ_map: *std.process.Environ.Map,
) !goose.Connection {
    return goose.Connection.init(allocator, .System, io, environ_map);
}

pub const polkit = struct {
    pub const bus_name: [:0]const u8 = "org.freedesktop.PolicyKit1";
    pub const object_path: [:0]const u8 = "/org/freedesktop/PolicyKit1/Authority";
    pub const authority_interface: [:0]const u8 = "org.freedesktop.PolicyKit1.Authority";

    /// `org.freedesktop.PolicyKit1.Authority.CheckAuthorization` flags.
    pub const Flags = struct {
        pub const none: u32 = 0;
        /// Lets polkitd invoke the registered authentication agent.
        pub const allow_user_interaction: u32 = 1;
    };

    /// Subject the authorization applies to. Polkit pairs `process` with the
    /// boot-relative start time so a recycled pid cannot inherit a decision.
    pub const Subject = union(enum) {
        process: Process,
        session: []const u8,
        system_bus_name: []const u8,

        pub const Process = struct {
            pid: u32,
            /// Field 22 of `/proc/<pid>/stat` (clock ticks since boot).
            start_time: u64,
        };
    };

    /// `a{ss}` details forwarded to the authority (`polkit.caller-pid`, ...).
    pub const Detail = struct {
        key: []const u8,
        value: []const u8,
    };

    pub const Request = struct {
        action_id: [:0]const u8,
        details: []const Detail = &.{},
        flags: u32 = Flags.allow_user_interaction,
        cancellation_id: [:0]const u8 = "",
    };

    /// `(bba{ss})` reply of `CheckAuthorization`.
    pub const Decision = struct {
        authorized: bool,
        /// True when authentication could still be attempted, i.e. the action
        /// is not unconditionally denied.
        challenge: bool,
        details: std.StringHashMap(GStr),

        arena: *std.heap.ArenaAllocator,
        allocator: std.mem.Allocator,

        pub fn deinit(self: *Decision) void {
            self.details.deinit();
            self.arena.deinit();
            self.allocator.destroy(self.arena);
            self.* = undefined;
        }
    };

    pub fn processSubject(pid: u32, start_time: u64) Subject {
        return .{ .process = .{ .pid = pid, .start_time = start_time } };
    }

    /// Subject for the calling process, read from `/proc/self/stat`.
    pub fn selfProcessSubject(io: std.Io) !Subject {
        return processSubject(@intCast(std.os.linux.getpid()), try selfStartTime(io));
    }

    /// Subject for the logind session in `XDG_SESSION_ID`. Prefer this when the
    /// authorization is for the whole session instead of one process.
    pub fn sessionSubject(environ_map: *const std.process.Environ.Map) !Subject {
        const session_id = environ_map.get("XDG_SESSION_ID") orelse return error.SessionIdNotSet;
        return .{ .session = session_id };
    }

    /// Checks `action_id` for `subject`, letting polkitd call the session
    /// authentication agent. Blocks until the agent finishes authenticating.
    pub fn requestAuthorization(
        allocator: std.mem.Allocator,
        conn: *goose.Connection,
        subject: Subject,
        action_id: [:0]const u8,
        details: []const Detail,
    ) !Decision {
        return checkAuthorization(allocator, conn, subject, .{
            .action_id = action_id,
            .details = details,
            .flags = Flags.allow_user_interaction,
        });
    }

    pub fn checkAuthorization(
        allocator: std.mem.Allocator,
        conn: *goose.Connection,
        subject: Subject,
        request: Request,
    ) !Decision {
        // Wire values borrow from this arena; they must outlive the call only.
        var scratch = std.heap.ArenaAllocator.init(allocator);
        defer scratch.deinit();

        const wire = try buildWire(scratch.allocator(), subject, request);
        const proxy = goose.proxy.Proxy.init(conn, bus_name, object_path, authority_interface);

        var reply = try proxy.call("CheckAuthorization", callArgs(wire));
        defer reply.deinit();

        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();

        var decoder = goose.message.BodyDecoder.fromMessage(arena.allocator(), reply.msg);
        const raw = try decoder.decodeAlloc(DecisionWire);

        return .{
            .authorized = raw.authorized,
            .challenge = raw.challenge,
            .details = raw.details,
            .arena = arena,
            .allocator = allocator,
        };
    }

    const WireSubject = struct {
        kind: GStr,
        details: std.StringHashMap(GVariant),
    };

    const Wire = struct {
        subject: WireSubject,
        action_id: GStr,
        details: std.StringHashMap(GStr),
        flags: u32,
        cancellation_id: GStr,
    };

    const CallArgs = @Tuple(&.{ WireSubject, GStr, std.StringHashMap(GStr), u32, GStr });
    const DecisionWire = struct {
        authorized: bool,
        challenge: bool,
        details: std.StringHashMap(GStr),
    };

    fn callArgs(wire: Wire) CallArgs {
        return .{ wire.subject, wire.action_id, wire.details, wire.flags, wire.cancellation_id };
    }

    fn buildWire(allocator: std.mem.Allocator, subject: Subject, request: Request) !Wire {
        var subject_details = std.StringHashMap(GVariant).init(allocator);
        errdefer subject_details.deinit();

        const kind: GStr = switch (subject) {
            .process => |p| blk: {
                try subject_details.put("pid", .{ .uint32 = p.pid });
                try subject_details.put("start-time", .{ .uint64 = p.start_time });
                break :blk GStr.new("unix-process");
            },
            .session => |id| blk: {
                try subject_details.put("session-id", .{ .string = GStr.new(try allocator.dupeSentinel(u8, id, 0)) });
                break :blk GStr.new("unix-session");
            },
            .system_bus_name => |name| blk: {
                try subject_details.put("name", .{ .string = GStr.new(try allocator.dupeSentinel(u8, name, 0)) });
                break :blk GStr.new("system-bus-name");
            },
        };

        var action_details = std.StringHashMap(GStr).init(allocator);
        errdefer action_details.deinit();
        for (request.details) |detail| {
            try action_details.put(detail.key, GStr.new(try allocator.dupeSentinel(u8, detail.value, 0)));
        }

        return .{
            .subject = .{ .kind = kind, .details = subject_details },
            .action_id = GStr.new(request.action_id),
            .details = action_details,
            .flags = request.flags,
            .cancellation_id = GStr.new(request.cancellation_id),
        };
    }

    fn selfStartTime(io: std.Io) !u64 {
        var buffer: [1024]u8 = undefined;
        const stat = try std.Io.Dir.cwd().readFile(io, "/proc/self/stat", &buffer);
        return parseStartTime(stat);
    }

    /// `stat` is `/proc/<pid>/stat`; `comm` may contain spaces and ')'.
    fn parseStartTime(stat: []const u8) !u64 {
        const comm_end = std.mem.lastIndexOfScalar(u8, stat, ')') orelse return error.InvalidProcStat;
        var fields = std.mem.tokenizeScalar(u8, stat[comm_end + 1 ..], ' ');
        var index: usize = 3; // First token after comm is field 3 (state).
        while (fields.next()) |field| : (index += 1) {
            if (index == 22) return std.fmt.parseInt(u64, field, 10);
        }
        return error.InvalidProcStat;
    }
};

pub const systemd = struct {
    pub const bus_name: [:0]const u8 = "org.freedesktop.systemd1";
    pub const object_path: [:0]const u8 = "/org/freedesktop/systemd1";
    pub const manager_interface: [:0]const u8 = "org.freedesktop.systemd1.Manager";
    pub const unit_interface: [:0]const u8 = "org.freedesktop.systemd1.Unit";
    pub const service_interface: [:0]const u8 = "org.freedesktop.systemd1.Service";
    pub const properties_interface: [:0]const u8 = "org.freedesktop.DBus.Properties";

    /// Action the manager checks in polkit before `StartUnit` / `StopUnit`.
    /// `allow_active` is `auth_admin_keep`, so one interactive authorization
    /// covers the following start *and* stop of the session.
    pub const manage_units_action: [:0]const u8 = "org.freedesktop.systemd1.manage-units";

    /// Unit `ActiveState` values that are meaningful without the coupled
    /// `SubState`. `std.meta.stringToEnum` matches systemd's spelling, so the
    /// field names must stay verbatim.
    pub const ActiveState = enum {
        active,
        activating,
        deactivating,
        failed,
        inactive,
        reloading,
        unknown,

        /// Maps a `Get` reply that names a state this client does not know
        /// (systemd grows new ones) instead of failing.
        pub fn parse(name: []const u8) ActiveState {
            return std.meta.stringToEnum(ActiveState, name) orelse .unknown;
        }
    };

    pub const Status = struct {
        active_state: ActiveState,
        /// `MainPID`; 0 when the unit has no main process.
        main_pid: u32,
    };

    /// How long a start/stop may take before the caller is handed the state it
    /// settled on. `Restart=`/`ExecStartPre=` make short waits common.
    const settle_timeout_ms: u32 = 15_000;
    const settle_poll_ms: u32 = 100;

    const Settle = enum { started, stopped };

    /// Asks the manager to start `name` and waits until the unit settles on
    /// `active`, `failed` or `inactive`. The manager replies with a job, not
    /// with the finished state, so the wait is the interesting part.
    pub fn startUnit(
        allocator: std.mem.Allocator,
        conn: *goose.Connection,
        io: std.Io,
        name: [:0]const u8,
    ) !Status {
        const manager = goose.proxy.Proxy.init(conn, bus_name, object_path, manager_interface);
        var reply = try manager.call("StartUnit", .{ GStr.new(name), GStr.new("replace") });
        reply.deinit();

        return settle(allocator, conn, io, name, .started);
    }

    pub fn stopUnit(
        allocator: std.mem.Allocator,
        conn: *goose.Connection,
        io: std.Io,
        name: [:0]const u8,
    ) !Status {
        const manager = goose.proxy.Proxy.init(conn, bus_name, object_path, manager_interface);
        var reply = try manager.call("StopUnit", .{ GStr.new(name), GStr.new("replace") });
        reply.deinit();

        return settle(allocator, conn, io, name, .stopped);
    }

    pub fn status(
        allocator: std.mem.Allocator,
        conn: *goose.Connection,
        name: [:0]const u8,
    ) !Status {
        // Property values are decoded into this scratch arena and copied out
        // as plain values, so nothing outlives the call.
        var scratch = std.heap.ArenaAllocator.init(allocator);
        defer scratch.deinit();

        const path = try unitObjectPath(scratch.allocator(), conn, name);

        return .{
            .active_state = switch (try getProperty(scratch.allocator(), conn, path, unit_interface, "ActiveState")) {
                .string => |value| ActiveState.parse(value.s),
                else => return error.UnexpectedPropertyType,
            },
            // `MainPID` lives on the type-specific interface, not on `Unit`.
            .main_pid = switch (try getProperty(scratch.allocator(), conn, path, service_interface, "MainPID")) {
                .uint32 => |pid| pid,
                else => return error.UnexpectedPropertyType,
            },
        };
    }

    /// Raises the session authentication agent for `manage_units_action`, which
    /// is what makes the following `StartUnit` privileged rather than denied.
    /// Blocks until the agent finishes; polkitd then caches the authorization
    /// for the session (`auth_admin_keep`).
    pub fn authorizeManageUnits(
        allocator: std.mem.Allocator,
        conn: *goose.Connection,
        io: std.Io,
        environ_map: *const std.process.Environ.Map,
    ) !void {
        // A session subject lets the cached authorization apply to every
        // process of the session, which is how the manager re-checks us.
        const subject = polkit.sessionSubject(environ_map) catch try polkit.selfProcessSubject(io);

        var decision = try polkit.requestAuthorization(allocator, conn, subject, manage_units_action, &.{});
        defer decision.deinit();

        if (!decision.authorized) return error.NotAuthorized;
    }

    fn settle(
        allocator: std.mem.Allocator,
        conn: *goose.Connection,
        io: std.Io,
        name: [:0]const u8,
        wanted: Settle,
    ) !Status {
        var waited_ms: u32 = 0;
        while (true) {
            const current = try status(allocator, conn, name);
            switch (wanted) {
                .started => switch (current.active_state) {
                    .active, .failed, .inactive => return current,
                    else => {},
                },
                .stopped => switch (current.active_state) {
                    // `failed` is where a crashing unit sits before `StopUnit`
                    // moves it on, so only `inactive` means the stop landed.
                    .inactive => return current,
                    else => {},
                },
            }
            if (waited_ms >= settle_timeout_ms) return current;

            try std.Io.sleep(io, .fromMilliseconds(settle_poll_ms), .awake);
            waited_ms += settle_poll_ms;
        }
    }

    /// Resolves the unit's object path. `LoadUnit` (not `GetUnit`) is what
    /// `systemctl` uses too: units are loaded lazily, so a never-started unit
    /// is absent from the manager until it is asked for by name.
    fn unitObjectPath(
        allocator: std.mem.Allocator,
        conn: *goose.Connection,
        name: [:0]const u8,
    ) ![:0]const u8 {
        const manager = goose.proxy.Proxy.init(conn, bus_name, object_path, manager_interface);
        var reply = try manager.call("LoadUnit", .{GStr.new(name)});
        defer reply.deinit();

        var decoder = goose.message.BodyDecoder.fromMessage(allocator, reply.msg);
        const path = try decoder.decode(GPath);
        return try allocator.dupeSentinel(u8, path.s, 0);
    }

    /// `org.freedesktop.DBus.Properties.Get`; `interface` is the one that
    /// declares the property, since systemd spreads them over several
    /// interfaces of the same object.
    fn getProperty(
        allocator: std.mem.Allocator,
        conn: *goose.Connection,
        path: [:0]const u8,
        interface: [:0]const u8,
        name: [:0]const u8,
    ) !GVariant {
        const properties = goose.proxy.Proxy.init(conn, bus_name, path, properties_interface);
        var reply = try properties.call("Get", .{ GStr.new(interface), GStr.new(name) });
        defer reply.deinit();

        var decoder = goose.message.BodyDecoder.fromMessage(allocator, reply.msg);
        return decoder.decodeAlloc(GVariant);
    }
};

test "CheckAuthorization wire signature" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const wire = try polkit.buildWire(arena.allocator(), polkit.processSubject(77, 424242), .{
        .action_id = "org.example.Test",
        .details = &.{.{ .key = "polkit.caller-pid", .value = "77" }},
    });
    var encoder = try goose.message.BodyEncoder.encode(arena.allocator(), polkit.callArgs(wire));
    defer encoder.deinit();

    try std.testing.expectEqualStrings("(sa{sv})sa{ss}us", encoder.signature());
}

test "subjects encode their kind and detail variants" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const process_wire = try polkit.buildWire(arena.allocator(), polkit.processSubject(77, 424242), .{
        .action_id = "org.example.Test",
    });
    try std.testing.expectEqualStrings("unix-process", process_wire.subject.kind.s);
    try std.testing.expectEqual(@as(u32, 77), process_wire.subject.details.get("pid").?.uint32);
    try std.testing.expectEqual(@as(u64, 424242), process_wire.subject.details.get("start-time").?.uint64);

    const session_wire = try polkit.buildWire(arena.allocator(), .{ .session = "3" }, .{
        .action_id = "org.example.Test",
    });
    try std.testing.expectEqualStrings("unix-session", session_wire.subject.kind.s);
    try std.testing.expectEqualStrings("3", session_wire.subject.details.get("session-id").?.string.s);

    const name_wire = try polkit.buildWire(arena.allocator(), .{ .system_bus_name = ":1.42" }, .{
        .action_id = "org.example.Test",
    });
    try std.testing.expectEqualStrings("system-bus-name", name_wire.subject.kind.s);
    try std.testing.expectEqualStrings(":1.42", name_wire.subject.details.get("name").?.string.s);
}

test "start time is field 22 after a comm containing parentheses" {
    const stat = "42 (weird ) name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 99";
    try std.testing.expectEqual(@as(u64, 424242), try polkit.parseStartTime(stat));
    try std.testing.expectError(error.InvalidProcStat, polkit.parseStartTime("42 (short) S 1 2"));
}

test "active state names are systemd's verbatim strings" {
    const cases = .{
        .{ "active", systemd.ActiveState.active },
        .{ "activating", systemd.ActiveState.activating },
        .{ "deactivating", systemd.ActiveState.deactivating },
        .{ "failed", systemd.ActiveState.failed },
        .{ "inactive", systemd.ActiveState.inactive },
        .{ "reloading", systemd.ActiveState.reloading },
        .{ "maintenance", systemd.ActiveState.unknown },
    };
    inline for (cases) |case| {
        try std.testing.expectEqual(case[1], systemd.ActiveState.parse(case[0]));
    }
}
