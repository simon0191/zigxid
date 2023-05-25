const std = @import("std");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    var now = std.time.timestamp();
    try stdout.print("now: {d}\n", .{now});
    //1684965100
    //16849651000
    for (0..5) |i| {
        var xid = New();
        try stdout.print("{d}: count: {d}, {s}\n", .{ i, xid.counter(), xid.toStr().* });
    }
}

///////////
// Types //
///////////

pub const xid_str_t = [20:0]u8;
const id_t = [12]u8;

/////////////
// Globals //
/////////////

const encoding = "0123456789abcdefghijklmnopqrstuv";
// dec is the decoding map for base32 encoding
var maybe_dec: ?[256]u8 = null;
var maybe_id_counter: ?std.atomic.Atomic(u32) = null;
var maybe_host_id: ?u32 = null;
var maybe_pid: ?u32 = null;

////////////
// Errors //
////////////

const Error = error{
    InvalidXidString,
};

//////////////////
// Constructors //
//////////////////

pub fn New() Xid {
    var now = std.time.timestamp();
    return NewWithTime(@bitCast(u32, @truncate(i32, now)));
}

pub fn NewWithTime(ts_in_secs: u32) Xid {
    var id: id_t = undefined;
    // std.debug.print("ts_in_secs: {d} | ", .{ts_in_secs});
    // 4 bytes from timestamp
    id[0] = @truncate(u8, ts_in_secs >> 24);
    id[1] = @truncate(u8, ts_in_secs >> 16);
    id[2] = @truncate(u8, ts_in_secs >> 8);
    id[3] = @truncate(u8, ts_in_secs);

    // 3 bytes from the machine ID
    const host_id: u32 = getHostId();
    id[4] = @truncate(u8, host_id >> 24);
    id[5] = @truncate(u8, host_id >> 16);
    id[6] = @truncate(u8, host_id);

    // 2 bytes from the process ID
    // since PIDs tend to be small numbers, we'll use the lower 2 bytes
    const pid: u32 = getPid();
    id[7] = @truncate(u8, pid >> 8);
    id[8] = @truncate(u8, pid);

    // 3 bytes from the counter
    if (maybe_id_counter == null) {
        // TODO: initialize counter with random number atomically
        var rand_gen = std.rand.DefaultPrng.init(@bitCast(u64, std.time.microTimestamp()));
        const random = rand_gen.random();
        var rand_int = random.int(u24);
        std.debug.print("rand_int: {d}\n", .{rand_int});
        maybe_id_counter = std.atomic.Atomic(u32).init(rand_int);
    }
    var prev_counter: u24 = 0;
    if (maybe_id_counter) |*id_counter| {
        prev_counter = @truncate(u24, id_counter.fetchAdd(1, .Monotonic));
    }
    std.debug.print("prev_counter: {d} | ", .{prev_counter});
    id[9] = @truncate(u8, prev_counter >> 16);
    id[10] = @truncate(u8, prev_counter >> 8);
    id[11] = @truncate(u8, prev_counter);

    return Xid{ .id = id };
}

pub fn NewFromBytes(bytes: id_t) Xid {
    return Xid{ .id = bytes };
}

// encode by unrolling the stdlib base32 algorithm + removing all safe checks
pub fn NewFromString(src: xid_str_t) Error!Xid {
    if (maybe_dec == null) {
        maybe_dec = std.mem.zeroes([256]u8);
        for (0..@sizeOf(encoding)) |i| {
            maybe_dec[encoding[i]] = i;
        }
    }
    var id = std.mem.zeroes(id_t);
    var dec = maybe_dec.?;

    id[11] = dec[src[17]] << 6 | dec[src[18]] << 1 | dec[src[19]] >> 4;
    // check the last byte
    if (encoding[(id[11] << 4) & 0x1F] != src[19]) {
        return Error.InvalidXidString;
    }
    id[10] = dec[src[16]] << 3 | dec[src[17]] >> 2;
    id[9] = dec[src[14]] << 5 | dec[src[15]];
    id[8] = dec[src[12]] << 7 | dec[src[13]] << 2 | dec[src[14]] >> 3;
    id[7] = dec[src[11]] << 4 | dec[src[12]] >> 1;
    id[6] = dec[src[9]] << 6 | dec[src[10]] << 1 | dec[src[11]] >> 4;
    id[5] = dec[src[8]] << 3 | dec[src[9]] >> 2;
    id[4] = dec[src[6]] << 5 | dec[src[7]];
    id[3] = dec[src[4]] << 7 | dec[src[5]] << 2 | dec[src[6]] >> 3;
    id[2] = dec[src[3]] << 4 | dec[src[4]] >> 1;
    id[1] = dec[src[1]] << 6 | dec[src[2]] << 1 | dec[src[3]] >> 4;
    id[0] = dec[src[0]] << 3 | dec[src[1]] >> 2;

    return NewFromBytes(id);
}

/////////////
// Structs //
/////////////

pub const Xid = struct {
    // id is a byte array with fixed size of 16 bytes
    id: id_t,

    // a function that returns a string representation of the ID
    pub fn toStr(self: @This()) *const xid_str_t {
        var dst: xid_str_t = undefined;
        // std.debug.println("-- {d}", .{(self.id[11] << 4) & 0x1F});
        dst[20] = 0;
        dst[19] = encoding[(self.id[11] << 4) & 0x1F];
        dst[18] = encoding[(self.id[11] >> 1) & 0x1F];
        dst[17] = encoding[(self.id[11] >> 6) & 0x1F | (self.id[10] << 2) & 0x1F];
        dst[16] = encoding[self.id[10] >> 3];
        dst[15] = encoding[self.id[9] & 0x1F];
        dst[14] = encoding[(self.id[9] >> 5) | (self.id[8] << 3) & 0x1F];
        dst[13] = encoding[(self.id[8] >> 2) & 0x1F];
        dst[12] = encoding[self.id[8] >> 7 | (self.id[7] << 1) & 0x1F];
        dst[11] = encoding[(self.id[7] >> 4) & 0x1F | (self.id[6] << 4) & 0x1F];
        dst[10] = encoding[(self.id[6] >> 1) & 0x1F];
        dst[9] = encoding[(self.id[6] >> 6) & 0x1F | (self.id[5] << 2) & 0x1F];
        dst[8] = encoding[self.id[5] >> 3];
        dst[7] = encoding[self.id[4] & 0x1F];
        dst[6] = encoding[self.id[4] >> 5 | (self.id[3] << 3) & 0x1F];
        dst[5] = encoding[(self.id[3] >> 2) & 0x1F];
        dst[4] = encoding[self.id[3] >> 7 | (self.id[2] << 1) & 0x1F];
        dst[3] = encoding[(self.id[2] >> 4) & 0x1F | (self.id[1] << 4) & 0x1F];
        dst[2] = encoding[(self.id[1] >> 1) & 0x1F];
        dst[1] = encoding[(self.id[1] >> 6) & 0x1F | (self.id[0] << 2) & 0x1F];
        dst[0] = encoding[self.id[0] >> 3];
        return &dst;
    }

    pub fn time(self: @This()) u32 {
        // First 4 bytes of the id are 32-bit big-endian seconds from epoch
        return u32(self.id[3]) | u32(self.id[2]) << 8 | u32(self.id[1]) << 16 | u32(self.id[0]) << 24;
    }

    pub fn machine(self: @This()) [3]u8 {
        // Next 3 bytes of the id are 24-bit machine identifier
        return self.id[4..7];
    }

    pub fn pid(self: @This()) u16 {
        // Next 2 bytes of the id are 16-bit big-endian process id
        return u16(self.id[8]) | u16(self.id[7]) << 8;
    }

    pub fn counter(self: @This()) u24 {
        // Last 3 bytes of the id are 24-bit counter
        return @as(u24, self.id[11]) | @as(u24, self.id[10]) << 8 | @as(u24, self.id[9]) << 16;
    }
};

///////////////
// Functions //
///////////////

// TODO: get a better machine ID using some hardware UID
fn getHostId() u32 {
    if (maybe_host_id == null) {
        var hostname_buff = std.mem.zeroes([std.os.HOST_NAME_MAX]u8);
        var hostname = std.os.gethostname(&hostname_buff) catch unreachable;
        maybe_host_id = std.hash.Murmur2_32.hash(hostname);
    }
    // std.debug.print("host_id: {d} --\n", .{maybe_host_id.?});
    return maybe_host_id.?;
}

// TODO: make it platform independent
fn getPid() u32 {
    if (maybe_pid == null) {
        // PIDs are always >= 0, so we can safely cast it to u32
        maybe_pid = @bitCast(u32, std.os.linux.getpid());
    }
    return maybe_pid.?;
}

///////////
// Tests //
///////////

test "simple test" {
    const xid = NewFromBytes(.{ 0x4d, 0x88, 0xe1, 0x5b, 0x60, 0xf4, 0x86, 0xe4, 0x28, 0x41, 0x2d, 0xc9 });
    std.debug.print("--- {s}\n", .{xid.toStr()});
}

test "get pid" {
    const pid = std.os.linux.getpid();
    std.debug.print("--- {d} --\n", .{pid});
}

fn assert(ok: bool) void {
    if (!ok) unreachable;
}
