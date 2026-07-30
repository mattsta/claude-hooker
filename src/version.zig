//! The one place the released version number is written down.
//!
//! `build.zig.zon`'s `.version` field must move with this constant — nothing
//! in the toolchain ties the two together, so a bump is two edits. The
//! "VERSION matches build.zig.zon" test in `cli.zig` fails the build when they
//! drift apart, which is the enforcement.

pub const VERSION = "0.3.0";
