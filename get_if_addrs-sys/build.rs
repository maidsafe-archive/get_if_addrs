extern crate gcc;

use std::env;

fn main() {
    let mut cfg = gcc::Build::new();
    if env::var("TARGET").unwrap().contains("android") {
        cfg.include("native").file("native/ifaddrs.c").compile(
            "libifaddrs.a",
        );
    }
}
