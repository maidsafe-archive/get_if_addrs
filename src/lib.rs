// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! #get_if_addrs
//! Retrieve interface IP addresses in windows and posix systems

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/get_if_addrs/")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
        unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results, variant_size_differences)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations)]

extern crate ip;
extern crate c_linked_list;
extern crate libc;

use std::io;
use ip::IpAddr;

/// Details about an interface on this host
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct IfAddr {
    /// The name of the interface
    pub name: String,
    /// The IP address of the interface
    pub addr: IpAddr,
    /// The netmask of the interface
    pub netmask: IpAddr,
    /// How to send a broadcast on the interface
    pub broadcast: Option<IpAddr>,
}

#[cfg(not(windows))]
mod getifaddrs_posix {
    use super::c_linked_list::CLinkedListMut;
    use super::IfAddr;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use ip::IpAddr;
    use std::{mem, io};
    use std::ffi::CStr;
    use libc::consts::os::bsd44::{AF_INET, AF_INET6};
    use libc::funcs::bsd43::getifaddrs as posix_getifaddrs;
    use libc::funcs::bsd43::freeifaddrs as posix_freeifaddrs;
    use libc::types::os::common::bsd44::ifaddrs as posix_ifaddrs;
    use libc::types::os::common::bsd44::sockaddr as posix_sockaddr;
    use libc::types::os::common::bsd44::sockaddr_in as posix_sockaddr_in;
    use libc::types::os::common::bsd44::sockaddr_in6 as posix_sockaddr_in6;

    #[allow(unsafe_code)]
    fn sockaddr_to_ipaddr(sockaddr: *const posix_sockaddr) -> Option<IpAddr> {
        if sockaddr.is_null() {
            return None;
        }
        if unsafe { *sockaddr }.sa_family as u32 == AF_INET as u32 {
            let sa = &unsafe { *(sockaddr as *const posix_sockaddr_in) };
            Some(IpAddr::V4(Ipv4Addr::new(((sa.sin_addr.s_addr) & 255) as u8,
                                          ((sa.sin_addr.s_addr >> 8) & 255) as u8,
                                          ((sa.sin_addr.s_addr >> 16) & 255) as u8,
                                          ((sa.sin_addr.s_addr >> 24) & 255) as u8)))
        } else if unsafe { *sockaddr }.sa_family as u32 == AF_INET6 as u32 {
            let sa = &unsafe { *(sockaddr as *const posix_sockaddr_in6) };
            // Ignore all fe80:: addresses as these are link locals
            if sa.sin6_addr.s6_addr[0] == 0x80fe {
                return None;
            }
            Some(IpAddr::V6(Ipv6Addr::new(((sa.sin6_addr.s6_addr[0] & 255) << 8) |
                                          ((sa.sin6_addr.s6_addr[0] >> 8) & 255),
                                          ((sa.sin6_addr.s6_addr[1] & 255) << 8) |
                                          ((sa.sin6_addr.s6_addr[1] >> 8) & 255),
                                          ((sa.sin6_addr.s6_addr[2] & 255) << 8) |
                                          ((sa.sin6_addr.s6_addr[2] >> 8) & 255),
                                          ((sa.sin6_addr.s6_addr[3] & 255) << 8) |
                                          ((sa.sin6_addr.s6_addr[3] >> 8) & 255),
                                          ((sa.sin6_addr.s6_addr[4] & 255) << 8) |
                                          ((sa.sin6_addr.s6_addr[4] >> 8) & 255),
                                          ((sa.sin6_addr.s6_addr[5] & 255) << 8) |
                                          ((sa.sin6_addr.s6_addr[5] >> 8) & 255),
                                          ((sa.sin6_addr.s6_addr[6] & 255) << 8) |
                                          ((sa.sin6_addr.s6_addr[6] >> 8) & 255),
                                          ((sa.sin6_addr.s6_addr[7] & 255) << 8) |
                                          ((sa.sin6_addr.s6_addr[7] >> 8) & 255))))
        } else {
            None
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android", target_os = "nacl"))]
    fn do_broadcast(ifaddr: &posix_ifaddrs) -> Option<IpAddr> {
        sockaddr_to_ipaddr(ifaddr.ifa_ifu)
    }

    #[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "ios"))]
    fn do_broadcast(ifaddr: &posix_ifaddrs) -> Option<IpAddr> {
        sockaddr_to_ipaddr(ifaddr.ifa_dstaddr)
    }

    /// Return a vector of IP details for all the valid interfaces on this host
    #[allow(unsafe_code)]
    pub fn get_if_addrs() -> io::Result<Vec<IfAddr>> {
        let mut ret = Vec::<IfAddr>::new();
        let mut ifaddrs: *mut posix_ifaddrs;
        unsafe {
            ifaddrs = mem::uninitialized();
            if -1 == posix_getifaddrs(&mut ifaddrs) {
                return Err(io::Error::last_os_error());
            }
        }

        for ifaddr in CLinkedListMut::from_ptr(ifaddrs, |a| a.ifa_next).iter() {
            // debug!("ifaddr1={}, next={}", ifaddr as u64, ifaddr.ifa_next as u64);
            if ifaddr.ifa_addr.is_null() {
                continue;
            }
            let name = unsafe { CStr::from_ptr(ifaddr.ifa_name) }.to_string_lossy().into_owned();
            let addr = match sockaddr_to_ipaddr(ifaddr.ifa_addr) {
                Some(addr) => addr,
                None => continue,
            };
            let default = match addr {
                IpAddr::V4(..) => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                IpAddr::V6(..) => IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            };
            let netmask = sockaddr_to_ipaddr(ifaddr.ifa_netmask).unwrap_or(default);
            let broadcast = match (ifaddr.ifa_flags & 2) != 0 {
                true => do_broadcast(ifaddr),
                false => None,
            };
            ret.push(IfAddr {
                name: name,
                addr: addr,
                netmask: netmask,
                broadcast: broadcast,
            });
        }
        unsafe {
            posix_freeifaddrs(ifaddrs);
        }
        Ok(ret)
    }
}

/// For non-Windows operating system, use this function to get address
#[cfg(not(windows))]
pub fn get_if_addrs() -> io::Result<Vec<IfAddr>> {
    getifaddrs_posix::get_if_addrs()
}

#[cfg(windows)]
mod getifaddrs_windows {
    use super::c_linked_list::CLinkedListConst;
    use super::IfAddr;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use ip::IpAddr;
    use std::{io, ptr};
    use std::ffi::CStr;
    use libc::types::common::c95::c_void;
    use libc::types::os::arch::c95::{c_char, c_ulong, size_t, c_int};
    use libc::types::os::arch::extra::*;   // libc source code says this is all the Windows integral types
    use libc::consts::os::extra::*;        // win32 status code, constants etc
    use libc::consts::os::bsd44::*;        // the winsock constants
    use libc::types::os::common::bsd44::*; // the winsock types
    use libc;

    #[repr(C)]
    struct SocketAddress {
        pub lp_socket_address: *const sockaddr,
        pub i_socket_address_length: c_int,
    }
    #[repr(C)]
    struct IpAdapterUnicastAddress {
        pub length: c_ulong,
        pub flags: DWORD,
        pub next: *const IpAdapterUnicastAddress,
        // Loads more follows, but I'm not bothering to map these for now
        pub address: SocketAddress,
    }
    #[repr(C)]
    struct IpAdapterPrefix {
        pub length: c_ulong,
        pub flags: DWORD,
        pub next: *const IpAdapterPrefix,
        pub address: SocketAddress,
        pub prefix_length: c_ulong,
    }
    #[repr(C)]
    struct IpAdapterAddresses {
        pub length: c_ulong,
        pub if_index: DWORD,
        pub next: *const IpAdapterAddresses,
        pub adapter_name: *const c_char,
        pub first_unicast_address: *const IpAdapterUnicastAddress,
        first_anycast_address: *const c_void,
        first_multicast_address: *const c_void,
        first_dns_server_address: *const c_void,
        dns_suffix: *const c_void,
        description: *const c_void,
        friendly_name: *const c_void,
        physical_address: [c_char; 8],
        physical_address_length: DWORD,
        flags: DWORD,
        mtu: DWORD,
        if_type: DWORD,
        oper_status: c_int,
        ipv6_if_index: DWORD,
        zone_indices: [DWORD; 16],
        // Loads more follows, but I'm not bothering to map these for now
        pub first_prefix: *const IpAdapterPrefix,
    }
    #[link(name="Iphlpapi")]
    extern "system" {
        /// get adapter's addresses
        fn GetAdaptersAddresses(family: c_ulong,
                                flags: c_ulong,
                                reserved: *const c_void,
                                addresses: *const IpAdapterAddresses,
                                size: *mut c_ulong)
                                -> c_ulong;
    }

    #[allow(unsafe_code)]
    fn sockaddr_to_ipaddr(sockaddr: *const sockaddr) -> Option<IpAddr> {
        if sockaddr.is_null() {
            return None;
        }
        if unsafe { *sockaddr }.sa_family as u32 == AF_INET as u32 {
            let ref sa = unsafe { *(sockaddr as *const sockaddr_in) };
            // Ignore all 169.254.x.x addresses as these are not active interfaces
            if sa.sin_addr.s_addr & 65535 == 0xfea9 {
                return None;
            }
            Some(IpAddr::V4(Ipv4Addr::new(((sa.sin_addr.s_addr >> 0) & 255) as u8,
                                          ((sa.sin_addr.s_addr >> 8) & 255) as u8,
                                          ((sa.sin_addr.s_addr >> 16) & 255) as u8,
                                          ((sa.sin_addr.s_addr >> 24) & 255) as u8)))
        } else if unsafe { *sockaddr }.sa_family as u32 == AF_INET6 as u32 {
            let ref sa = unsafe { *(sockaddr as *const sockaddr_in6) };
            // Ignore all fe80:: addresses as these are link locals
            if sa.sin6_addr.s6_addr[0] == 0x80fe {
                return None;
            }
            Some(IpAddr::V6(Ipv6Addr::new(((sa.sin6_addr.s6_addr[0] & 255) << 8) |
                                          ((sa.sin6_addr.s6_addr[0] >> 8) & 255),
                                          ((sa.sin6_addr.s6_addr[1] & 255) << 8) |
                                          ((sa.sin6_addr.s6_addr[1] >> 8) & 255),
                                          ((sa.sin6_addr.s6_addr[2] & 255) << 8) |
                                          ((sa.sin6_addr.s6_addr[2] >> 8) & 255),
                                          ((sa.sin6_addr.s6_addr[3] & 255) << 8) |
                                          ((sa.sin6_addr.s6_addr[3] >> 8) & 255),
                                          ((sa.sin6_addr.s6_addr[4] & 255) << 8) |
                                          ((sa.sin6_addr.s6_addr[4] >> 8) & 255),
                                          ((sa.sin6_addr.s6_addr[5] & 255) << 8) |
                                          ((sa.sin6_addr.s6_addr[5] >> 8) & 255),
                                          ((sa.sin6_addr.s6_addr[6] & 255) << 8) |
                                          ((sa.sin6_addr.s6_addr[6] >> 8) & 255),
                                          ((sa.sin6_addr.s6_addr[7] & 255) << 8) |
                                          ((sa.sin6_addr.s6_addr[7] >> 8) & 255))))
        } else {
            None
        }
    }

    // trivial_numeric_casts lint may become allow by default.
    // Refer: https://github.com/rust-lang/rfcs/issues/1020
    /// Return a vector of IP details for all the valid interfaces on this host
    #[allow(unsafe_code, trivial_numeric_casts)]
    pub fn get_if_addrs() -> io::Result<Vec<IfAddr>> {
        let mut ret = Vec::<IfAddr>::new();
        let mut ifaddrs: *const IpAdapterAddresses;
        let mut buffersize: c_ulong = 15000;
        loop {
            unsafe {
                ifaddrs = libc::malloc(buffersize as size_t) as *mut IpAdapterAddresses;
                if ifaddrs.is_null() {
                    panic!("Failed to allocate buffer in get_if_addrs()");
                }
                let retcode =
                    GetAdaptersAddresses(0,
                                         // GAA_FLAG_SKIP_ANYCAST       |
                                         // GAA_FLAG_SKIP_MULTICAST     |
                                         // GAA_FLAG_SKIP_DNS_SERVER    |
                                         // GAA_FLAG_INCLUDE_PREFIX     |
                                         // GAA_FLAG_SKIP_FRIENDLY_NAME
                                         0x3e,
                                         ptr::null(),
                                         ifaddrs,
                                         &mut buffersize) as c_int;
                match retcode {
                    ERROR_SUCCESS => break,
                    111 => {
                        libc::free(ifaddrs as *mut c_void);
                        buffersize = buffersize * 2;
                        continue;
                    }
                    _ => return Err(io::Error::last_os_error()),
                }
            }
        }

        for ifaddr in CLinkedListConst::from_ptr(ifaddrs, |a| a.next).iter() {
            // debug!("ifaddr1={}, next={}", ifaddr as u64, ifaddr.ifa_next as u64);

            for addr in CLinkedListConst::from_ptr(ifaddr.first_unicast_address, |a| a.next).iter() {
                let name = unsafe { CStr::from_ptr(ifaddr.adapter_name) }.to_string_lossy().into_owned();

                let ipaddr = match sockaddr_to_ipaddr(addr.address.lp_socket_address) {
                    Some(ipaddr) => ipaddr,
                    None => continue,
                };

                let mut item_netmask = match ipaddr {
                    IpAddr::V4(..) => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    IpAddr::V6(..) => IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
                };
                let mut item_broadcast = None;
                // Search prefixes for a prefix matching addr
                'prefixloop: for prefix in CLinkedListConst::from_ptr(ifaddr.first_prefix, |p| p.next).iter() {
                    let ipprefix = sockaddr_to_ipaddr(prefix.address.lp_socket_address);
                    match ipprefix {
                        None => continue,
                        Some(IpAddr::V4(ref a)) => {
                            if let IpAddr::V4(b) = ipaddr {
                                let mut netmask: [u8; 4] = [0; 4];
                                for n in 0..((prefix.prefix_length as usize + 7) / 8) {
                                    let x_byte = b.octets()[n];
                                    let y_byte = a.octets()[n];
                                    for m in 0..8 {
                                        if (n * 8) + m > prefix.prefix_length as usize {
                                            break;
                                        }
                                        let bit = 1 << m;
                                        if (x_byte & bit) == (y_byte & bit) {
                                            netmask[n] = netmask[n] | bit;
                                        } else {
                                            continue 'prefixloop;
                                        }
                                    }
                                }
                                item_netmask = IpAddr::V4(Ipv4Addr::new(netmask[0],
                                                                        netmask[1],
                                                                        netmask[2],
                                                                        netmask[3]));
                                let mut broadcast: [u8; 4] = b.octets();
                                for n in 0..4 {
                                    broadcast[n] = broadcast[n] | !netmask[n];
                                }
                                item_broadcast = Some(IpAddr::V4(Ipv4Addr::new(broadcast[0],
                                                                               broadcast[1],
                                                                               broadcast[2],
                                                                               broadcast[3])));
                                break 'prefixloop;
                            }
                        }
                        Some(IpAddr::V6(ref a)) => {
                            if let IpAddr::V6(b) = ipaddr {
                                // Iterate the bits in the prefix, if they all match this prefix
                                // is the right one, else try the next prefix
                                let mut netmask: [u16; 8] = [0; 8];
                                for n in 0..((prefix.prefix_length as usize + 15) / 16) {
                                    let x_word = b.segments()[n];
                                    let y_word = a.segments()[n];
                                    for m in 0..16 {
                                        if (n * 16) + m > prefix.prefix_length as usize {
                                            break;
                                        }
                                        let bit = 1 << m;
                                        if (x_word & bit) == (y_word & bit) {
                                            netmask[n] = netmask[n] | bit;
                                        } else {
                                            continue 'prefixloop;
                                        }
                                    }
                                }
                                item_netmask = IpAddr::V6(Ipv6Addr::new(netmask[0],
                                                                        netmask[1],
                                                                        netmask[2],
                                                                        netmask[3],
                                                                        netmask[4],
                                                                        netmask[5],
                                                                        netmask[6],
                                                                        netmask[7]));
                                item_broadcast = None;
                                break 'prefixloop;
                            }
                        }
                    };
                }
                ret.push(IfAddr {
                    name: name,
                    addr: ipaddr,
                    netmask: item_netmask,
                    broadcast: item_broadcast,
                });
            }
        }
        unsafe {
            libc::free(ifaddrs as *mut c_void);
        }
        Ok(ret)
    }
}
#[cfg(windows)]
/// Get address
pub fn get_if_addrs() -> io::Result<Vec<IfAddr>> {
    getifaddrs_windows::get_if_addrs()
}

fn is_loopback(ip_addr: &IpAddr) -> bool {
    match *ip_addr {
        IpAddr::V4(a) => a.octets()[0] == 127,
        IpAddr::V6(a) => a.segments() == [0, 0, 0, 0, 0, 0, 0, 1],
    }
}

/// Remove loopback address(s)
pub fn filter_loopback(mut ifaddrs: Vec<IfAddr>) -> Vec<IfAddr> {
    ifaddrs.retain(|x| !is_loopback(&x.addr));
    ifaddrs
}

#[cfg(test)]
mod test {
    use super::{get_if_addrs, filter_loopback, is_loopback};

    #[test]
    fn test_filter_loopback() {
        let ifaddrs = filter_loopback(get_if_addrs().unwrap());
        for ifaddr in ifaddrs {
            assert!(!is_loopback(&ifaddr.addr));
        }
    }
}
