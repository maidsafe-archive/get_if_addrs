# get_if_addrs - Change Log

## [0.5.3]
- Update dependency version of get_if_addrs-sys to 0.1.1
- Update dependency version of c_linked_list to 1.1.1

## [0.5.2]
- Fix incorrect parsing of IPv6 addresses

## [0.5.1]
- Fixed nullptr deref in unsafe code
- Use Rust 1.24.0 stable / 2018-02-05 nightly
- Use Clippy 0.0.186

## [0.5.0]
- Use rust 1.22.1 stable / 2017-12-02 nightly
- rustfmt 0.9.0 and clippy-0.0.175

## [0.4.1]
- Fix build for android

## [0.4.0]
- Replaced ip::IpAddr with std::IpAddr
- Changed to support BSD
- Updated lints
- Documentation fixes

## [0.3.1]
- Fix build on ARM

## [0.3.0]
- Added a method on the interface object to get the ip addresses
