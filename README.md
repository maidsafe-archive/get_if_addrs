# get_if_addrs

**Maintainer:** Spandan Sharma (spandan.sharma@maidsafe.net)

|Crate|Documentation|Linux/OS X|Windows|Issues|
|:---:|:-----------:|:--------:|:-----:|:----:|
|[![](http://meritbadge.herokuapp.com/ifaddrs)](https://crates.io/crates/ifaddrs)|[![Documentation](https://docs.rs/ifaddrs/badge.svg)](https://docs.rs/ifaddrs)|[![Build Status](https://travis-ci.org/maidsafe/ifaddrs.svg?branch=master)](https://travis-ci.org/maidsafe/ifaddrs)|[![Build status](https://ci.appveyor.com/api/projects/status/j773wvtxqy9eemue/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/ifaddrs/branch/master)|[![Stories in Ready](https://badge.waffle.io/maidsafe/ifaddrs.png?label=ready&title=Ready)](https://waffle.io/maidsafe/ifaddrs)|

| [MaidSafe website](https://maidsafe.net) | [SAFE Dev Forum](https://forum.safedev.org) | [SAFE Network Forum](https://safenetforum.org) |
|:----------------------------------------:|:-------------------------------------------:|:----------------------------------------------:|

## Overview

Retrieve network interface info for all interfaces on the system.

```rust
// List all of the machine's network interfaces
for iface in get_if_addrs::get_if_addrs().unwrap() {
    println!("{:#?}", iface);
}
```

## Todo Items

  * Create an API for responding to changes in network interfaces.

## License

Licensed under either of

* the MaidSafe.net Commercial License, version 1.0 or later ([LICENSE](LICENSE))
* the General Public License (GPL), version 3 ([COPYING](COPYING) or http://www.gnu.org/licenses/gpl-3.0.en.html)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the
work by you, as defined in the MaidSafe Contributor Agreement ([CONTRIBUTOR](CONTRIBUTOR)), shall be
dual licensed as above, and you agree to be bound by the terms of the MaidSafe Contributor Agreement.
