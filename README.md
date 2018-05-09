# get_if_addrs

**Maintainer:** Spandan Sharma (spandan.sharma@maidsafe.net)

|Crate|Documentation|Linux/OS X|Windows|Issues|
|:---:|:-----------:|:--------:|:-----:|:----:|
|[![](http://meritbadge.herokuapp.com/get_if_addrs)](https://crates.io/crates/get_if_addrs)|[![Documentation](https://docs.rs/get_if_addrs/badge.svg)](https://docs.rs/get_if_addrs)|[![Build Status](https://travis-ci.org/maidsafe/get_if_addrs.svg?branch=master)](https://travis-ci.org/maidsafe/get_if_addrs)|[![Build status](https://ci.appveyor.com/api/projects/status/77mots4kfaxs3v8g/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/get-if-addrs/branch/master)|[![Stories in Ready](https://badge.waffle.io/maidsafe/get_if_addrs.png?label=ready&title=Ready)](https://waffle.io/maidsafe/get_if_addrs)|

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

This SAFE Network library is dual-licensed under the Modified BSD ([LICENSE-BSD](LICENSE-BSD) https://opensource.org/licenses/BSD-3-Clause) or the MIT license ([LICENSE-MIT](LICENSE-MIT) http://opensource.org/licenses/MIT) at your option.

## Contribution

Copyrights in the SAFE Network are retained by their contributors. No copyright assignment is required to contribute to this project.
