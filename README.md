# get_if_addrs

[![](https://img.shields.io/badge/Project%20SAFE-Approved-green.svg)](http://maidsafe.net/applications) [![](https://img.shields.io/badge/License-GPL3-green.svg)](https://github.com/maidsafe/get_if_addrs/blob/master/COPYING)

**Primary Maintainer:** Andrew Cann (andrew.cann@maidsafe.net)

**Secondary Maintainer:** Qi Ma (qi.ma@maidsafe.net)

|Crate|Linux/OS X|Windows|Coverage|Issues|
|:---:|:--------:|:-----:|:------:|:----:|
|[![](http://meritbadge.herokuapp.com/get_if_addrs)](https://crates.io/crates/get_if_addrs)|[![Build Status](https://travis-ci.org/maidsafe/get_if_addrs.svg?branch=master)](https://travis-ci.org/maidsafe/get_if_addrs)|[![Build status](https://ci.appveyor.com/api/projects/status/d1d02u0ia5omrygb/branch/master?svg=true)](https://ci.appveyor.com/project/MaidSafe-QA/get-if-addrs/branch/master)|[![Coverage Status](https://coveralls.io/repos/maidsafe/get_if_addrs/badge.svg?branch=master&service=github)](https://coveralls.io/github/maidsafe/get_if_addrs?branch=master)|[![Stories in Ready](https://badge.waffle.io/maidsafe/get_if_addrs.png?label=ready&title=Ready)](https://waffle.io/maidsafe/get_if_addrs)|

| [API Documentation - master branch](http://maidsafe.net/get_if_addrs/master) | [SAFE Network System Documentation](http://systemdocs.maidsafe.net) | [MaidSafe website](http://maidsafe.net) | [SAFE Network Forum](https://forum.safenetwork.io) |
|:------:|:-------:|:-------:|:-------:|

## Overview

Retrieve IP addresses from all interfaces on system (excluding loopback)

```rust
// List all of the machine's network interfaces
for iface in get_if_addrs::get_if_addrs().unwrap() {
    println!("{:#?}", iface);
}
```

## Todo Items

  * Create an API for responding to changes in network interfaces.

