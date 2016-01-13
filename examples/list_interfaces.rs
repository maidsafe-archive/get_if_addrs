extern crate get_if_addrs;

fn main() {
    let ifaces = get_if_addrs::get_if_addrs().unwrap();
    println!("Got list of interfaces");
    println!("{:#?}", ifaces);
}

