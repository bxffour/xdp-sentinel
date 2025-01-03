mod xdp_blocker {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/xdp_blocker.skel.rs"
    ));
}

use std::{
    mem::MaybeUninit,
    net::Ipv4Addr,
    os::fd::AsFd,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::sleep,
    time::Duration,
};

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    ErrorExt, MapCore, MapFlags, Xdp, XdpFlags,
};
use nix::net::if_::if_nametoindex;
use xdp_blocker::*;
use xdp_sentinel::prelude::*;

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        return Err(Error::Static("Error setting memlock"));
    }
    Ok(())
}

fn main() -> Result<()> {
    let _ = bump_memlock_rlimit();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .unwrap();

    let mut skel_builder = XdpBlockerSkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object).unwrap();
    let skel = open_skel.load().unwrap();

    let iface_name = "enp1s0";
    let idx = if_nametoindex(iface_name).unwrap() as i32;
    println!("{iface_name} has index {idx}");

    let xdp = Xdp::new(skel.progs.xdp_test.as_fd());
    xdp.attach(idx, XdpFlags::SKB_MODE).unwrap();
    println!("successfully attached xdp program");

    let block_ip = Ipv4Addr::from_str("192.168.122.1").unwrap();
    let block_ip: u32 = block_ip.into();
    let key = types::ipv4_lpm_key {
        prefixlen: (32_u32),
        data: block_ip.to_be(),
    };

    let key = unsafe { plain::as_bytes(&key) };
    let value = block_ip.to_le();

    skel.maps
        .block_list
        .update(key, &value.to_be_bytes(), MapFlags::ANY)
        .context("update new record to map fail")
        .unwrap();

    while running.load(Ordering::SeqCst) {
        sleep(Duration::new(1, 0));
    }

    xdp.detach(idx, XdpFlags::SKB_MODE).unwrap();
    println!("successfully detached xdp program");
    Ok(())
}
