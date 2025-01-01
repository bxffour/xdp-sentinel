mod xdp_blocker {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/xdp_blocker.skel.rs"
    ));
}

use std::{
    mem::MaybeUninit,
    os::fd::AsFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::sleep,
    time::Duration,
};

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    Xdp, XdpFlags,
};
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

    let xdp = Xdp::new(skel.progs.xdp_test.as_fd());
    xdp.attach(1, XdpFlags::SKB_MODE).unwrap();
    println!("successfully attached xdp program");

    while running.load(Ordering::SeqCst) {
        sleep(Duration::new(1, 0));
    }

    xdp.detach(1, XdpFlags::SKB_MODE).unwrap();
    println!("successfully detached xdp program");
    Ok(())
}
