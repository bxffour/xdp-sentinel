mod xdp_blocker {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/xdp_blocker.skel.rs"
    ));
}
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::configuration::{self, Settings};
use crate::prelude::*;
use flexi_logger::Logger;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    ErrorExt, MapCore, MapFlags, Xdp, XdpFlags,
};
use log::{debug, info};
use nix::net::if_::if_nametoindex;
use xdp_blocker::XdpBlockerSkelBuilder;

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

pub struct Application {
    config: configuration::Settings,
    interface_indexes: Vec<i32>,
}

impl Application {
    pub fn build(config: Settings) -> Result<Self> {
        let idxes = get_interface_indexes(&config)?;
        Ok(Self {
            config,
            interface_indexes: idxes,
        })
    }

    pub fn run(&self) -> Result<()> {
        self.set_up_logging();

        let _ = bump_memlock_rlimit();
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        })
        .expect("unable to set ctrl+c handler");

        let skel_builder = XdpBlockerSkelBuilder::default();

        let mut open_object = MaybeUninit::uninit();
        let open_skel = skel_builder
            .open(&mut open_object)
            .expect("error opening skel_builder");
        let skel = open_skel.load().expect("error loading skel");

        let xdp = Xdp::new(skel.progs.xdp_test.as_fd());
        info!("attaching xdp program to interfaces");
        for idx in self.interface_indexes.iter() {
            debug!("attaching xdp program to interface {idx}");
            xdp.attach(*idx, XdpFlags::SKB_MODE)
                .expect("unable to attach program to interface");
            debug!("successfully attached xdp program to interface {idx}");
        }
        info!("successfully attached xdp programs to configured interfaces");

        info!("running xdp-sentinel");
        while running.load(Ordering::SeqCst) {
            sleep(Duration::new(1, 0));
        }

        info!("detaching xdp program from interfaces");
        for idx in self.interface_indexes.iter() {
            debug!("detaching xdp program to interface {idx}");
            xdp.detach(*idx, XdpFlags::SKB_MODE)
                .expect("unable to detach program to interface");
            debug!("successfully detached xdp program to interface {idx}");
        }
        info!("successfully detached xdp program from interfaces");
        Ok(())
    }

    fn set_up_logging(&self) -> Result<()> {
        let level: &str = self.config.log_level.as_ref();
        Logger::try_with_env_or_str(level)
            .expect("error initiating logger")
            .start()
            .expect("error starting logger");
        Ok(())
    }
}

fn get_interface_indexes(config: &Settings) -> Result<Vec<i32>> {
    let mut iface_idxes: Vec<i32> = Vec::new();

    for iface in config.interfaces.iter() {
        let iface_name: &str = iface.as_ref();

        debug!("retrieving index for interface '{iface_name}'");
        let idx = if_nametoindex(iface_name).expect("error getting name to index") as i32;
        debug!("successfully retrieved index {idx} for interface {iface_name}");

        iface_idxes.push(idx);
    }

    Ok(iface_idxes)
}
