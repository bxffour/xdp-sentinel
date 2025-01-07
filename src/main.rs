use std::path::Path;
use xdp_sentinel::{application::Application, configuration::get_configuration, prelude::*};

fn main() -> Result<()> {
    let configuration =
        get_configuration(Path::new("configuration")).expect("unable to get configuration file");

    let app = Application::build(configuration)?;
    match app.run() {
        Ok(_) => {
            log::info!("application should be shutting down now");
        }
        Err(e) => {
            log::error!("error running application: {e}");
        }
    }

    // let block_ip = Ipv4Addr::from_str("192.168.122.1").unwrap();
    // let block_ip: u32 = block_ip.into();
    // let key = types::ipv4_lpm_key {
    //     prefixlen: (32_u32),
    //     data: block_ip.to_be(),
    // };

    // let key = unsafe { plain::as_bytes(&key) };
    // let value = block_ip.to_le();

    // info!("adding ip {:?} to block list", block_ip);
    // skel.maps
    //     .block_list
    //     .update(key, &value.to_be_bytes(), MapFlags::ANY)
    //     .context("update new record to map fail")
    //     .unwrap();
    // info!("successfully added {block_ip} to block list");

    Ok(())
}
