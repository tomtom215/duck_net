mod dns;
mod ftp;
pub(crate) mod scalars;
mod smtp;
mod soap;
mod table;

use quack_rs::prelude::*;

pub fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let raw_con = con.as_raw_connection();
    unsafe {
        scalars::register_all(raw_con)?;
        soap::register_all(raw_con)?;
        table::register_all(raw_con)?;
        dns::register_all(raw_con)?;
        smtp::register_all(raw_con)?;
        ftp::register_all(raw_con)?;
    }
    Ok(())
}
