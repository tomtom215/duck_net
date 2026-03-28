mod scalars;

use quack_rs::prelude::*;

pub fn register_all(con: &Connection) -> Result<(), ExtensionError> {
    let raw_con = con.as_raw_connection();
    unsafe { scalars::register_all(raw_con) }
}
