mod dns;
mod ffi;
#[allow(dead_code)]
mod ftp;
mod http;
mod json;
mod pagination;
mod rate_limit;
mod runtime;
#[allow(dead_code)]
mod sftp;
mod smtp;
mod soap;

quack_rs::entry_point_v2!(duck_net_init_c_api, |con| { ffi::register_all(con) });
