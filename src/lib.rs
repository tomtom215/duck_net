mod ffi;
mod http;
mod json;
mod pagination;
mod rate_limit;
mod soap;

quack_rs::entry_point_v2!(duck_net_init_c_api, |con| { ffi::register_all(con) });
