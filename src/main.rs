extern crate ravel;

fn main() {
    let addr = "127.0.0.1:13265".parse().unwrap();
    let config = ravel::Config{ addr };
    ravel::run(config);
}
