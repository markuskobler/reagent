extern crate reagent;

use reagent::{Server};

fn main() {

    let addr = "0.0.0.0:6567".parse().unwrap();

    let mut srv = Server::new(&addr).unwrap();

    srv.run().unwrap();
}
