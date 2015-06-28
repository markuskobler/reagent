extern crate reagent;

use reagent::{Server};

fn main() {
    let mut srv = Server::new("0.0.0.0:6567").unwrap();

    srv.run().unwrap();
}
