use mio;
use mio::udp::UdpSocket;
//use rustc_serialize::hex::ToHex;

use {Result};
use dns::{Message};

const SERVER_UDP: mio::Token = mio::Token(0);
//const TCP_SERVER: mio::Token = mio::Token(1);
//const CLIENT: mio::Token = mio::Token(1);


#[derive(Copy, Clone, Debug)]
pub struct ServerConfig<'a> {
    pub addr: &'a str,
}

pub struct Server {
    udp_socket: UdpSocket,
    // tcp_listener: TcpListener,
}

impl Server {

    pub fn new(addr: &str) -> Result<Server> {
        Ok(Server{
            udp_socket: try!(UdpSocket::bind(&addr)),
        })
    }

    pub fn run(&mut self) -> Result<()> {
        println!("Listening on {}", self.udp_socket.local_addr().unwrap());

        let mut evloop = try!(mio::EventLoop::<Server>::new());
        try!(evloop.register(&self.udp_socket, SERVER_UDP));
        try!(evloop.run(self));

        Ok(())
    }
}


impl mio::Handler for Server {
    type Timeout = usize;
    type Message = ();

    fn readable(&mut self, _event_loop: &mut mio::EventLoop<Server>, token: mio::Token, _hint: mio::ReadHint) {
        match token {
            SERVER_UDP => {
                let mut buf = [0; 512];
                match self.udp_socket.recv_from(&mut buf) {
                    Ok((_amt, src)) => {
                        match Message::unpack(&buf) {
                            Ok(msg) => if !msg.qr {
                                println!("{}", msg);

                                let msg = Message::new_reply(&msg);
                                let len = msg.pack(&mut buf).unwrap();

                                match self.udp_socket.send_to(&buf[..len], src) {
                                    Err(e) => {
                                        println!("failed to write response {}", e);
                                    }
                                    _ => {}
                                };
                            } else {
                                // TODO return error
                                println!("Error got response {}", msg.qr);
                            },
                            Err(e) => {
                                println!("failed {:?}", e);
                            }
                        }
                        // TODO return error?
                    }
                    Err(e) => {
                        println!("listener.accept() failed: {}", e);
                    }
                }
            }
            _ => (),
        }
    }
}
