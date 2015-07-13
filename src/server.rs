use std::net::{SocketAddr};
use mio;
use mio::udp::UdpSocket;
use mio::buf::{SliceBuf, MutSliceBuf};
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

    pub fn new(addr: &SocketAddr) -> Result<Server> {
        Ok(Server{
            udp_socket: try!(UdpSocket::bound(&addr)),
        })
    }

    pub fn run(&mut self) -> Result<()> {
        println!("Listening on {}", self.udp_socket.local_addr().unwrap());

        let mut config = mio::EventLoopConfig::default();
        config.io_poll_timeout_ms = 10_000;
        config.timer_tick_ms = 1_000;

        let mut evloop = try!(mio::EventLoop::<Server>::configured(config));
        try!(evloop.register_opt(&self.udp_socket,
                                 SERVER_UDP,
                                 mio::EventSet::all(),
                                 mio::PollOpt::edge()));
        try!(evloop.run(self));

        Ok(())
    }
}


impl mio::Handler for Server {
    type Timeout = usize;
    type Message = ();

    fn ready(&mut self, _event_loop: &mut mio::EventLoop<Server>, token: mio::Token, _events: mio::EventSet) {
        match token {
            SERVER_UDP => {
                let mut buf = [0; 512];
                match self.udp_socket.recv_from(&mut MutSliceBuf::wrap(&mut buf)) {
                    Ok(Some(ref src)) => {
                        match Message::unpack(&buf, 0) {
                            Ok(msg) => if !msg.qr {
                                println!("{}", msg);

                                let msg = Message::new_reply(&msg);

                                // todo move response

                                let len = msg.pack(&mut buf, 0).unwrap();

                                match self.udp_socket.send_to(&mut SliceBuf::wrap(&mut buf[..len]), src) {
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
                                println!("failed to parse {:?}", e);
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        println!("listener.accept() failed: {}", e);
                    }
                }
            }
            _ => (),
        }
    }
}
