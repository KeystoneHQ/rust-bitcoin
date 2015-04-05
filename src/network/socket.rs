// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Sockets
//!
//! This module provides support for low-level network communication.
//!

use time::now;
use rand::{thread_rng, Rng};
use std::io::Cursor;
use std::io::{Error, Result, ErrorKind};
use std::net::{ip, tcp};
use std::sync::{Arc, Mutex};

use network::constants;
use network::address::Address;
use network::encodable::{ConsensusEncodable, ConsensusDecodable};
use network::message::{RawNetworkMessage, NetworkMessage};
use network::message::NetworkMessage::Version;
use network::message_network::VersionMessage;
use network::serialize::{RawEncoder, RawDecoder};
use util::misc::prepend_err;

/// Format an IP address in the 16-byte bitcoin protocol serialization
fn ipaddr_to_bitcoin_addr(ipaddr: &ip::IpAddr) -> [u16; 8] {
  match *ipaddr {
    ip::IpAddr::V4(ref addr) => &addr.to_ipv6_mapped(),
    ip::IpAddr::V6(ref addr) => addr
  }.segments()
}

/// A network socket along with information about the peer
#[derive(Clone)]
pub struct Socket {
  /// The underlying socket, which is only used directly to (a) get
  /// information about the socket, and (b) to close down the socket,
  /// quickly cancelling any read/writes and unlocking the Mutexes.
  socket: Option<tcp::TcpStream>,
  /// The underlying network data stream read buffer
  buffered_reader: Arc<Mutex<Option<tcp::TcpStream>>>,
  /// The underlying network data stream write buffer
  buffered_writer: Arc<Mutex<Option<tcp::TcpStream>>>,
  /// Services supported by us
  pub services: u64,
  /// Our user agent
  pub user_agent: String,
  /// Nonce to identify our `version` messages
  pub version_nonce: u64,
  /// Network magic
  pub magic: u32
}

impl Socket {
  // TODO: we fix services to 0
  /// Construct a new socket
  pub fn new(network: constants::Network) -> Socket {
    let mut rng = thread_rng();
    Socket {
      socket: None,
      buffered_reader: Arc::new(Mutex::new(None)),
      buffered_writer: Arc::new(Mutex::new(None)),
      services: 0,
      version_nonce: rng.gen(),
      user_agent: String::from_str(constants::USER_AGENT),
      magic: constants::magic(network)
    }
  }

  /// Connect to the peer
  pub fn connect(&mut self, host: &str, port: u16) -> Result<()> {
    // Boot off any lingering readers or writers
    if self.socket.is_some() {
      let _ = self.socket.as_mut().unwrap().close_read();
      let _ = self.socket.as_mut().unwrap().close_write();
    }
    // These locks should just pop open now
    let mut reader_lock = self.buffered_reader.lock();
    let mut writer_lock = self.buffered_writer.lock();
    match tcp::TcpStream::connect(host, port) {
      Ok(s)  => {
        *reader_lock = Some(s.clone());
        *writer_lock = Some(s.clone());
        self.socket = Some(s);
        Ok(()) 
      }
      Err(e) => Err(e)
    }
  }

  /// Peer address
  pub fn receiver_address(&mut self) -> Result<Address> {
    match self.socket {
      Some(ref mut s) => match s.peer_name() {
        Ok(addr) => {
          Ok(Address {
            services: self.services,
            address: ipaddr_to_bitcoin_addr(&addr.ip),
            port: addr.port
          })
        }
        Err(e) => Err(e)
      },
      None => Err(Error::new(ErrorKind::NotConnected,
                             "receiver_address: not connected to peer", None))
    }
  }

  /// Our own address
  pub fn sender_address(&mut self) -> Result<Address> {
    match self.socket {
      Some(ref mut s) => match s.socket_name() {
        Ok(addr) => {
          Ok(Address {
            services: self.services,
            address: ipaddr_to_bitcoin_addr(&addr.ip),
            port: addr.port
          })
        }
        Err(e) => Err(e)
      },
      None => Err(Error::new(ErrorKind::NotConnected,
                             "sender_address: not connected to peer", None))
    }
  }

  /// Produce a version message appropriate for this socket
  pub fn version_message(&mut self, start_height: i32) -> Result<NetworkMessage> {
    let timestamp = now().to_timespec().sec;
    let recv_addr = self.receiver_address();
    let send_addr = self.sender_address();
    // If we are not connected, we might not be able to get these address.s
    match recv_addr {
      Err(e) => { return Err(e); }
      _ => {}
    }
    match send_addr {
      Err(e) => { return Err(e); }
      _ => {}
    }

    Ok(Version(VersionMessage {
      version: constants::PROTOCOL_VERSION,
      services: constants::SERVICES,
      timestamp: timestamp,
      receiver: recv_addr.unwrap(),
      sender: send_addr.unwrap(),
      nonce: self.version_nonce,
      user_agent: self.user_agent.clone(),
      start_height: start_height,
      relay: false
    }))
  }

  /// Send a general message across the line
  pub fn send_message(&mut self, payload: NetworkMessage) -> Result<()> {
    let mut writer_lock = self.buffered_writer.lock();
    match *writer_lock.deref_mut() {
      None => Err(Error::new(ErrorKind::NotConnected,
                             "send_message: not connected to peer", None)),
      Some(ref mut writer) => {
        let message = RawNetworkMessage { magic: self.magic, payload: payload };
        try!(message.consensus_encode(&mut RawEncoder::new(writer.by_ref())));
        writer.flush()
      }
    }
  }

  /// Receive the next message from the peer, decoding the network header
  /// and verifying its correctness. Returns the undecoded payload.
  pub fn receive_message(&mut self) -> Result<NetworkMessage> {
    let mut reader_lock = self.buffered_reader.lock();
    match *reader_lock.deref_mut() {
      None => Err(Error::new(ErrorKind::NotConnected,
                             "receive_message: not connected to peer", None)),
      Some(ref mut buf) => {
        // We need a new scope since the closure in here borrows read_err,
        // and we try to read it afterward. Letting `iter` go out fixes it.
        let mut decoder = RawDecoder::new(buf.by_ref());
        let decode: Result<RawNetworkMessage> = ConsensusDecodable::consensus_decode(&mut decoder);
        match decode {
          // Check for parse errors...
          Err(e) => {
            prepend_err("network_decode", Err(e))
          },
          Ok(ret) => {
            // Then for magic (this should come before parse error, but we can't
            // get to it if the deserialization failed). TODO restructure this
            if ret.magic != self.magic {
              Err(Error {
                kind: ErrorKind::OtherError,
                desc: "bad magic",
                detail: Some(format!("got magic {:x}, expected {:x}", ret.magic, self.magic)),
              })
            } else {
              Ok(ret.payload)
            }
          }
        }
      }
    }
  }
}


