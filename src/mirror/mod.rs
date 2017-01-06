// Copyright 2016 Taku Fukushima. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// The packet mirror interfaces and functions.

extern crate pcap;
extern crate pnet;

use std::io::Result;

use self::pnet::datalink::Channel::Ethernet;
use self::pnet::packet::ethernet::EthernetPacket;

/// Maximum size of TCP packets in bytes, which is 64K bytes.
pub const MAX_TCP_PACKET_SIZE: i32 = 65535;

/// The generic interface for packet mirror.
pub trait PacketMirror {
    fn new(src: &str, dst: &str) -> Self;
    /// Does the acutal mirroring against the given Ethernet packet.
    fn mirror(&mut self, packet: &EthernetPacket) -> Result<()>;
}

/// Start packet mirroring.
pub fn start_mirroring<T: PacketMirror>(src: &str, dst: &str, filter: &str) {
    let interfaces = pnet::datalink::interfaces();
    let src_if = interfaces.iter().find(|i| i.name == src)
        .expect(format!("Failed to get interface {}", src).as_str());
    let channel = pnet::datalink::channel(&src_if, Default::default());
    let (_, mut rx) = match channel {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unhandled channel type."),
        Err(e) => panic!("unable to create channel: {}", e),
    };
    let mut rx_iter = rx.iter();

    let mut mirror = T::new(src, dst);
    loop {
        match rx_iter.next() {
            Ok(packet) => {
                match mirror.mirror(&packet) {
                    Ok(_) => (),
                    Err(e) => error!("Failed to mirror the packet: {:?}", e),
                }
            },
            Err(e) => {
                error!("Couldn't capture any packet: {:?}", e);
                break
            },
        }   
    }
}

pub mod gtpu_pdu;
