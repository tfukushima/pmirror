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

/// The GTP-U PDU mirror specific implementation of packet mirror interfaces
/// and functions.

extern crate std;

extern crate pnet;
extern crate pcap;

use std::fmt::Write;
use std::io::{Error, ErrorKind, Result};
use std::iter::repeat;

use self::pnet::datalink::{Channel, NetworkInterface, EthernetDataLinkSender};
use self::pnet::packet::Packet;
use self::pnet::packet::ethernet::{EthernetPacket, EtherTypes, MutableEthernetPacket};
use self::pnet::packet::ip::IpNextHeaderProtocols;
use self::pnet::packet::ipv4::Ipv4Packet;
use self::pnet::packet::udp::UdpPacket;

use super::PacketMirror;

/// The size of GTP-U header for PDU.
const GTPU_HEADER_SIZE: i32 = 8;
/// The index of the message type in the GTP-U header.
const GTPU_HEADER_MESSAGE_TYPE_INDEX: usize = 1;
/// The type of the GTP-U packet. ff stands for PDU.
const GTPU_MESSAGE_TYPE_PDU: u8 = 0xff;

/// The packet mirror for GTP-U PDU packets. GTP-U headers are stripped and
/// only payloads of PDUs are mirrored.
pub struct GtpUPduPacketMirror {
    src: NetworkInterface,
    dst: NetworkInterface,
    sender: Box<EthernetDataLinkSender>,
}

/// PacketMirror implementations for GtpUPduPacketMirror.
impl PacketMirror for GtpUPduPacketMirror {
    /// Create a new GtpUPduPacketMirror instance.
    fn new(src: &str, dst: &str) -> Self {
        let interfaces = pnet::datalink::interfaces();
        let mut if_iter = interfaces.iter();
        
        let src_if = if_iter.find(|i| i.name == src)
            .expect(format!("Failed to get interface {}", src).as_str())
            .to_owned();

        let dst_if = if_iter.find(|i| i.name == dst)
            .expect(format!("Failed to get interface {}", dst).as_str())
            .to_owned();

        let channel = pnet::datalink::channel(&dst_if, Default::default());
        let (tx, _) = match channel {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("unhandled channel type."),
            Err(e) => panic!("unable to create channel {}", e),
        };

        GtpUPduPacketMirror {
            src: src_if,
            dst: dst_if,
            sender: tx,
        }
    }

    /// Mirror the given packet through the established mirroring channel.
    fn mirror(&mut self, packet: &EthernetPacket) -> Result<()> {
        if packet.get_ethertype() != EtherTypes::Ipv4 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "The payload of the ethernet fram e is not IP."));
        }
        let ip_packet = Ipv4Packet::new(packet.payload())
            .expect("The packet is not a IP packet.");
        if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "The payload of the IP packet is not UDP."));
        }
        let udp_packet = UdpPacket::new(ip_packet.payload())
            .expect("The packet is not a UDP packet.");
        let pdu = udp_packet.payload();
        if pdu[GTPU_HEADER_MESSAGE_TYPE_INDEX] != GTPU_MESSAGE_TYPE_PDU {
            return Err(Error::new(
                ErrorKind::InvalidData, "The packet does not contain PDU."));
        }
        let stripped_pdu: &[u8] = &pdu[GTPU_HEADER_SIZE as usize..];

        let mut s = String::new();
        write!(&mut s, "{:?} ", stripped_pdu).unwrap();
        println!("stripped_pdu: {:?}", s);

        let mut vec: Vec<u8> = repeat(0u8)
            .take(MutableEthernetPacket::minimum_packet_size())
            .collect();
        let mut ethernet_packet = MutableEthernetPacket::new(&mut vec[..]).unwrap();
        ethernet_packet.set_destination(self.dst.mac.unwrap());
        ethernet_packet.set_source(self.src.mac.unwrap());
        ethernet_packet.set_ethertype(EtherTypes::Ipv4);
        ethernet_packet.set_payload(stripped_pdu);

        println!("Sending packet: {:?}", ethernet_packet);

        self.sender.send_to(&ethernet_packet.to_immutable(), None).unwrap()
    }
}
