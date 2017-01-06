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

/// Naive packet mirror written in Rust.

extern crate pmirror;

#[macro_use]
extern crate log;
extern crate env_logger;

use std::io::Write;

use pmirror::mirror::start_mirroring;
use pmirror::mirror::gtpu_pdu::GtpUPduPacketMirror;

// Show usage and exit the program.
fn usage(command: &str) {
    writeln!(std::io::stderr(), "usage: {} SOURCE_IF TARGET_IF [FILTER]",
             command).unwrap();
    std::process::exit(2);
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 3 {
        usage(&args[0].to_string());
    }

    let (src, dst) = (&args[1], &args[2]);
    let filter: String = if args.len() >= 4 {
        args[3..].join(" ")
    } else {
        String::new()
    };

    start_mirroring::<GtpUPduPacketMirror>(src, dst, filter.as_str());
}
