use core::str;
use std::{env, error::Error, fs::OpenOptions, io::Result, net::UdpSocket};

use regex::Regex;

fn main() {
    let args: Vec<String> = env::args().collect();
    dbg!(&args);
    //
    // TODO wright a args parser
    //
    if args.len() < 2 {
        panic!("Error: No port specifed with -p 1")
    }

    if args[1] != "-p" {
        panic!("Error: No port specifed with -p")
    }

    let port_wrapped = args[2].parse::<i32>();

    match port_wrapped {
        Ok(port) => {
            println!("Listing on port {}", port);
            listen(port);
        }
        Err(err) => {
            panic!("Error: Typing to parse port got this error {}", err)

        }

    }
}


fn listen(port: i32) -> std::io::Result<()>{
    loop {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", port))?;

        let mut buffer = [0; 400];

        let (amt, src) = socket.recv_from(&mut buffer)?;


        let buffer = &mut buffer[..amt];

        let firewall_log  = str::from_utf8(&buffer);

        match firewall_log {
            Ok(log) => {
                //println!("{}", log);
                parse_log(&log);
            }

            Err(err) => {
                panic!("Error: Tying to convert udp packet data to UTF8 String {}", err);
            }
            
        }

        
    }

}

fn write_log(log: &str) -> std::io::Result<()> {
    let (first, last) = log.split_at(4);
    let mut log_file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open("./firewall-log.txt")?;


    Ok(())
}


fn parse_log(log: &str) {
    let re = Regex::new(r"(\d\d:\d\d:\d\d) (\S+) kernel: (\w+) IN=(\w+) OUT= MAC=(\S+) SRC=(\S+) DST=(\S+) LEN=(\d+) TOS=(\S+) PREC=(\S+) TTL=(\d+) ID=(\d+) PROTO=(\w+) SPT=(\d+) DPT=(\d+) SEQ=(\d+) ACK=(\d+) WINDOW=(\d+) RES=(\S+) (\w+) URGP=(\d+)").unwrap();


    let mut result = vec![];

    for (_, [time, hub, typ, addp, mac, src, dst, len, tos, prec, ttl, id, proto, spt, dpt, seq, ack, window, res, flag, urgp]) in re.captures_iter(log).map(|c| c.extract()) {
        result.push((time, hub, typ, addp, mac, src, dst, len.parse::<i32>().unwrap(), tos, prec, ttl.parse::<i32>().unwrap(), id.parse::<i32>().unwrap(), proto, spt.parse::<i32>().unwrap(), 
            dpt.parse::<i32>().unwrap(),seq.parse::<f64>().unwrap(), ack.parse::<i32>().unwrap(), window.parse::<i32>().unwrap(), res, flag, urgp));
    }

    let log = result[0];

    println!("A {ptype} Packet has been dropped:\n\t- Src-IP:{src}\n\t- Dst-IP:{dst}\n\t- Src-Port:{spt}\n\t- Dst-Port:{dpt}", ptype = log.12,src=log.5,dst=log.6,spt=log.13,dpt=log.14);

}
