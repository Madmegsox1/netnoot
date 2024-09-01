use core::str;
use std::collections::HashMap;
use std::{env, error::Error, fs::{File, OpenOptions}, io::{Result, Write}, iter::Map, net::UdpSocket};

use regex::Regex;
use sqlite::{Connection, State};

fn main() {
    let args: Vec<String> = env::args().collect();
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


fn listen(port: i32) -> Result<()>{
    let mut log_file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open("./firewall-log.txt")?;

    let conn = Connection::open("connections.db").unwrap();

    conn.execute("CREATE TABLE IF NOT EXISTS port_count (
    ID integer primary key,
    Port integer not null unique,
    Count integer not null
            )").unwrap();

    conn.execute("CREATE TABLE IF NOT EXISTS ip_count (
            ID integer primary key,
            Ip text not null unique,
            Count integer not null
            )").unwrap();

    loop {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", port))?;

        let mut buffer = [0; 400];

        let (amt, src) = socket.recv_from(&mut buffer)?;


        let buffer = &mut buffer[..amt];

        let firewall_log  = str::from_utf8(&buffer);

        match firewall_log {
            Ok(log) => {
                let result = write_log(log, &mut log_file);
                parse_log(&log, &conn);

                match result {
                    Ok(()) => {
                    }
                    Err(e) => {
                        println!("Error: Tying to write to log file {}", e);
                    }
                    
                }
            }

            Err(err) => {
                panic!("Error: Tying to convert udp packet data to UTF8 String {}", err);
            }
            
        }

        
    }

}

fn write_log(log: &str, log_file: &mut File) -> std::io::Result<()> {
    let (first, last) = log.split_at(4);

    writeln!(log_file, "{}",last)?;
    log_file.flush()?;

    Ok(())
}


fn parse_log(log: &str, conn: &Connection) {
    let re = Regex::new(r"(\d\d:\d\d:\d\d) (\S+) kernel: (\w+) IN=(\w+) OUT= MAC=(\S+) SRC=(\S+) DST=(\S+) LEN=(\d+) TOS=(\S+) PREC=(\S+) TTL=(\d+) ID=(\d+) PROTO=(\w+) SPT=(\d+) DPT=(\d+) SEQ=(\d+) ACK=(\d+) WINDOW=(\d+) RES=(\S+) (\w+) URGP=(\d+)").unwrap();


    let mut result = vec![];

    if re.is_match(log) {

        for (_, [time, hub, typ, addp, mac, src, dst, len, tos, prec, ttl, id, proto, spt, dpt, seq, ack, window, res, flag, urgp]) in re.captures_iter(log).map(|c| c.extract()) {
            result.push((time, hub, typ, addp, mac, src, dst, len.parse::<i32>().unwrap(), tos, prec, ttl.parse::<i32>().unwrap(), id.parse::<i32>().unwrap(), proto, spt.parse::<i32>().unwrap(), 
                dpt.parse::<i32>().unwrap(),seq.parse::<f64>().unwrap(), ack.parse::<i32>().unwrap(), window.parse::<i32>().unwrap(), res, flag, urgp));
        }

        let log = result[0];

        let ip: String = log.5.to_string();
        let mut ip_count: i64 = 1;

        let mut statment= conn.prepare("SELECT Count FROM ip_count WHERE Ip = ?").expect("Error: Tying to select count from ip_count table");
        statment.bind((1, log.5)).expect("Error: Tying to select count from ip_count table");

        if let Ok(State::Row) = statment.next() {
            ip_count += statment.read::<i64, _>("Count").unwrap();
        }

        if ip_count == 1 {
            conn.execute(format!("INSERT INTO ip_count VALUES (NULL,'{}', {})", ip, ip_count)).expect("Error: Trying to insert into ip_count table");
        }
        else {
            conn.execute(format!("UPDATE ip_count SET Count = {} WHERE Ip = '{}'", ip_count, ip)).expect("Error: Tying to update ip_count table");
        }

        let port: i64 = log.14.into();
        let mut port_count: i64 = 1;
        
        let mut statment= conn.prepare("SELECT Count FROM port_count WHERE Port = ?").expect("Error: Tying to select count from port_count table");
        statment.bind((1, port)).expect("Error: Tying to select count from port_count table");

        if let Ok(State::Row) = statment.next() {
            port_count += statment.read::<i64, _>("Count").unwrap();
        }

        if port_count == 1 {
            conn.execute(format!("INSERT INTO port_count VALUES (NULL, {}, {})", port, port_count)).expect("Error: Trying to insert into ip_count table");
        }
        else {
            conn.execute(format!("UPDATE port_count SET Count = {} WHERE Port = '{}'", port_count, port)).expect("Error: Tying to update ip_count table");
        }


        println!("A {ptype} Packet has been dropped:\n\t- Src-IP:{src} | {count_ip}\n\t- Dst-IP:{dst}\n\t- Src-Port:{spt}\n\t- Dst-Port:{dpt} | {count_port}", ptype = log.12,src=log.5,count_ip=ip_count,dst=log.6,spt=log.13,dpt=log.14, count_port=port_count);

    }
}
