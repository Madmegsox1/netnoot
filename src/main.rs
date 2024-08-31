use std::{env, error::Error, io::Result, net::UdpSocket};

fn main() {
    let args: Vec<String> = env::args().collect();
    //
    // TODO wright a args parser
    //
    if args.len() < 2 {
        panic!("Error: No port specifed with -p")
    }

    if args[0] != "-p" {
        panic!("Error: No port specifed with -p")
    }

    let port_wrapped = args[1].parse::<i32>();

    match port_wrapped {
        Ok(port) => {


        }
        Err(err) => {
            panic!("Error: Typing to parse port got this error {}", err)

        }

    }
}


fn listen(port: i32) -> std::io::Result<()>{
    {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", port))?;

        let mut buffer = [0; 400];

        let (amt, src) = socket.recv_from(&mut buffer)?;

        let buffer = &mut buffer[..amt];
        buffer.reverse();

        
    }

    Ok(())

}
