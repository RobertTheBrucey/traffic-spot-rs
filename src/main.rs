use clap::{Args, Parser};
use default_net;
use itertools::Itertools;
use pcap::{Capture, Device};
use std::ffi::OsString;
use std::process::Command;
use std::string::String;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    ports: Ports,
    //IP - Optional
    #[arg(short, long)]
    address: Option<String>,

    //Start command - Required
    #[arg(short, long, required = true)]
    start_command: Option<String>,

    //Finish command - Optional
    #[arg(short, long)]
    finish_command: Option<String>,

    //Timeout - Optional
    #[arg(long, default_value = "900")]
    timeout: Option<u64>,

    //Debug Flag
    #[arg(short, long, action)]
    debug: bool,
    //Check command
    //Packet filter?
}

#[derive(Args)]
#[group(required = true)]
struct Ports {
    //UDP & TCP Ports
    #[arg(short = 'p', long)]
    both: Option<Vec<u64>>,

    #[arg(short, long)]
    tcp: Option<Vec<u64>>,

    #[arg(short, long)]
    udp: Option<Vec<u64>>,
}

fn generate_port_str(ports: &Ports) -> String {
    let mut port_string = String::from("( ");
    if ports.both.is_some() {
        port_string.push_str("dst port ");
        port_string.push_str(
            ports
                .both
                .as_ref()
                .unwrap()
                .into_iter()
                .join(" or dst port ")
                .as_str(),
        );
        port_string.push_str(" ");
    }

    if ports.udp.is_some() {
        if ports.both.is_some() {
            port_string.push_str("or ");
        }
        port_string.push_str("udp dst port ");
        port_string.push_str(
            ports
                .udp
                .as_ref()
                .unwrap()
                .into_iter()
                .join(" or udp dst port ")
                .as_str(),
        );
        port_string.push_str(" ");
    }

    if ports.tcp.is_some() {
        if ports.both.is_some() || ports.udp.is_some() {
            port_string.push_str("or ");
        }
        port_string.push_str("tcp dst port ");
        port_string.push_str(
            ports
                .tcp
                .as_ref()
                .unwrap()
                .into_iter()
                .join(" or udp dst port ")
                .as_str(),
        );
        port_string.push_str(" ");
    }

    port_string.push_str(")");
    return port_string;
}

fn generate_pretty_port_str(ports: &Ports) -> String {
    let mut port_string = String::from("");
    if ports.udp.is_some() || ports.both.is_some() {
        port_string.push_str("UDP: ");
    }
    if ports.udp.is_some() {
        port_string.push_str(ports.udp.as_ref().unwrap().into_iter().join(",").as_str());
        if ports.tcp.is_some() || ports.both.is_some() {
            port_string.push_str(",");
        }
    }
    if ports.both.is_some() {
        port_string.push_str(ports.both.as_ref().unwrap().into_iter().join(",").as_str());
    }
    if ports.tcp.is_some() || ports.both.is_some() {
        port_string.push_str(" TCP: ");
    }
    if ports.tcp.is_some() {
        port_string.push_str(ports.tcp.as_ref().unwrap().into_iter().join(",").as_str());
    }
    if ports.both.is_some() {
        if ports.tcp.is_some() {
            port_string.push_str(",");
        }
        port_string.push_str(ports.both.as_ref().unwrap().into_iter().join(",").as_str());
    }

    port_string.push_str(")");
    return port_string;
}

fn main() {
    let mut running = false;
    let cli = Cli::parse();
    let ports = cli.ports;
    let ip: String;
    let timeout = Duration::from_secs(cli.timeout.unwrap());

    if cli.address.is_some() {
        ip = cli.address.unwrap();
        println!("Using provided IP {}, to find appropriate interface.", ip);
    } else {
        println!("IP address not specified, searching for default outbound IP.");
        ip = default_net::get_default_interface()
            .expect("Could not determine default IP, please specify with -a <address>")
            .ipv4[0]
            .to_string()
            .split("/")
            .next()
            .expect("No default device found, specify -a <address> manually")
            .to_string();
        println!("Found default IP: {}", ip);
    }

    //Tie IP to Device
    let devices = Device::list().expect("Error listing network interfaces");
    if cli.debug {
        dbg!(&devices);
    }

    let device = devices
        .into_iter()
        .find(|dev| dev.addresses.iter().any(|addr| addr.addr.to_string() == ip))
        .expect(format!("Could not find interface with IP: {}", ip).as_str());
    println!("Interface found: {:?}\nStarting Capture.", device);

    // Open the network device for capture
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .timeout(1000) //Required for responsive capture
        .open()
        //.unwrap()
        //.setnonblock()
        .unwrap();

    // Set a BPF filter to capture only UDP traffic on ports specified
    let port_string = generate_port_str(&ports);
    cap.filter(
        format!("{} and dst host {}", port_string, ip).as_str(),
        true,
    )
    .expect(
        format!(
            "Error setting capture filter: '{} and dst host {}'",
            port_string, ip
        )
        .as_str(),
    );

    println!(
        "Capture started for UDP traffic on {} Ports: {}",
        ip,
        generate_pretty_port_str(&ports)
    );
    let mut last_packet_time = Instant::now();
    let mut p_count = 0;
    // Set up monitoring thread
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        while let Ok(_packet) = cap.next_packet() {
            let packet_time = Instant::now();
            tx.send(packet_time).unwrap();
        }
    });
    // Monitor indefinitely
    loop {
        //Clear the buffer since last read - ideally this should be it's own thread.
        while let Ok(thread_packet_time) = rx.try_recv() {
            last_packet_time = thread_packet_time;
            p_count += 1;
            if !running {
                //Startup
                println!("Starting Service");
                #[cfg(target_family = "unix")]
                let s_output = Command::new("sh")
                    .arg("-c")
                    .arg(OsString::from(cli.start_command.as_ref().unwrap()))
                    .spawn();
                //                #[cfg(target_family="windows")] //Future Windows support
                println!("Start command output: {:?}", s_output);
                running = true;
            }
        }
        if cli.debug {
            println!("Packets recieved: {}", p_count);
        }
        p_count = 0;
        if last_packet_time.elapsed() >= timeout && running {
            //Shutdown
            print!("Timeout Expired:");
            if cli.finish_command.is_some() {
                println!(" Stopping Service");
                #[cfg(target_family = "unix")]
                let f_output = Command::new("sh")
                    .arg("-c")
                    .arg(OsString::from(cli.finish_command.as_ref().unwrap()))
                    .spawn();
                //#[cfg(target_family="windows")] //Future Windows support
                println!("Stop command output: {:?}", f_output);
            } else {
                println!(" Resetting running flag for next start");
            }
            running = false;
        }
        thread::sleep(std::time::Duration::from_millis(1000));
    }
}
