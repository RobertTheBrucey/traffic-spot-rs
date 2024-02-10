use pcap::{Device, Capture};
use std::process::Command;
use std::time::{Duration, Instant};
use std::thread;
use clap::Parser;
use default_net;
use itertools::Itertools;
use std::ffi::OsString;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
   //IP - Optional
   #[arg(short, long)]
   address: Option<String>,

   //Port(s) - Required
   #[arg(short, long, required = true)]
   ports: Option<Vec<u64>>,

   //Start command - Required
   #[arg(short, long, required = true)]
   start_command: Option<String>,

   //Finish command - Optional
   #[arg(short, long)]
   finish_command: Option<String>,

   //Timeout - Optional
   #[arg(short, long, default_value = "900")]
   timeout: Option<u64>,

   //Debug Flag
   #[arg(short, long, action)]
   debug: bool,
   //Check command
   //Packet filter?
}

fn main() {
    let mut running = false;
    let cli = Cli::parse();
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
            .find(|dev| {
                  dev
                  .addresses
                  .iter()
                  .any(|addr| addr.addr.to_string() == ip)
            })
            .expect(format!("Could not find interface with IP: {}", ip).as_str());
    println!("Interface found: {:?}\nStarting Capture.", device);

    // Open the network device for capture
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .timeout(1000) //Required for responsive capture
        .open()
        .unwrap()
        .setnonblock()
        .unwrap();

    // Set a BPF filter to capture only UDP traffic on ports specified
    let port_string = "(udp dst port ".to_owned() + 
        cli.ports.as_ref().unwrap().into_iter().join(" or udp dst port ").as_str() + 
        ")";
    cap.filter(format!("{} and dst host {}", port_string, ip).as_str(), true)
        .expect("Error setting capture filter.");

    println!("Capture started for UDP traffic on {}:{:?}", ip, cli.ports.unwrap());
    let mut last_packet_time = Instant::now();
    let mut p_count = 0;
    // Monitor indefinitely
    loop {
        //Clear the buffer since last read - ideally this should be it's own thread.
        while let Ok(packet) = cap.next_packet() {
            p_count += 1;
            // Access the packet data - Useful for counting clients
            let _data = packet;
            //println!("Received packet: {:?}", data); //For deep debugging only
            last_packet_time = Instant::now();
            if !running {
                //Startup
                println!("Starting Service");
                #[cfg(target_family="unix")]
                let s_output = Command::new("sh").arg("-c").arg(OsString::from(cli.start_command.as_ref().unwrap())).spawn();
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
                #[cfg(target_family="unix")]
                let f_output = Command::new("sh").arg("-c").arg(OsString::from(cli.finish_command.as_ref().unwrap())).spawn();
//                #[cfg(target_family="windows")] //Future Windows support
                println!("Stop command output: {:?}", f_output);
            } else {
                println!(" Resetting running flag for next start");
            }
            running = false;
            //Clear buffer
            //while let Ok(_packet) = cap.next_packet() {}
        }
        thread::sleep(std::time::Duration::from_millis(1000));
    }
}
