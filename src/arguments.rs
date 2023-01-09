use clap::Parser;
use std::net::{SocketAddr, Ipv4Addr, IpAddr, TcpStream};
use std::process::exit;
use std::time::Duration;
use console::style;
use std::thread;

mod services;
use services::*;

const AUTHOR: &str = "liquidlegs";
const VERSION: &str = "0.1.0";
const MIN_PORT: u32 = 1;
const MAX_PORT: u32 = 65535;

#[derive(Debug, Parser, Clone)]
#[clap(author, version, about, help = "")]
pub struct Arguments {
  #[clap(value_parser)]
  /// Ip Address
  pub ip: String,

  #[clap(short, long, help = "Ports to scan. Example: 1-1024, 1,2,3,4\n[default: 1-65535]")]
  /// The Port(s) you want to scan.
  pub ports: Option<String>,

  #[clap(long, default_value_if("debug", Some("false"), Some("true")), min_values(0))]
  /// Display debug information.
  pub debug: bool,

  #[clap(long, default_value_if("verbose", Some("false"), Some("true")), min_values(0))]
  /// Display verbose information about the port scan
  pub verbose: bool,

  #[clap(short, long, default_value = "300")]
  /// The timeout in ms before a port is dropped
  pub timeout: u64,

  #[clap(short = 'T', long, default_value = "650")]
  /// TThe number of threads
  pub threads: u32,
}

// Displays help information.
pub fn display_help(bin: &str) -> () {
  println!(
"
{} - {}
{}

{}:
    {} <IP> [OPTIONS]

{}:
    <IP>    IP Address

{}:
        --{}                     Displays debug information
    -h, --{}                      Displays help information
    -p, --{}   <PORTS>           Ports to scan. Example: 1-1024, 1,2,3,4 [default: 1-65535]
    -t, --{} <TIMEOUT>         The timeout in ms before a port is dropped [default: 300]
    -T, --{} <THREADS>         The number of threads [default: 650]
        --{}                   Display verbose information about the port scan", 
  style("lethal_potato").red().bright(), style(VERSION).yellow().bright(), style(AUTHOR).yellow().bright(), 
  style("USAGE").yellow(), bin, style("ARGS").yellow(), style("OPTIONS").yellow(), style("debug").cyan(), 
  style("help").cyan(), style("ports").cyan(), style("timeout").cyan(), style("threads").cyan(), style("verbose").cyan()
  );
}

// Module contains simple functions used for displaying different types of messages.
pub mod fmt {
  use console::style;

  pub fn f_error(msg: &str, value: &str, error_enum: &str) -> () {
    println!("{}: {} {} - {}", style("Error").red().bright(), msg, style(value).cyan(), style(error_enum).red());
  }

  pub fn f_debug(msg: &str, value: &str) -> () {
    println!("{} {} {}", style("Debug =>").red().bright(), style(msg).yellow(), style(value).cyan());
  }
}

// Used to determine how ports should be generated.
#[derive(Debug, Clone, PartialEq)]
pub enum Pattern {
  Range,
  Csv,
  Single,
  Unknown,
}

// Struct stores the ip address information and a vec
// containing all the ports to be scanned.
#[derive(Debug, Clone)]
pub struct IpData {
  a: u8,
  b: u8,
  c: u8,
  d: u8,
  ports: Vec<u16>,
}

impl IpData {
  pub fn new() -> IpData {
    IpData {
      a: 0,
      b: 0,
      c: 0,
      d: 0,
      ports: Default::default(),
    }
  }
}

impl Arguments {  

  /**Function parses u8 values.
   * Params:
   *  value: &str {The value to parse as a slice}
   * Returns u8.
   */
  pub fn parse_u8(value: &str) -> u8 {
    let mut out: u8 = 0;

    match value.parse::<u8>() {
      Ok(s) => { out = s; },
      Err(e) => {
        fmt::f_error("unable to parse", value.to_string().as_str(), format!("{}", e).as_str());
        exit(1);
      }
    }

    out
  }

  /**Function parses u16 values.
   * Params:
   *  value: &str {The value to parse as a slice}
   * Returns u8.
   */
  pub fn parse_u32(value: &str) -> u32 {
    let mut out: u32 = 0;

    match value.parse::<u32>() {
      Ok(s) => { out = s; },
      Err(e) => {
        fmt::f_error("unable to parse", value.to_string().as_str(), format!("{}", e).as_str());
        exit(1);
      }
    }

    out
  }

  /**Function works out ports should be generated and what ports should be scanned.
   * Params:
   *  text: String {The port string}
   * Returns Pattern.
   */
  pub fn find_pattern(text: String) -> Pattern {
    let out = Pattern::Unknown;
    
    let c_text = text.clone();
    let mut split_text: Vec<&str> = c_text.split("-").collect();

    if split_text.len() == 2 {
      return Pattern::Range;
    }

    split_text = c_text.split(",").collect();
    if split_text.len() >= 2 {
      return Pattern::Csv;
    }

    if split_text.len() == 1 {
      match split_text[0].parse::<usize>() {
        Ok(_) => { return Pattern::Single; },
        Err(e) => {
          fmt::f_error("unable to parse port", split_text[0], format!("{}", e).as_str());
          exit(1);
        }
      }
    }

    out
  }

  /**Function parses each octet in the network byte address as well as the port and returns a struct with the information.
   * Params:
   *  &self
   * Returns IpData.
   */
  pub fn create_address(&self) -> IpData {
    let clone_ip = self.ip.clone();
    let ip_str: Vec<&str> = clone_ip.split(".").collect();
    let mut port_string = String::new();
    let mut address = IpData::new();

    // Check if ip is valid.
    if ip_str.len() < 4 || ip_str.len() > 4 {
      println!("{}: Invalid ip address [{}]", style("Error").red(), style(clone_ip).cyan());
      exit(1);
    }

    address.a = Self::parse_u8(ip_str[0]);
    address.b = Self::parse_u8(ip_str[1]);
    address.c = Self::parse_u8(ip_str[2]);
    address.d = Self::parse_u8(ip_str[3]);

    // Get the port string if it exists.
    if let Some(port) = self.ports.clone() {
      port_string = port;
    }
    
    // We will scan all ports if no port string exists.
    else {
      for i in MIN_PORT..MAX_PORT+1 {
        address.ports.push(i as u16);
      }

      return address;
    }

    // Check if port is using the '-' for range.
    let c_port = port_string.clone();
    let pattern = Self::find_pattern(c_port);

    // Ports are generated and pushed to the vec based on the range set by the user.
    if pattern == Pattern::Range {
      let clone_port = port_string.clone();
      let split_port: Vec<&str> = clone_port.split("-").collect();
      
      let port_start = Self::parse_u32(split_port[0]);
      let port_end = Self::parse_u32(split_port[1]);

      for i in port_start..port_end+1 {
        address.ports.push(i as u16);
      }
    }
    
    // Ports are generated and pushed into the vec based on comma separated values.
    else if pattern == Pattern::Csv {
      let clone_port = port_string.clone();
      let split_port: Vec<&str> = clone_port.split(",").collect();

      for i in split_port {
        match i.parse::<u16>() {
          Ok(s) => {
            address.ports.push(s);
          },
          Err(e) => {
            fmt::f_error("unable to parse port", i.to_string().as_str(), format!("{}", e).as_str());
            exit(1);
          }
        }
      }
    }

    // A single value is pushed into the vec.
    else if pattern == Pattern::Single {
      let clone_port = port_string.clone();
      match clone_port.parse::<u16>() {
        Ok(s) => { address.ports.push(s); },
        Err(e) => {
          fmt::f_error("unable to parse port", port_string.as_str(), format!("{}", e).as_str());
          exit(1);
        }
      }
    }

    else if pattern == Pattern::Unknown {
      fmt::f_error("Invalid port syntax", port_string.as_str(), "");
      exit(1);
    }

    address
  }

  /**Function begins the port scan.
   * Params:
   *  &self
   * Returns nothing.
   */
  pub fn begin_scan(&self) -> () {
    // We prepare our network information here.
    let ip = self.create_address();
    println!("{} Starting scan on host {} over {} ports", style("Potato =>").red().bright(),
    style(format!("[{}.{}.{}.{}]", ip.a, ip.b, ip.c, ip.d)).cyan(), style(format!("[{}]", ip.ports.clone().len())).cyan());
    println!("");

    let mut address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip.a, ip.b, ip.c, ip.d)), 1);
    let ports = ip.ports.clone();

    // start_time will be used to generated the elasped time at the end of the scan.
    let start_time = std::time::Instant::now();
    
    if self.threads == 0 || self.threads == 1 || self.threads > ip.ports.len() as u32 {

      for i in ports {
        address.set_port(i);
        self.standard_port_scan(address);
      }

      println!("\n{}: Scan completed in {:?}\n", style("OK").yellow().bright(), style(start_time.elapsed()).cyan())
    }

    else if self.threads > 1 {
      self.init_threads(ip);
      println!("\n{}: Scan completed in {:?}\n", style("OK").yellow().bright(), style(start_time.elapsed()).cyan())
    }
  }

  /**function scans a port and displays whether the port was open or closed. 
   * Params:
   *  &self
   *  address: SocketAddr {The ip address and port that will be passed to the connect_timeout function}
   * Returns nothing.
  */
  pub fn standard_port_scan(&self, address: SocketAddr) -> () {
    match TcpStream::connect_timeout(&address, Duration::from_millis(self.timeout)) {
      Ok(_) => {
        if let Some(port_name) = service_map(format!("{}", address.port()).as_str()) {
          println!("{}: {} - {}", style(format!("{}/tcp", address.port())).yellow().bright(), style("Open").green().bright(),
          style(port_name).cyan());
        }
        else {
          println!("{}: {}", style(format!("{}/tcp", address.port())).yellow().bright(), style("Open").green().bright());
        }
      },

      Err(_) => {
        if self.verbose == true {
          println!("{}: {}", style(format!("{}/tcp", address.port())).yellow().bright(), style("closed").red().bright());
        }
      }
    }
  }

  /**Function sets up the stage and scans multiple ports using the specified number of threads by the user.
   * Params:
   *  &self
   *  ip:   IpData {The structure that holds the ip address and ports to be scanned}
   * Returns nothing.
   */
  pub fn init_threads(&self, ip: IpData) -> () {
    let th_timeout = self.timeout.clone();                        // Sets the thread timeout.
    let th_verbose = self.verbose.clone();                       // Sets the thread verbose flag.
    let th_debug = self.debug.clone();                           // Sets the thread debug flag.
    let scanable_ports = ip.ports.clone();

    // The ports per chunk for each thread is calculated.
    let total_ports = ip.ports.len() as u16;
    let port_chunk = total_ports / self.threads.clone() as u16;
    let remainder_chunk = total_ports % self.threads.clone() as u16;

    if self.debug == true {
      fmt::f_debug("Ports allocated per thread", format!("{}", port_chunk).as_str());
    }
    
    // let port_chunks: Vec<u16> = Default::default();
    let mut handles: Vec<std::thread::JoinHandle<()>> = Default::default();
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip.a, ip.b, ip.c, ip.d)), 1);

    // Sets the boundries for each port vec to be generated.
    let mut port_counter: u16 = 0;
    let mut thread_counter = self.threads.clone();     
    let mut port_chunk_start: u16 = 0;
    let mut port_chunk_end: u16 = port_chunk;

    while thread_counter > 0  {

      // Tempoarily stores ports to hand off to each thread.
      let mut temp_ports: Vec<u16> = Default::default();

      // Segements the overall port vec into a smaller vec.
      for i in port_chunk_start..port_chunk_end {
        temp_ports.push(scanable_ports[i as usize]);
        
        if port_counter as usize +1 > MAX_PORT as usize {
          port_counter = MAX_PORT as u16;
        }
        
        else {
          port_counter += 1;
        }
      }

      let th_port_chunk = temp_ports.clone();
      let mut ip_clone = address.clone();
      
      // The thread is pushed and stores in a vec of handles upon creation.
      handles.push(thread::spawn(move || {
        Self::thread_run_scan(&mut ip_clone, th_port_chunk, th_debug, th_verbose, th_timeout);
      }));      

      if port_chunk_start as usize + port_chunk as usize > MAX_PORT as usize {
        port_chunk_start = MAX_PORT as u16 - port_chunk;
      }

      else {
        port_chunk_start += port_chunk;
      }

      if port_chunk_end as usize + port_chunk as usize > MAX_PORT as usize {
        port_chunk_end = MAX_PORT as u16;
      }

      else {
        port_chunk_end += port_chunk;
      }

      temp_ports.clear();
      thread_counter -= 1;
    }

    // Code block deals with the reaminder ports that are left over from a calcuation
    // that results in a float instead of an integer.
    if remainder_chunk > 0 {
      
      if self.debug == true {
        println!("{} {} {} {}", style("debug =>").red().bright(),
        style("Found").yellow(), style(remainder_chunk).cyan(), style("remaining ports. Allocating to one or multiple threads").yellow());
      
        println!("{} {}={} {}={} {}={}", style("Debug =>").red().bright(), 
        style("Start").yellow(), style(port_chunk_start).cyan(), style("End").yellow(), style(port_chunk_end).cyan(),
        style("chunk").yellow(), style(port_chunk).cyan());
      }

      // Assign the correct starting and end chunk values to scan remaining ports.
      port_chunk_end = port_chunk_start + remainder_chunk;
      port_chunk_start = port_chunk_end- remainder_chunk;
      
      if self.debug == true {
        fmt::f_debug("Correcting port range", "");
        
        println!("{} {}={} {}={}", style("Debug =>").red().bright(), 
        style("Start").yellow(), style(port_chunk_start).cyan(), style("End").yellow(), style(port_chunk_end).cyan());
      }

      // Push remaining ports into a vec.
      let mut ip_clone = address.clone();
      let mut remainder_ports: Vec<u16> = Default::default();

      // Calculate the number of threads that should be created for each remainder divided by the size of each port chunk.
      let mut remaining_port_loops = ((remainder_chunk as f32) / port_chunk as f32).ceil() as u16;
      let mut port_chunk_pos = port_chunk_start.clone()+port_chunk;

      while remaining_port_loops > 0 {
        
        // Push remaining ports into a temporary vec.
        for i in port_chunk_start as u32..port_chunk_pos as u32 +1 as u32 {
          remainder_ports.push(i as u16);
        }

        // Create the thread and clear the port vec through each iteration.
        let th_remainder_ports = remainder_ports.clone();
        handles.push(thread::spawn(move || {
          Self::thread_run_scan(&mut ip_clone, th_remainder_ports, th_debug, th_verbose, th_timeout);
        }));
        
        remainder_ports.clear();
        
        if port_chunk_start as u32 + port_chunk as u32 > port_chunk_end as u32 {
          port_chunk_start += remaining_port_loops;
        }

        else {
          port_chunk_start += port_chunk;
        }

        if port_chunk_pos as u32 + port_chunk as u32 > port_chunk_end as u32 {
          port_chunk_pos = port_chunk_end;
        }

        else {
          port_chunk_pos += port_chunk;
        }

        if self.debug == true {
          // println!("port_chunk_start={} port_chunk_end_pos={}", port_chunk_start, port_chunk_end_pos);
          println!("{} ch_st={} ch={} ch_pos={} ch_end={} p_lps={} rem_ch={}", style("Debug =>").red().bright(), 
          style(port_chunk_start).cyan(), style(port_chunk).cyan(), style(port_chunk_pos).cyan(), 
          style(port_chunk_end).cyan(), style(remaining_port_loops).cyan(), style(remainder_chunk).cyan());
        }

        remaining_port_loops -= 1;
      }
    }

    std::thread::sleep(Duration::from_secs(2));
    // Thread handles are joined the main thread here.
    for i in handles {
      
      let id = i.thread().id();
      if let Ok(_) = i.join() {
        if self.debug.clone() == true {
          fmt::f_debug("joined thread to main with id", format!("{:?}", id).as_str());
        }
      }
    }
  }

  /**Function is called by each thread and scans the assigned port chunk.
   * Params:
   *  ip_clone: &mut SocketAddr {The ip address and port structure}
   *  ports:    Vec<u16>        {A vec that contains a list of ports to scan}
   *  debug:    bool            {Shows debug messages when enabled}
   *  verbose:  bool            {Shows closed port messages when enabled}
   *  timeout:  u64             {The time before the socket times out and moves on the next}
   * Returns nothing.
   */
  pub fn thread_run_scan(ip_clone: &mut SocketAddr, ports: Vec<u16>, debug: bool, verbose: bool, timeout: u64) -> () {
    let th_debug = debug.clone();
    let th_timeout = timeout.clone();
    let th_verbose = verbose.clone();

    if th_debug == true {
      let port_range: (u16, u16) = (ports[0], ports[ports.len() as usize -1]);

      fmt::f_debug(format!("Starting thread with {:?} and will be scanning ports ",
      thread::current().id()).as_str(), format!("[{}-{}]", port_range.0, port_range.1).as_str());
    }

    // Ports are scanned here.
    for i in ports {
      ip_clone.set_port(i);
      
      match TcpStream::connect_timeout(&ip_clone, Duration::from_millis(th_timeout)) {
        Ok(_) => {
          if let Some(port_name) = service_map(format!("{}", ip_clone.port()).as_str()) {
            println!("{}: {} - {}", style(format!("{}/tcp", ip_clone.port())).yellow().bright(), style("Open").green().bright(),
            style(port_name).cyan());
          }
          else {
            println!("{}: {}", style(format!("{}/tcp", ip_clone.port())).yellow().bright(), style("Open").green().bright())
          };
        },

        Err(_) => {
          if th_verbose == true {
            println!("{}: {}", style(format!("{}/tcp", ip_clone.port())).yellow().bright(), style("Closed").red().bright());
          }
        }
      }
    }
  }
}