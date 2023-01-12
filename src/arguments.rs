use chrono::Utc;
use clap::Parser;
use std::io::{Write, ErrorKind};
use std::net::{SocketAddr, Ipv4Addr, IpAddr, TcpStream};
use std::path::Path;
use std::process::exit;
use std::time::Duration;
use console::style;
use std::{thread, env, fs::{OpenOptions, File}};
use crossbeam::channel::{unbounded, Sender, RecvTimeoutError};
use serde::Serialize;

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

  #[clap(short, long)]
  /// Output open ports to a json.
  pub output: Option<String>,

  #[clap(long, default_value_if("verbose", Some("false"), Some("true")), min_values(0))]
  /// Display verbose information about the port scan
  pub verbose: bool,

  #[clap(short, long, default_value = "300")]
  /// The timeout in ms before a port is dropped
  pub timeout: u64,

  #[clap(short = 'T', long, default_value = "650")]
  /// TThe number of threads
  pub threads: u32,

  #[clap(short, long, default_value_if("bannergrab", Some("false"), Some("true")), min_values(0))]
  /// Make a get request on each port to grab the banner.
  pub banner_grab: bool,

  #[clap(long, default_value = "256")]
  /// Set the max length of a banner grab.
  pub banner_len: u32,
}

// Displays help information.
pub fn display_help(bin: String) -> () {
  let mut bin_name = String::new();
  let mut split_bin: Vec<&str> = bin.split("/").collect();
  
  if split_bin.len() > 1 {
    bin_name.push_str(split_bin[split_bin.len()-1]);
  }

  else {
    split_bin = bin.split("\\").collect();
    
    if split_bin.len() > 1 {
      bin_name.push_str(split_bin[split_bin.len()-1]);
    }

    else {
      bin_name = bin;
    }
  }

  println!(
"
{} - {}
{}

{}:
    {} <IP> [OPTIONS]

{}:
    <IP>    IP Address

{}:
        --{}                          Displays debug information
    -h, --{}                           Displays help information
    -b, --{}                         Sends a GET request to the port and records the response
        --{}   <BANNER>          Sets the maxium response length for a banner grab
    -o, --{}       <OUTPUT>          Exports open ports to a json file
    -p, --{}        <PORTS>           Ports to scan. Example: 1-1024, 1,2,3,4 [default: 1-65535]
    -t, --{}      <TIMEOUT>         The timeout in ms before a port is dropped [default: 300]
    -T, --{}      <THREADS>         The number of threads [default: 650]
        --{}                        Display verbose information about the port scan", 
  style("lethal_potato").red().bright(), style(VERSION).yellow().bright(), style(AUTHOR).yellow().bright(), 
  style("USAGE").yellow(), bin_name, style("ARGS").yellow(), style("OPTIONS").yellow(), style("debug").cyan(), 
  style("help").cyan(), style("banner-grab").cyan(), style("banner-len").cyan(), style("output").cyan(), 
  style("ports").cyan(), style("timeout").cyan(), style("threads").cyan(), style("verbose").cyan()
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


#[derive(Debug, Clone)]
pub struct Flags {
  pub debug: bool,
  pub verbose: bool,
  pub timeout: u64,
  pub banner_grab: bool,
  pub banner_len: u32,
}


impl Flags {
  pub fn new() -> Flags {
    Flags {
      debug: false,
      timeout: 0,
      verbose: false,
      banner_grab: false,
      banner_len: 0,
    }
  }

  pub fn set_flags(&mut self, debug: bool, timeout: u64, verbose: bool, banner_grab: bool, banner_len: u32) -> () {
    self.debug = debug;
    self.verbose = verbose;
    self.timeout = timeout;
    self.banner_grab = banner_grab;
    self.banner_len = banner_len;
  }
}

// Tells the code what operating system is being used.
#[derive(Debug, Clone, PartialEq)]
pub enum OperatingSystem {
  Windows,
  Linux,
  Unknown,
}

// Stores the application settings.
#[derive(Debug, Clone)]
pub struct ArgumentSettings {
  pub is_valid_output_path: bool,
  pub os: OperatingSystem,
}

// Tells the code what operating system is in use and how the app should run based on the application settings.
impl ArgumentSettings {
  pub fn new() -> ArgumentSettings {
    let mut operating_system = OperatingSystem::Unknown;
    
    match env::consts::OS {
      "windows" =>  {
        operating_system = OperatingSystem::Windows;
      },

      "linux" =>    {
        operating_system = OperatingSystem::Linux;
      }

      _ =>          {
        fmt::f_error("Operating system either unknown or not supported", env::consts::OS, "");
      }
    }

    ArgumentSettings {
      is_valid_output_path: false,
      os: operating_system,
    }
  }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ThreadMessage {
  OpenPort,
  Banner,
  KeepAlive,
}

#[derive(Debug, Clone, Serialize)]
pub struct BannerResponse {
  port: u16,
  data: String
}

impl BannerResponse {
  pub fn new() -> BannerResponse {
    BannerResponse {
      port: 0,
      data: String::new(),
    }
  }
}

// Structure is used for writing output for json files.
#[derive(Debug, Clone, Serialize)]
pub struct FileOutput {
  pub host: String,
  pub ip: String,
  pub protocol: String,
  pub ports: Vec<u16>,
  pub banner_response: Vec<BannerResponse>
}

impl FileOutput {
  pub fn new() -> FileOutput {
    FileOutput {
      host: String::new(),
      ip: String::from("V4"),
      protocol: String::from("TCP"), 
      ports: Default::default(),
      banner_response: Default::default(),
    }
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

  /**Function returns the full path from the present working directory
   * Params:
   *  nothing
   * Returns String
   */
  pub fn get_current_directory() -> String {
    let mut out = String::new();
    
    match std::env::current_dir() {
      Ok(path) => {
        match path.into_os_string().into_string() {
          Ok(s) => {
            out = s;
          },
          Err(os) => {}
        }
      },
      Err(e) => {}
    }
    
    out
  }

  /**Function the ip address of the target and discovered ports and writes the output to json file.
   * Params:
   *  &mut self
   *   target: FileOutput {Contains the ip address and open ports found on the target}
   * Returns nothing. 
   */
  pub fn write_output(&self, os: OperatingSystem, target: FileOutput) -> () {
    let mut path = String::new();                               // Stores the path specified by the user.
    let mut c_path = String::new();                             
    let mut json_output = String::new();                        // Stores the output of the created json object.
    let full_path = Self::get_current_directory();              // The full path to the current directory.
    let mut path_slice= "";                                       

    let time = Utc::now();                              // The date and time in UTC as a string.
    let mut time_date = format!("{}", time);
    time_date = time_date.replace("-", "");
    time_date = time_date.replace(":", "-");

    // Check if the output path was provided.
    if let Some(p) = self.output.clone() {
      path = p.clone();
      
      // Prepare the new file path depending on the operating system.
      if os == OperatingSystem::Windows {
        if path.clone().as_bytes()[path.len()-1] != '\\' as u8 {
          path.push('\\');
        }
        
        path = format!("{}\\{}{}-output.json", full_path, path, &time_date[0..16]);
        c_path = path.clone();
        path_slice = c_path.as_str();
      }

      else if os == OperatingSystem::Linux {
        if path.clone().as_bytes()[path.len()-1] != '/' as u8 {
          path.push('/');
        }
        
        path = format!("{}{}-output.json", path, &time_date[0..16]);
        c_path = path.clone();
        path_slice = c_path.as_str();
      }
    }
    
    // Creates a file if it does not already exist.
    let create_file = move || -> bool {
      let mut out = false;
      
      match OpenOptions::new().create(true).read(true).write(true).open(path) {
        Ok(_) => {
          out = true
        },
        Err(_) => {
          match File::create(path_slice.clone()) {
            Ok(_) => {
              if self.debug == true {
                fmt::f_debug("successfully created file", path_slice.clone());
              }

              out = true;
            },

            Err(e) => {
              if e.kind() == ErrorKind::AlreadyExists {
                out = true;
              }
              
              if e.kind() != ErrorKind::AlreadyExists {
                fmt::f_error("unable to create file", path_slice.clone(), format!("{}", e).as_str());
              }
            }
          }
        }
      }

      out
    };

    // Writes the json data to the file.
    let write_file = |path: &str, buffer: String| -> bool {
      let mut out = false;
      
      match OpenOptions::new().read(true).write(true).open(path) {
        Ok(mut f) => {
          match f.write(buffer.as_bytes()) {
            Ok(s) => {
              println!("\n{}: successfully wrote {} bytes to file\n{}", style("OK").yellow().bright(), style(s).cyan(),style(path).cyan());
              out = true;
            },
            Err(e) => {
              fmt::f_error("unable to write results to file", path, format!("{}", e).as_str());
            }
          }
        },

        Err(e) => {
          fmt::f_error("unable to write file to disk", path, format!("{}", e).as_str()); 
        }
      }
      
      out
    };
    
    // Turns the FileOutput structure into a json object.
    match serde_json::to_string_pretty(&target) {
      Ok(s) => {
        json_output = s;
      },
      Err(e) => {
        println!("{}: failed to create json object - {}", style("Error").red(), style(e).red());
      }
    }

    let is_file_created = create_file();
    if is_file_created == true {
      write_file(path_slice.clone(), json_output);
    }

  }

  /**Function checks if the path provided by the user is a valid or not.
   * Params:
   *  &mut self
   * Returns bool.
   */
  pub fn check_valid_directory(&self) -> bool {
    let mut path = String::new();            // Stores the path provided by the user.
    let mut c_path = String::new();
    let mut valid_path = false;                // Flag determines if we can write output in the directory.

    // Check if a path was provided.
    if let Some(p )= self.output.clone() {
      path = p;
      c_path = path.clone();
    }

    if Path::new(&path).is_dir() == true {
      valid_path = true;
    }

    // Return if the provided path is not a valid directory.
    else {
      match std::fs::create_dir(path) {
        Ok(_) => {
          valid_path = true;
          println!("{}: Successfully created output directory {}", style("OK").yellow(), style(c_path).cyan())
        },

        Err(e) => {
          fmt::f_error("unable to create directory", c_path.clone().as_str(), format!("{}", e).as_str());
          exit(1);
        }
      }
    }

    valid_path
  }
  
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
  pub fn begin_scan(&self, settings: ArgumentSettings) -> () {
    // We prepare our network information here.
    let ip = self.create_address();
    println!("{} Starting scan on host {} over {} ports", style("Potato =>").red().bright(),
    style(format!("[{}.{}.{}.{}]", ip.a, ip.b, ip.c, ip.d)).cyan(), style(format!("[{}]", ip.ports.clone().len())).cyan());
    println!("");

    let mut file_output = FileOutput::new();
    let mut write_ports: Vec<u16> = Default::default();
    let mut banner_resp: Vec<BannerResponse> = Default::default();
    let mut address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip.a, ip.b, ip.c, ip.d)), 1);
    let ports = ip.ports.clone();

    // start_time will be used to generated the elasped time at the end of the scan.
    let start_time = std::time::Instant::now();
    
    if self.threads == 0 || self.threads == 1 || self.threads > ip.ports.len() as u32 {

      for i in ports {
        address.set_port(i);
        self.standard_port_scan(address, &mut write_ports);
      }

      if settings.is_valid_output_path == true {
        file_output.host = address.ip().to_string();
        file_output.ports = write_ports;
        file_output.ports.sort();

        self.write_output(settings.os.clone(), file_output);
      }

      println!("\n{}: Scan completed in {:?}\n", style("OK").yellow().bright(), style(start_time.elapsed()).cyan())
    }

    else if self.threads > 1 {
      self.init_threads(ip, &mut write_ports, &mut banner_resp, settings.clone());
      
      if settings.is_valid_output_path == true {             // Checks that output will be written to a valid directory before writing to the disk.
        file_output.host = address.ip().to_string();   // Data structure will be used for creating the json object.
        file_output.ports = write_ports;
        file_output.banner_response = banner_resp;

        self.write_output(settings.os.clone(), file_output);
      }
      
      println!("\n{}: Scan completed in {:?}\n", style("OK").yellow().bright(), style(start_time.elapsed()).cyan())
    }
  }

  /**function scans a port and displays whether the port was open or closed. 
   * Params:
   *  &self
   *  address: SocketAddr {The ip address and port that will be passed to the connect_timeout function}
   * Returns nothing.
  */
  pub fn standard_port_scan(&self, address: SocketAddr, write_ports: &mut Vec<u16>) -> () {
    match TcpStream::connect_timeout(&address, Duration::from_millis(self.timeout)) {
      Ok(s) => {
        write_ports.push(address.port());

        if let Some(port_name) = service_map(address.port()) {
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
  pub fn init_threads(&self, ip: IpData, write_ports: &mut Vec<u16>, banner_resp: &mut Vec<BannerResponse>, settings: ArgumentSettings) -> () {
    let mut flags = Flags::new();
    flags.set_flags(
      self.debug.clone(), 
      self.timeout.clone(), 
      self.verbose.clone(), 
      self.banner_grab.clone(),
      self.banner_len.clone()
    );

    let scanable_ports = ip.ports.clone();
    // let mut writable_ports: Vec<u16> = Default::default();
    let (th_sender, main_recv) = unbounded::<String>();

    // The ports per chunk for each thread is calculated.
    let total_ports = ip.ports.len() as u16;
    let mut port_chunk = total_ports / self.threads.clone() as u16;
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
      let c_flags = flags.clone();
      let sender_clone = th_sender.clone();
      
      // The thread is pushed and stores in a vec of handles upon creation.
      handles.push(thread::spawn(move || {
        Self::thread_run_scan(&mut ip_clone, th_port_chunk, c_flags, sender_clone);
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

      if port_chunk > remainder_chunk {
        port_chunk = ((remainder_chunk as f32) / 2 as f32) as u16;
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
        let c_flags = flags.clone();
        let sender_clone = th_sender.clone();

        handles.push(thread::spawn(move || {
          Self::thread_run_scan(&mut ip_clone, th_remainder_ports, c_flags, sender_clone);
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

      
    let mut timeout_counter = 0;
    while timeout_counter < 10 {
      
      // We will loop here and wait any incoming messages from worker thread about open ports
      match main_recv.recv_timeout(Duration::from_millis(self.timeout)) {
        Ok(s) => {
          let str_clone = s.clone();
          let mut split_msg: Vec<&str> = Default::default();

          // If we receive a message with a single 0, we do nothing.
          // However, if we receive  "number open" we will push the u16 value to a vec.
          match s.as_str() {
            "0" => {}
            _ => {
              split_msg = str_clone.split("[_]").collect();

              if split_msg.len() > 1 {

                let th_message = Self::validate_thread_message(split_msg[0]);
                if th_message == ThreadMessage::OpenPort {
                  if self.debug == true {
                    println!("added port {}", split_msg[1]);
                    fmt::f_debug("added port to output vec", split_msg[1]);
                  }
                  
                  let port = Self::parse_u32(split_msg[1]);
                  if port > 0{
                    write_ports.push(port as u16);
                    println!("{} port(s) found", style(write_ports.len()).cyan());
                  }
                }

                else if th_message == ThreadMessage::Banner {
                  if self.debug == true {
                    println!("found banner response");
                    fmt::f_debug("Banner response found for port", format!("{} {}", split_msg[1], split_msg[2]).as_str());
                  }

                  let mut banner = BannerResponse::new();
                  let port = Self::parse_u32(split_msg[1]);

                  banner.port = port as u16;
                  banner.data = format!("{}", split_msg[2]);
                  banner_resp.push(banner);
                }
              }
            }
          }
        },

        Err(e) => {
          if e == RecvTimeoutError::Timeout {
            timeout_counter += 1;   // This determines how long main_recv will wait before we join each thread.
            
            if self.debug == true {
              fmt::f_debug("Time before channel is dropped", format!("{}", timeout_counter).as_str());
            }
          }

          if e == RecvTimeoutError::Disconnected {
            break;
          }
        }
      }
    }

    // Closes and drops the main channel sender and receiver from memory.
    drop(main_recv);
    drop(th_sender);

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

    // Sorts the ports received by the main threads and displays them to the screen.
    println!("");
    write_ports.sort();

    let c_write_ports = write_ports.clone();
    for i in c_write_ports {
      Self::display_port(i);
    }

    println!("");
    for i in banner_resp.clone() {
      println!("Port: {}\nbanner: {}\n", style(i.port).cyan(), style(i.data).cyan());
    }
  }

  /**Function works out what kind of message was to the main thread and returns with the corresponding thread message enum.
   * Params:
   *  slice: &str {The message that was ennt}
   * Returns ThreadMessage
   */
  pub fn validate_thread_message(slice: &str) -> ThreadMessage {
    let mut out = ThreadMessage::KeepAlive;

    match slice {
      "PORT" =>     { out = ThreadMessage::OpenPort }
      "BANNER" =>   { out = ThreadMessage::Banner }
      _ =>          {}
    }

    out
  }


  /**Function is called by each thread and scans the assigned port chunk.
   * Params:
   *  ip_clone: &mut SocketAddr {The ip address and port structure}
   *  ports:    Vec<u16>        {A vec that contains a list of ports to scan}
   *  f:        Flags           {Setting we want to apply to the worker threads}
   *  send:     Sender<String>  {}
   * Returns nothing.
   */
  pub fn thread_run_scan(ip_clone: &mut SocketAddr, ports: Vec<u16>, f: Flags, send: Sender<String>) -> () {
    let th_debug = f.debug.clone();
    let th_timeout = f.timeout.clone();
    let th_verbose = f.verbose.clone();
    let th_banner_req = f.banner_grab.clone();
    let th_banner_len = f.banner_len.clone();
    let mut address = ip_clone.clone();

    if th_debug == true {
      let port_range: (u16, u16) = (ports[0], ports[ports.len() as usize -1]);

      fmt::f_debug(format!("Starting thread with {:?} and will be scanning ports ",
      thread::current().id()).as_str(), format!("[{}-{}]", port_range.0, port_range.1).as_str());
    }

    // Ports are scanned here.
    for i in ports {
      address.set_port(i);
      
      match TcpStream::connect_timeout(&address, Duration::from_millis(th_timeout)) {
        Ok(_) => {

          // If a port was successfully found to be open, the thread will rescan the port just to be sure.
          if let Ok(_) = Self::quick_scan(&address, th_timeout.clone()) {
            
            // A message is sent to the main thread containing the open port.
            Self::thread_send_message(send.clone(), address.port(), String::new(), ThreadMessage::OpenPort);
            
            // This line sends a banner request to the main thread if it gets a response.
            if let Some(data) = Self::get_banner(&address, th_timeout, th_debug, th_banner_len) {
              if data.len() > 0 && th_banner_req == true {
                Self::thread_send_message(send.clone(), address.port(), data, ThreadMessage::Banner);
              }
            }
          }

          else {
            Self::thread_send_message(send.clone(), address.port(), String::new(), ThreadMessage::KeepAlive);
          }
        },

        Err(_) => {
          Self::thread_send_message(send.clone(), address.port(), String::new(), ThreadMessage::KeepAlive);

          if th_verbose == true {
            println!("{}: {}", style(format!("{}/tcp", address.port())).yellow().bright(), style("Closed").red().bright());
          }
        }
      }
    }
  }

  pub fn display_port(port: u16) -> () {
    if let Some(port_name) = service_map(port) {
      println!("{}: {} - {}", style(format!("{}/tcp", port)).yellow().bright(), style("Open").green().bright(),
      style(port_name).cyan());
    }

    else {
      println!("{}: {}", style(format!("{}/tcp", port)).yellow().bright(), style("Open").green().bright())
    };
  }

  /**Function sends messages from worker thread to the main thread via channels with open ports
   * Params:
   *  send:            Sender<String> {The sender channel used to send messages to the main thread}
   *  port:            u16            {The port that was found}
   *  data:            String         {The banner response}
   *  thread_flag:     ThreadMessage  {The type of message to send to the main thread}
   * Returns nothing.
   */
  pub fn thread_send_message(send: Sender<String>, port: u16, data: String, thread_flag: ThreadMessage) -> () {
    let mut msg = String::new();

    // Send "PORT number" for open ports.
    if thread_flag == ThreadMessage::OpenPort {
      msg = format!("PORT[_]{}", port);
    }

    // Send "BANNER number banner_response" for responses longer than 0 bytes.
    else if thread_flag == ThreadMessage::Banner {
      msg = format!("BANNER[_]{}[_]{}", port, data);
      // println!("msg = {}", msg);
    }
    
    // Value is meaningless.
    // This line is used to keep the channel alive.
    else if thread_flag == ThreadMessage::KeepAlive {
      msg.push('0');
    }
    
    // Sends a message to the main thread every 50ms.
    match send.send_timeout(msg, Duration::from_millis(50)) {
      Ok(_) => {},
      Err(_) => {}
    }
  }


  /**Function does a quick scan of a single port number and returns whether it was a success or failure.
   * Params:
   *  address: &SocketAddr {The ip address and port of the service}
   *  timeout: u64         {The socket timeout}
   * Returns Result<TcpStream, std::io::Error>
   */
  pub fn quick_scan(address: &SocketAddr, timeout: u64) -> Result<TcpStream, std::io::Error> {
    match TcpStream::connect_timeout(&address, Duration::from_millis(timeout*2)) {
      Ok(s) => { Ok(s) },
      Err(e) => { Err(e) }
    }
  }

  /**Function makes a get request and returns the response.
   * Params:
   *  address:    &SocketAddr {The ip address and port of the service to contact}
   *  timeout:    u64         {The socket timeout}
   *  debug:      bool        {Shows debug messages}
   *  banner_len: u32         {The max response length that the function will return}
   * Returns Option<String>
   */
  pub fn get_banner(address: &SocketAddr, timeout: u64, debug: bool, banner_len: u32) -> Option<String> {
    let builder = reqwest::blocking::ClientBuilder::new();
    let client_timeout = builder.timeout(Duration::from_millis(timeout));
    let url = format!("http://{}:{}/", address.ip().to_string(), address.port());
    let mut out = String::new();

    match client_timeout.build() {
      Ok(client) => {
        match client.get(url.as_str()).send() {
          Ok(s) => {

            if let Ok(text) = s.text() {
              if text.len() > 0 {
                out.push_str(text.as_str());
              }
            }

          },

          Err(e) => {
            if debug == true {
              fmt::f_error("unable to get response from request", url.as_str(), format!("{}", e).as_str());
            }
          }
        }  
      },

      Err(e) => {
        if debug == true {
          println!("{}: unable to build client request {}ms - {}", style("Error").red(), style(timeout).cyan(), style(e).red());
        }
      }
    }

    if out.len() > 0 {
      let string_bytes = out.as_str();
      let mut banner = String::new();

      let mut counter: u32 = 0;
      for i in string_bytes.chars() {
        if counter > banner_len {
          break;  
        }

        banner.push(i);
        counter += 1;
      }

      Some(banner)
    }

    else {
      None
    }
  }
}