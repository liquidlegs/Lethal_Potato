use serde::Serialize;

// Module contains simple functions used for displaying different types of messages.
pub mod fmt {
  use crate::arguments::service_map;
  use console::style;
  use super::BannerResponse;
  use comfy_table::{Cell, Color};

  // Function prints errors in the format [Error: {message} {value} {enum}]
  pub fn f_error(msg: &str, value: &str, error_enum: &str) -> () {
    println!("{}: {} {} - {}", style("Error").red().bright(), msg, style(value).cyan(), style(error_enum).red());
  }

  // Function prints dbg messages in the format [debug: {message} {value}]
  pub fn f_debug(msg: &str, value: &str) -> () {
    println!("{} {} {}", style("Debug =>").red().bright(), style(msg).yellow(), style(value).cyan());
  }

  // Function displays banners in format [{port} {content}]
  pub fn f_display_banner(banner: BannerResponse) -> () {
    println!("Port: {}\nbanner: {}\n", style(banner.port).cyan(), style(banner.data).cyan());
  }

  /**Function displays ports in a nicely formatted table
   * Params:
   *  ports: &Vec<u16> {The ports to be displayed}
   * Returns nothing.
   */
  pub fn f_display_port(ports: &Vec<u16>) -> () {
    // Creates a new table and adds the header columns
    let mut table = comfy_table::Table::new();
    table.set_header(vec![
      Cell::new("Port").fg(Color::Red), 
      Cell::new("State").fg(Color::Red), 
      Cell::new("Service").fg(Color::Red)
    ]);
    
    let mut port_string = String::new();
    let mut state_string = String::new();
    let mut svc_string = String::new();

    // Forms the structure of each of column.
    for i in ports {
      port_string.push_str(format!("{i}/tcp\n").as_str());
      state_string.push_str("Open\n");
      
      if let Some(result) = service_map(i.clone()) {
        svc_string.push_str(result);
        svc_string.push('\n');
      }

      else {
        svc_string.push('\n');
      }
    }

    // Pops the last newline off the end of each string.
    port_string.pop();
    state_string.pop();
    svc_string.pop();

    // Adds the contents to the table.
    table.add_row(vec![
      Cell::new(port_string).fg(Color::Yellow),
      Cell::new(state_string).fg(Color::Green),
      Cell::new(svc_string).fg(Color::DarkCyan)
    ]);

    println!("{table}");
  }
}

#[derive(Debug, Clone)]
pub struct Flags {
  pub debug: bool,          // Flag will show debug messages
  pub verbose: bool,        // Flag will show information
  pub timeout: u64,         // Flags sets the socket timeout.
  pub banner_grab: bool,    // Enables banner grabs.
  pub banner_len: u32,      // Sets the max displayable length in bytes.
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
    
    match std::env::consts::OS {
      "windows" =>  {
        operating_system = OperatingSystem::Windows;
      },

      "linux" =>    {
        operating_system = OperatingSystem::Linux;
      }

      _ =>          {
        fmt::f_error("Operating system either unknown or not supported", std::env::consts::OS, "");
      }
    }

    ArgumentSettings {
      is_valid_output_path: false,
      os: operating_system,
    }
  }
}

// Tells the thread what message was received and how to deal with it.
#[derive(Debug, Clone, PartialEq)]
pub enum ThreadMessage {
  OpenPort,
  Banner,
  KeepAlive,
}

#[derive(Debug, Clone, Serialize)]
pub struct BannerResponse {
  pub port: u16,
  pub data: String
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
  pub a: u8,
  pub b: u8,
  pub c: u8,
  pub d: u8,
  pub ports: Vec<u16>,
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