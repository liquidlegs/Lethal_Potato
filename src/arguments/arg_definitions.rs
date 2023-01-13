use serde::Serialize;

// Module contains simple functions used for displaying different types of messages.
pub mod fmt {
  use crate::arguments::service_map;
  use console::style;
  use super::BannerResponse;

  pub fn f_error(msg: &str, value: &str, error_enum: &str) -> () {
    println!("{}: {} {} - {}", style("Error").red().bright(), msg, style(value).cyan(), style(error_enum).red());
  }

  pub fn f_debug(msg: &str, value: &str) -> () {
    println!("{} {} {}", style("Debug =>").red().bright(), style(msg).yellow(), style(value).cyan());
  }

  pub fn f_display_banner(banner: BannerResponse) -> () {
    println!("Port: {}\nbanner: {}\n", style(banner.port).cyan(), style(banner.data).cyan());
  }

  pub fn f_display_port(port: u16) -> () {
    if let Some(port_name) = service_map(port) {
      println!("{}: {} - {}", style(format!("{}/tcp", port)).yellow().bright(), style("Open").green().bright(),
      style(port_name).cyan());
    }

    else {
      println!("{}: {}", style(format!("{}/tcp", port)).yellow().bright(), style("Open").green().bright())
    };
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