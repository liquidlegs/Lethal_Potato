mod arguments;
use arguments::{Arguments, ArgumentSettings, display_help, FileOutput};
use clap::Parser;

fn main() {
  let display: Vec<String> = std::env::args().collect();
  if display.len() > 1 {
    match display[1].as_str() {
      "--help" | "-h" => {
        // let current_dir = std::env::current_dir().unwrap();
        // println!("{}", current_dir.into_os_string().into_string().unwrap());

        display_help(display[0].clone());
      }

      _ => {}
    }
  }

  let mut args = Arguments::parse();
  let mut settings = ArgumentSettings::new();
  
  if let Some(s) = args.output.clone() {
    settings.is_valid_output_path = args.check_valid_directory();
  }
  
  args.begin_scan(settings.clone());
}
