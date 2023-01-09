mod arguments;
use arguments::{Arguments, display_help};
use clap::Parser;

fn main() {
  let display: Vec<String> = std::env::args().collect();
  if display.len() > 1 {
    match display[1].as_str() {
      "--help" => {
        display_help(display[0].clone());
      }

      _ => {}
    }
  }

  let args = Arguments::parse();
  args.begin_scan();
}
