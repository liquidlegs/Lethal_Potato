# Lethal_Potato

![potato](https://github.com/liquidlegs/Lethal_Potato/blob/main/images/potato.gif)

Lethal Potato is a very basic multithreaded port scanner that can produce blazing fast results.
What was originally a project that I undertook over the weekend to see how much performance I could sqeeze out my machine while using as little resources as possible, became a useful tool.

Lethal Potato gets its name because it was written and tested on a 1.60 GHz I5 processor that was able to scan over 65,535 ports and run on as little as %14 CPU usage.

## Features
- FAST
- Scan ports in a range (1-1024)
- Scan port individually (80,443,445)
- Customizable threads
- Customizable socket timeout
- Display debug messages
- Display closed ports
- Supports Windows and Linux

# Compilation Instructions
1) Download and install rustup https://www.rust-lang.org/
2) Add the cargo to your path
3) cd into the project directory
4) Run the following command 
5) > Cargo build --release

You will find the executable under /target/build/
