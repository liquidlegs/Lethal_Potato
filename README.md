# Lethal_Potato

![potato](https://github.com/liquidlegs/Lethal_Potato/blob/main/images/potato.gif)

Lethal Potato is a very basic multithreaded port scanner that can produce blazing fast results.
What was originally a project that I undertook over the weekend to see how much performance I could squeeze out of my machine while using as little resources as possible, became a useful tool.

Lethal Potato gets its name because it was written and tested on a 1.60 GHz I5 processor that was able to scan over 65,535 ports and run on as little as %14 CPU usage.

## Features
- Fast and lightweight
- Scan ports in a range (1-1024)
- Scan port individually (80,443,445)
- Customizable threads
- Customizable socket timeout
- Display verbose output
- Supports Windows and Linux

## Features to come
- Banner grabbing
- Export as json
- Display the recommended max threads
- Auto calcuate socket timeout

# Compilation Instructions
1) Download and install rustup https://www.rust-lang.org/
2) Add the cargo to your path
3) cd into the project directory
4) Run the following command
5) `Cargo build --release`

You will find the executable under `/target/build/`

# Known issues
## How come I see no results after a scan finishes even if Nmap says there are ports open?
The application isn't smart enough to determine the average server response time against the target. Therefore before you begin the scan you need to make a guesstimate about the average server response time + add 200-300ms to make up for the huge amount of network traffic the server has to deal with.

Obtaining the client response time can be done by using the "ping" utility.

## Why does Lethal_potato execute more threads than what I asked for?
As an example, if you scan 1024 ports with 650 threads you may use up to 1024 threads. This is because threads are allocated ports to scan in segments, meaning that if we calculate 1024/650 we get 1.5. Since it makes no sense to scan half a port, we have to round down to 1 and allocate 1 port per thread to 1000 threads + 24 to scan all 1024 ports. You can figure out the correct number of threads to use by calculating "total_number_of_ports/2".

## Sometimes ports are occasionally rescanned.
I am aware of the issue and it will be fixed soon.

## How come the linux version looks so dark and the windows version looks so bright?
Lethal Potato was originally written and tested on the windows terminal.
That being said, I will giving the linux version some love so that it looks bright colourful also.
