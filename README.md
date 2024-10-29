# Instructions

There are two programs in this folder, a port scanner inside ```./port_scanner``` and the puzzle solver inside ```./puzzle_solver```

## To run the port scanner:
1. cd into the port_scanner directory: ```cd port_scanner/```.
2. Run the make command: ```make```.
3. Run the scanner program: ```sudo ./scanner <ip_to_scan> <starting_port> <ending_port> ```
    * Example: ```sudo ./scanner 130.208.246.249 4000 4100```

This will loop through all the ports between the starting and ending given ports and print the open ports.


## To run the puzzle solver:
1. cd into the puzzle_solver directory: ```cd puzzle_solver```
2. Run the make command: ```make```
3. Run the puzzle_solver program: ```sudo ./puzzlesolver <server_ip> <port_1> <port_2> <port_3> <port_4>```
    * Example: ```sudo ./puzzlesolver 130.208.246.249 4047 4048 4059 4066```

# NOTE:
## This was developed, tested and verified on a Mac OS device.