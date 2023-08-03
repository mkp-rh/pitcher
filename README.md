# Description

Send, recieve, and measure traffic

# Build

$ go build

# Run

To run the server, include the -s flag and a server IP

$ ./pitcher -d 4000 -p 2000 -s -saddr 127.0.0.1 

To run the client, include both a server and client IP

$ ./pitcher -d 4000 -p 2000 -saddr 127.0.0.1 -caddr 127.0.0.2

