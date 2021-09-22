# raw_tcp_client
Raw socket tcp client for Linux.

## Build
```bash
$ git clone https://github.com/mozzzzy/raw_tcp_client.git
$ cmake -Bbuild
$ cmake --build build
```

## Run
The following command make tcp connection between localhost's 49152 port and 172.18.0.3's 80 port, and send 'HELLO TCP'.
```
$ sudo build/bin/main eth0 49152 172.18.0.3 80
```
To check the above communication,  
first, run TCP server in 172.18.0.3's 80 port using following command.
```
$ nc -kl 80
```
And then capture the packets between them.
```
$ sudo tcpdump -Zroot port 80 -X -vvv
```
The output of tcpdump is like the following.
```
tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes

# local -> remote (SYN = 1)
12:48:23.315197 IP (tos 0x0, ttl 32, id 42891, offset 0, flags [none], proto TCP (6), length 40)
    b66b6a69127b.49152 > 172.18.0.3.http: Flags [S], cksum 0x9d51 (correct), seq 2935894183, win 64240, length 0
        0x0000:  4500 0028 a78b 0000 2006 9b1b ac12 0002  E..(............
        0x0010:  ac12 0003 c000 0050 aefe 30a7 0000 1f80  .......P..0.....
        0x0020:  5002 faf0 9d51 0000                      P....Q..

# local <- remote (SYN = 1, ACK = 1)
12:48:23.315309 IP (tos 0x0, ttl 64, id 0, offset 0, flags [DF], proto TCP (6), length 44)
    172.18.0.3.http > b66b6a69127b.49152: Flags [S.], cksum 0x5848 (incorrect -> 0x14e2), seq 1480013803, ack 2935894184, win 64240, options [mss 1460], length 0
        0x0000:  4500 002c 0000 4000 4006 e2a2 ac12 0003  E..,..@.@.......
        0x0010:  ac12 0002 0050 c000 5837 37eb aefe 30a8  .....P..X77...0.
        0x0020:  6012 faf0 5848 0000 0204 05b4            `...XH......

# local -> remote (ACK = 1)
12:48:23.316201 IP (tos 0x0, ttl 32, id 42891, offset 0, flags [none], proto TCP (6), length 40)
    b66b6a69127b.49152 > 172.18.0.3.http: Flags [.], cksum 0x2c9f (correct), seq 1, ack 1, win 64240, length 0
        0x0000:  4500 0028 a78b 0000 2006 9b1b ac12 0002  E..(............
        0x0010:  ac12 0003 c000 0050 aefe 30a8 5837 37ec  .......P..0.X77.
        0x0020:  5010 faf0 2c9f 0000                      P...,...

# local -> remote (send 'HELLO TCP', PSH = 1)
12:48:23.316369 IP (tos 0x0, ttl 32, id 42891, offset 0, flags [none], proto TCP (6), length 49)
    b66b6a69127b.49152 > 172.18.0.3.http: Flags [P.], cksum 0xa498 (correct), seq 1:10, ack 1, win 64240, length 9: HTTP
        0x0000:  4500 0031 a78b 0000 2006 9b12 ac12 0002  E..1............
        0x0010:  ac12 0003 c000 0050 aefe 30a8 5837 37ec  .......P..0.X77.
        0x0020:  5018 faf0 a498 0000 4845 4c4c 4f20 5443  P.......HELLO.TC
        0x0030:  50                                       P

# local <- remote (ACK = 1)
12:48:23.316396 IP (tos 0x0, ttl 64, id 13412, offset 0, flags [DF], proto TCP (6), length 40)
    172.18.0.3.http > b66b6a69127b.49152: Flags [.], cksum 0x5844 (incorrect -> 0x2c9f), seq 1, ack 10, win 64231, length 0
        0x0000:  4500 0028 3464 4000 4006 ae42 ac12 0003  E..(4d@.@..B....
        0x0010:  ac12 0002 0050 c000 5837 37ec aefe 30b1  .....P..X77...0.
        0x0020:  5010 fae7 5844 0000                      P...XD..

# local -> remote (ACK = 1, FIN = 1)
12:48:23.317446 IP (tos 0x0, ttl 32, id 42891, offset 0, flags [none], proto TCP (6), length 40)
    b66b6a69127b.49152 > 172.18.0.3.http: Flags [F.], cksum 0x2c95 (correct), seq 10, ack 1, win 64240, length 0
        0x0000:  4500 0028 a78b 0000 2006 9b1b ac12 0002  E..(............
        0x0010:  ac12 0003 c000 0050 aefe 30b1 5837 37ec  .......P..0.X77.
        0x0020:  5011 faf0 2c95 0000                      P...,...

# local <- remote (ACK = 1, FIN = 1)
12:48:23.317581 IP (tos 0x0, ttl 64, id 13413, offset 0, flags [DF], proto TCP (6), length 40)
    172.18.0.3.http > b66b6a69127b.49152: Flags [F.], cksum 0x5844 (incorrect -> 0x2c9e), seq 1, ack 11, win 64230, length 0
        0x0000:  4500 0028 3465 4000 4006 ae41 ac12 0003  E..(4e@.@..A....
        0x0010:  ac12 0002 0050 c000 5837 37ec aefe 30b2  .....P..X77...0.
        0x0020:  5011 fae6 5844 0000                      P...XD..

# local -> remote (ACK = 1)
12:48:23.319213 IP (tos 0x0, ttl 32, id 42891, offset 0, flags [none], proto TCP (6), length 40)
    b66b6a69127b.49152 > 172.18.0.3.http: Flags [.], cksum 0x2c94 (correct), seq 11, ack 2, win 64240, length 0
        0x0000:  4500 0028 a78b 0000 2006 9b1b ac12 0002  E..(............
        0x0010:  ac12 0003 c000 0050 aefe 30b2 5837 37ed  .......P..0.X77.
        0x0020:  5010 faf0 2c94 0000                      P...,...
```
