This repository contains a selection of Georg's DPDK examples.

2021, Georg Sauthoff <mail@gms.tf>



## Build Instructions

Assuming you have DPDK installed under `/opt/dpdk-20.11.2` you
can compile the examples like this:

```
export PKG_CONFIG_PATH=/opt/dpdk-20.11.2/lib64/pkgconfig
meson build --buildtype debugoptimized
cd build
ninja
```

## Ping Pong

Pingpong is a simple program that demonstrates the basic API of
the (lockless) DPDK Ring library and measures the overhead of
transmitting small data between two threads through such a ring
(buffer).

Example call:

    ./pingpong -l 4-7 --main-lcore 4  -n 2 --in-memory --allow 05:00.1 \
        --socket-mem $((4*1024)) 2>&1 \
        | grep USER1 \
        | datamash -t ' ' --header-out -s -g 2 min 3 q1 3 median 3 q3 3 max 3 count 3  \
        | column -t


## Multicast Send

This example shows how to send UDP multicast packets in an
efficient way while modifying header fields that are usually
cumbersome and expensive to modify when using the POSIX socket
API (think: IP TOS field). It uses a DPDK memory pool for the
packets where all packets are pre-initialized (i.e. before
later alloc calls) such that only changing headers/fields
need to be modified.

When available, the program tries to offload checksum computation as
much as possible.

The program is driven by a run control file which is read by a
helper thread that pushes commands into a ring buffer which are
interpreted by a sender thread.

Example call:

    ./mcast_send -l 3-5 --main-lcore 3  -n 2 --in-memory --allow 05:00.1 \
        --socket-mem $((4*1024))  --  -r 1024 ../mcast.rc


