

// SPDX-FileCopyrightText: © 2021 Georg Sauthoff <mail@gms.tf>
// SPDX-License-Identifier: GPL-3.0-or-later


#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_byteorder.h>
#include <rte_mbuf.h>

#include <stdbool.h>
#include <unistd.h>         // getopt(), sleep()
#include <fcntl.h>          // open()
#include <arpa/inet.h>      // inet_pton()
#include <time.h>           // clock_gettime()


struct Args {
    unsigned delay;
    bool offload_chksum;
    uint32_t src_addr;
    uint16_t src_port;
    uint32_t dst_addr;
    uint16_t dst_port;
    unsigned ring_size;
    FILE *file;
};
typedef struct Args Args;

static void help(FILE *o, const char *argv0)
{
    fprintf(o, "call: %s [DPDK_OPTS...] -- [OPTS...] CFG_FILENAME\n\n", argv0);
    fprintf(o, "Options:\n"
            //################################################################################
            "  -w SECS    wait before first transmit for link auto-negotiation to complete\n"
            "             (default: 2)\n"
            "  -c         don't offload checksum computation (default: auto-detect)\n"
            "  -r N       ring size, i.e. 1024, 2048 or 4096 (default: 4096)\n"
            "  -s ADDR    source IPv4 address (default: 192.168.178.223)\n"
            "  -S PORT    source port (default: 1337)\n"
            "  -d ADDR    destination IPv4 multicast address (default: 224.0.2.23)\n"
            "  -D PORT    destination port (default: 6666)\n"
            "  -h         show this help text\n"
            );
}

static int parse_args(int argc, char **argv, Args *args)
{
    *args = (const Args){
        .delay = 2,
        .offload_chksum = true,
        .src_addr = rte_cpu_to_be_32(RTE_IPV4(192,168, 178, 223)),
        .src_port = rte_cpu_to_be_16(1337),
        .dst_addr = rte_cpu_to_be_32(RTE_IPV4(224, 0, 2, 23)),
        .dst_port = rte_cpu_to_be_16(6666),
        .ring_size = 4096
    };
    char c = 0;
    while ((c = getopt(argc, argv, "hw:cr:s:S:d:D:")) != -1) {
        switch (c) {
            case '?':
                fprintf(stderr, "unknown option: %c\n", optopt);
                help(stderr, argv[0]);
                return -1;
            case 'h':
                help(stdout, argv[0]);
                return 1;
            case 'w':
                args->delay = atoi(optarg);
                break;
            case 'c':
                args->offload_chksum = false;
                break;
            case 'r':
                {
                    unsigned r = atoi(optarg);
                    if (!(r == 1024 || r == 2048 || r == 4096)) {
                        fprintf(stderr, "Unsupported ringsize: %u\n", r);
                    }
                    args->ring_size = r;
                }
                break;
            case 's':
                {
                    int r = inet_pton(AF_INET, optarg, &args->src_addr);
                    if (r == 0) {
                        fprintf(stderr, "invalid source address string\n");
                        return -1;
                    } else if (r == -1) {
                        perror("while parsing source address");
                        return -1;
                    }
                }
                break;
            case 'S':
                args->src_port = rte_cpu_to_be_16(atoi(optarg));
                break;
            case 'd':
                {
                    int r = inet_pton(AF_INET, optarg, &args->dst_addr);
                    if (r == 0) {
                        fprintf(stderr, "invalid destination address string\n");
                        return -1;
                    } else if (r == -1) {
                        perror("while parsing destination address");
                        return -1;
                    }
                }
                break;
            case 'D':
                args->dst_port = rte_cpu_to_be_16(atoi(optarg));
                break;
            default:
                fprintf(stderr, "unimplemented option: %c\n", c);
                return -1;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "positional argument is missing\n");
        return -1;
    }
    const char *filename = argv[optind];
    args->file = fopen(filename, "r");
    if (!args->file) {
        fprintf(stderr, "could not open config file %s: %s",
                filename, strerror(errno));
        return -1;
    }
    return 0;
}


struct Setup_Result {
    struct rte_ether_addr eth_src;
    bool can_offload_chksum;
};
typedef struct Setup_Result Setup_Result;

static Setup_Result setup_device(const Args *args)
{
    Setup_Result result = {0};

    uint16_t ports = rte_eth_dev_count_avail();
    RTE_LOG(INFO, USER1, "%" PRIu16 " ports availabe\n", ports);
    uint16_t port_id = 0;

    uint16_t rx_ring_size = 256;

    RTE_ETH_FOREACH_DEV(port_id) {
        int r = rte_eth_dev_is_valid_port(port_id);
        if (!r)
            rte_panic("port_id %" PRIu16 " is invalid\n", port_id);

        RTE_LOG(INFO, USER1, "using port: %" PRIu16 "\n", port_id);

        struct rte_eth_dev_info dev_info;
        r = rte_eth_dev_info_get(port_id, &dev_info);
        if (r)
            rte_panic("cannot get devinfo: %s\n", rte_strerror(-r));
        unsigned ip_chk     = !!(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM);
        unsigned udp_chk    = !!(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM);
        unsigned udp_tso    = !!(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_TSO);
        unsigned send_on_ts = !!(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_SEND_ON_TIMESTAMP);
        unsigned fast_free  = !!(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE);
        unsigned tx_multi   = !!(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS);
        RTE_LOG(INFO, USER1,
                "available offloads: ip_chksum=%u, udp_chksum=%u, "
                "fast_free=%u, send_on_ts=%u, udp_tso=%u, tx_offload_multi_segs=%u\n",
                ip_chk, udp_chk, fast_free, send_on_ts, udp_tso, tx_multi);
        RTE_LOG(INFO, USER1, "default tx thresh: %" PRIu16 ", tx rs thresh %" PRIu16
                ", pthresh %" PRIu16 ", hthresh %" PRIu16 ", wthresh %" PRIu16 "\n",
                dev_info.default_txconf.tx_free_thresh, dev_info.default_txconf.tx_rs_thresh,
                dev_info.default_txconf.tx_thresh.pthresh,
                dev_info.default_txconf.tx_thresh.hthresh,
                dev_info.default_txconf.tx_thresh.wthresh);

        // NB: we set it less than the rte_pktmbuf_pool_create() size
        // such that we run out of descriptors before we run out of descriptors
        // which simplifies our allocation loop
        // NB: 'tx_rs_thresh must be a divisor of the number of TX descriptors'
        //     default: tx_rs_thresh=32
        uint16_t tx_ring_size = args->ring_size - dev_info.default_txconf.tx_rs_thresh;

        struct rte_eth_conf port_conf = {0};

        r = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &rx_ring_size, &tx_ring_size);
        if (r != 0)
            rte_panic("cannot adjust rx/tx sizes: %s\n", rte_strerror(-r));
        RTE_LOG(INFO, USER1, "Adjusted rx/tx ring size to %" PRIu16
                " and %" PRIu16 "\n", rx_ring_size, tx_ring_size);
        if (tx_ring_size >= 4095)
            rte_panic("tx ring size too big: %" PRIu16, tx_ring_size);

        if (args->offload_chksum && ip_chk && udp_chk) {
            // according to http://doc.dpdk.org/guides/nics/overview.html there isn't really a device
            // that supports L3 checksum offload without also supporting L4 checksum offload
            port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;
            port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;
            // required for Solarflare, i.e. UDP/TCP offload can only be enabled in tandem ...
            port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;
            result.can_offload_chksum = true;
        }

        r = rte_eth_dev_configure(port_id, 0 /* rxrings */, 1 /* txrings */, &port_conf);
        if (r)
            rte_panic("cannot configure port/dev: %s\n", rte_strerror(-r));

        // NB rxrings must be 0, when no rx-queue is configured
        // otherwise, cf. rte_eth_rx_queue_setup()

        struct rte_eth_txconf txconf = dev_info.default_txconf;
        txconf.offloads = port_conf.txmode.offloads;

        r = rte_eth_tx_queue_setup(port_id, 0 /* first txring */, tx_ring_size /* descriptors */,
                rte_eth_dev_socket_id(port_id), &txconf);
        if (r)
            rte_panic("cannot configure tx queue: %s\n", rte_strerror(-r));

        r = rte_eth_dev_start(port_id);
        if (r)
            rte_panic("cannot start port/dev: %s\n", rte_strerror(-r));

        struct rte_ether_addr mac_addr = {0};
        r = rte_eth_macaddr_get(port_id, &mac_addr);
        if (r)
            rte_panic("cannot get mac address: %s\n", rte_strerror(-r));
        result.eth_src = mac_addr;

        RTE_LOG(INFO, USER1, "port %" PRIu16 " MAC address: "
                "%02x:%02x:%02x:%02x:%02x:%02x\n",
                port_id, mac_addr.addr_bytes[0], mac_addr.addr_bytes[1], mac_addr.addr_bytes[2],
                mac_addr.addr_bytes[3], mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);

        uint16_t mtu = 0;
        r = rte_eth_dev_get_mtu(port_id, &mtu);
        if (r)
            rte_panic("failed to get mtu: %s\n", rte_strerror(-r));
        else
            RTE_LOG(INFO, USER1, "port %" PRIu16 " MTU: %" PRIu16 "\n", port_id, mtu);

        struct rte_eth_link link = {0};
        r = rte_eth_link_get(port_id, &link);
        if (r)
            rte_panic("failed to get link: %s\n", rte_strerror(-r));
	char t[RTE_ETH_LINK_MAX_STR_LEN];
        t[0] = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
        rte_eth_link_to_str(t, sizeof t, &link);
#pragma GCC diagnostic pop
        RTE_LOG(INFO, USER1, "port %" PRIu16 " link status: %s\n", port_id, t);

        break;
    }

    // required on some devices since it might takes some time until
    // the link is up and auto-negotiated with the switch ...
    sleep(args->delay);

    return result;
}

static struct rte_ether_addr mcast_i2e(rte_be32_t addrP)
{
    uint32_t addr = rte_be_to_cpu_32(addrP);
    struct rte_ether_addr e = {
        .addr_bytes = {
                              1,
                              0,
                           0x5Eu,
            (addr >> 16) & 0x7Fu,
            (addr >>  8) & 0xFFu,
             addr        & 0xFFu
        }
    };
    return e;
}


struct Payload {
    char      prefix[8];
    uint32_t  seq_no;
    char      msg[12];
    uint64_t  timestamp_ns;
    char      epilogue[992];
};
typedef struct Payload Payload;

struct Pkt_Args {
    struct rte_ether_addr eth_src;
    struct rte_ether_addr eth_dst;
    rte_be32_t            src;
    rte_be16_t            src_port;
    rte_be32_t            dst;
    rte_be16_t            dst_port;
    bool                  offload_chksum;
    unsigned char         noise[16 * 1024];
};
typedef struct Pkt_Args Pkt_Args;

struct Pkt_Headers {
    struct rte_ether_hdr *ehdr;
    struct rte_ipv4_hdr  *ihdr;
    struct rte_udp_hdr   *uhdr;
    Payload              *payload;
};
typedef struct Pkt_Headers Pkt_Headers;

void fill_packet(const unsigned char *p, const Pkt_Args *args)
{
    struct rte_ether_hdr *ehdr = (struct rte_ether_hdr*) p;
    p += sizeof *ehdr;

    rte_ether_addr_copy(&args->eth_src, &ehdr->src_addr);
    rte_ether_addr_copy(&args->eth_dst, &ehdr->dst_addr);
    ehdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ihdr = (struct rte_ipv4_hdr*) p;
    p += sizeof *ihdr;
    ihdr->version_ihl     = RTE_IPV4_VHL_DEF;
    ihdr->type_of_service = 0;
    ihdr->total_length    = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(Payload));
    // can be globally incremented on each send, constant or random
    // cf. https://blog.apnic.net/2018/06/18/a-closer-look-at-ip-headers/
    ihdr->packet_id       = rte_cpu_to_be_16(0);

    ihdr->fragment_offset = rte_cpu_to_be_16(1 << RTE_IPV4_HDR_DF_SHIFT);
    ihdr->time_to_live    = 23;

    ihdr->next_proto_id   = IPPROTO_UDP;
    // ihdr->hdr_checksum initialized later
    ihdr->src_addr        = args->src;
    ihdr->dst_addr        = args->dst;

    struct rte_udp_hdr *uhdr = (struct rte_udp_hdr*) p;
    p += sizeof *uhdr;

    uhdr->src_port    = args->src_port;
    uhdr->dst_port    = args->dst_port;
    uhdr->dgram_len   = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr) + sizeof(Payload));
    // uhdr->dgram_cksum initialized later

    Payload *payload = (Payload*) p;
    memcpy(payload, args->noise, sizeof *payload);
    strcpy(payload->epilogue, "Hello World!\n");
}

static Pkt_Headers pkt_headers(const struct rte_mbuf *pkt)
{
    unsigned char *p = rte_pktmbuf_mtod(pkt, unsigned char*);
    struct rte_ether_hdr *ehdr = (struct rte_ether_hdr*) p;
    p += sizeof *ehdr;
    struct rte_ipv4_hdr  *ihdr = (struct rte_ipv4_hdr*) p;
    p += sizeof *ihdr;
    struct rte_udp_hdr   *uhdr = (struct rte_udp_hdr*) p;
    p += sizeof *uhdr;
    Payload *payload = (Payload*) p;
    return (Pkt_Headers){ ehdr, ihdr, uhdr, payload };
}

static void chksum_packet(struct rte_mbuf *pkt,
        struct rte_ipv4_hdr *ihdr,
        struct rte_udp_hdr  *uhdr,
        uint16_t port_id, uint16_t queue_id,
        bool offload_chksum)
{
    if (offload_chksum) {
#if 1
        // NB: rte_eth_tx_prepare() sets L3 checksum to 0 and initializes
        // the L4 checksum to the pseudo-header checksum, or similar,
        // or does nothing, whatever the PMD requires
        uint16_t l = rte_eth_tx_prepare(port_id, queue_id, &pkt, 1);
        if (l != 1)
            rte_panic("cannot prepare packet: %s\n", rte_strerror(rte_errno));
#else
        // alternatively, we have to have outside information whether
        // partial/full offload is available!
        // there is no way to query partial/full offload support via DPDK!
        if (!args.full_l4_chksum_offload) {
            // perhaps a PMD might even require this for full oflload?
            ihdr->hdr_checksum    = rte_cpu_to_be_16(0);
            // Intel NICs support UDP checksum offloading but
            // still expect the partial checksum of the IPv4 pseudo header
            uhdr->dgram_cksum = rte_ipv4_phdr_cksum(ihdr, pkt->ol_flags);
        }
#endif
    } else {
        ihdr->hdr_checksum = rte_cpu_to_be_16(0);
        uhdr->dgram_cksum  = rte_cpu_to_be_16(0);
        uhdr->dgram_cksum  = rte_ipv4_udptcp_cksum(ihdr, uhdr);
        ihdr->hdr_checksum = rte_ipv4_cksum(ihdr);
    }
}


enum Cmd {
    CMD_EXIT,
    CMD_WAIT,
    CMD_SET_TOS,
    CMD_SET_SIZE,
    CMD_SET_DST,
    CMD_SET_DPORT,
    CMD_SET_SPORT,
    CMD_XMIT
};
typedef enum Cmd Cmd;

struct Command {
    Cmd      cmd;
    uint32_t arg;
};
typedef struct Command Command;

struct Command_Block {
    Command cmds[1024];
};
typedef struct Command_Block Command_Block;


struct Sender_Args {
    int                 port_id;
    struct rte_mempool *pkt_pool;
    rte_be32_t          src;
    struct rte_ether_addr eth_dst;
    rte_be32_t          dst;
    rte_be16_t          sport;
    rte_be16_t          dport;
    bool                offload_chksum;
    struct rte_ring    *cmd_ring;
    struct rte_mempool *cmd_pool;
};
typedef struct Sender_Args Sender_Args;

static int sender_main(void *v)
{
    const Sender_Args *argsP = v;
    Sender_Args args = *argsP;

    Command_Block *block = 0;
    unsigned tos = 0;
    unsigned msg_size = sizeof(Payload);
    uint32_t dst = args.dst;
    struct rte_ether_addr eth_dst = args.eth_dst;
    uint16_t sport = args.sport;
    uint16_t dport = args.dport;
    unsigned k = 0;
    for (;;) {
        while (rte_ring_dequeue(args.cmd_ring, (void**)&block))
            rte_pause();

        for (unsigned i = 0; i < sizeof block->cmds / sizeof block->cmds[0]; ++i) {
            Command c = block->cmds[i];
            switch (c.cmd) {
                case CMD_EXIT:
                    return 0;
                case CMD_WAIT:
                    rte_delay_us_block(c.arg);
                    continue;
                case CMD_SET_TOS:
                    tos = c.arg;
                    continue;
                case CMD_SET_SIZE:
                    msg_size = c.arg;
                    continue;
                case CMD_SET_DST:
                    dst = c.arg;
                    eth_dst = mcast_i2e(dst);
                    continue;
                case CMD_SET_DPORT:
                    dport = rte_cpu_to_be_16((uint16_t)c.arg);
                    continue;
                case CMD_SET_SPORT:
                    sport = rte_cpu_to_be_16((uint16_t)c.arg);
                    continue;
                case CMD_XMIT:
                    break;
                default:
                    continue;
            }

            struct rte_mbuf *pkt;
            do {
                // NB: we can raw alloc here since we initialized the packets
                // at pool creation time - cf. init_pkt_headers()
                pkt = rte_mbuf_raw_alloc(args.pkt_pool);
                if (!pkt) {
                    // NB: this branch is never taken since we run out of descriptors
                    // first because tx_ring_size < mbuf_pool_size
                    // -> failsafe in case setup is messed up
                    // NB: rte_eth_tx_done_cleanup() isn't available with all PMDs
                    // e.g. ixgbe let it fail when checksum offload isn't enabled ...
                    int r = rte_eth_tx_done_cleanup(args.port_id, 0 /* queue */, 256);
                    if (r < 0)
                        rte_panic("%u. cannot cleanup tx descs: %s\n", i, rte_strerror(-r));
                }
            } while (!pkt);

            size_t n = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)
                + sizeof(struct rte_udp_hdr) + msg_size;

            pkt->data_len = n;
            pkt->pkt_len  = n;
            assert(pkt->l2_len   == sizeof(struct rte_ether_hdr));
            assert(pkt->l3_len   == sizeof(struct rte_ipv4_hdr));

            Pkt_Headers h = pkt_headers(pkt);
            rte_ether_addr_copy(&eth_dst, &h.ehdr->dst_addr);
            h.ihdr->type_of_service = tos;
            h.ihdr->total_length    = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + msg_size);
            h.ihdr->dst_addr        = dst;
            h.uhdr->src_port        = sport;
            h.uhdr->dst_port        = dport;
            h.uhdr->dgram_len       = rte_cpu_to_be_16(sizeof(struct rte_udp_hdr)  + msg_size);

            h.payload->seq_no = k++;
            struct timespec ts = {0};
            clock_gettime(CLOCK_REALTIME, &ts);
            h.payload->timestamp_ns  = ts.tv_sec * 1000000000ul;
            h.payload->timestamp_ns += ts.tv_nsec;

            chksum_packet(pkt, h.ihdr, h.uhdr, args.port_id, 0 /* queue_id */,
                    args.offload_chksum);

            for (;;) {
                // it's perfectly fine for rte_eth_tx_burst() to return 0, e.g.
                // in case no descriptor is re-usable, yet. Thus, we just keep
                // on retrying ...
                uint16_t l = rte_eth_tx_burst(args.port_id, 0, &pkt, 1);
                if (l == 1) {
                    break;
                } else {
                    // NB: a successfull transmit auto-frees the pkt
                    // alternative to retry: throwing it away
                    // rte_pktmbuf_free(pkt);
                    // RTE_LOG(ERR, USER1, "%u. cannot send packet - retry\n", i);
                }
            }
        }
        rte_mempool_put(args.cmd_pool, block);
    }

    return 0;
}



struct Reader_Args {
    FILE               *file;
    struct rte_mempool *cmd_pool;
    struct rte_ring    *cmd_ring;
};
typedef struct Reader_Args Reader_Args;

static int reader_main(void *v)
{
    const Reader_Args *argsP = v;
    Reader_Args args = *argsP;

    char *line = 0;
    size_t n = 0;
    Command_Block *block = 0;
    int r = rte_mempool_get(args.cmd_pool, (void**)&block);
    if (r)
        rte_panic("could not allocate command block");
    size_t k = 0;
    size_t m = sizeof block->cmds / sizeof block->cmds[0];
    for (;;) {
        ssize_t l = getline(&line, &n, args.file);
        if (l == -1) {
            if (feof(args.file))
                break;
            rte_panic("getline failed: %s\n", strerror(errno));
        }

        char c = 0;
        unsigned u = 0;
        sscanf(line, "%c %u", &c, &u);
        Command x;
        switch (*line) {
            case 'w':
                x.cmd = CMD_WAIT;
                break;
            case 't':
                x.cmd = CMD_SET_TOS;
                break;
            case 'n':
                x.cmd = CMD_SET_SIZE;
                break;
            case 'x':
                x.cmd = CMD_XMIT;
                break;
            case 'd':
                x.cmd = CMD_SET_DST;
                {
                    line[strlen(line)-1] = 0;
                    int r = inet_pton(AF_INET, line+2, &u);
                    if (r == 0) {
                        rte_panic("invalid destination address string\n");
                    } else if (r == -1) {
                        rte_panic("while parsing source address: %s", strerror(errno));
                    }
                }
                break;
            case 'D':
                x.cmd = CMD_SET_DPORT;
                break;
            case 'S':
                x.cmd = CMD_SET_SPORT;
                break;
            default:
                continue;
        }
        x.arg = u;
        if (k == m) {
            while ((r = rte_ring_enqueue(args.cmd_ring, block)))
                rte_pause();
            while ((r = rte_mempool_get(args.cmd_pool, (void**)&block)))
                rte_pause();
            k = 0;
        }
        block->cmds[k++] = x;
    }
    fclose(args.file);
    if (k == m) {
        while ((r = rte_ring_enqueue(args.cmd_ring, block)))
            rte_pause();
        while ((r = rte_mempool_get(args.cmd_pool, (void**)&block)))
            rte_pause();
        k = 0;
    }
    block->cmds[k++] = (Command) { .cmd = CMD_EXIT };
    while ((r = rte_ring_enqueue(args.cmd_ring, block)))
        rte_pause();
    return 0;
}

// NB: supposed to be called via rte_mempool_obj_iter(), directly
// after pool creation.
// When used that way we can avoid resetting most fields/headers
// again and again - and thus call rte_mbuf_raw_alloc() instead
// of rte_pktmbuf_alloc().
static void init_pkt_headers(struct rte_mempool *mp, void *extra,
        void *v, unsigned i)
{
    const Pkt_Args *args = extra;
    struct rte_mbuf *pkt = v;

    size_t n = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr)
        + sizeof(struct rte_udp_hdr) + sizeof(Payload);

    if (args->offload_chksum) {
        pkt->ol_flags |= RTE_MBUF_F_TX_IPV4;
        pkt->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM;
        pkt->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
    }

    pkt->data_len = n;
    pkt->pkt_len  = n;
    pkt->l2_len   = sizeof(struct rte_ether_hdr);
    pkt->l3_len   = sizeof(struct rte_ipv4_hdr);

    // NB: not required for ip/udp checksum offload: pkt->l4_len

    unsigned char *p = rte_pktmbuf_mtod(pkt, unsigned char*);

    fill_packet(p, args);
}

int read_noise(unsigned char *b, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1)
        return -1;
    do {
        ssize_t l = read(fd, b, n);
        if (l == -1) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        n -= l;
        b += l;
    } while (n);
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    int r = rte_eal_init(argc, argv);
    if (r < 0)
        rte_panic("cannot init EAL: %s\n", rte_strerror(-r));

    argc -= r;
    argv += r;
    Args args;
    r = parse_args(argc, argv, &args);
    if (r)
        return r != 1;

    Setup_Result sr = setup_device(&args);
    if (!sr.can_offload_chksum)
        args.offload_chksum = false;

    unsigned n = 0, cache = 0;
    // NB: docs recommend: n == 2^q-1
    // NB: must be: cache < n/1.5 && cache < 512 && n % cache == 0
    // for example:
    switch (args.ring_size) {
        case 1024: n = 1023; cache = 341; break;
        case 2048: n = 2047; cache =  89; break;
        case 4096: n = 4095; cache = 455; break;
        default: rte_panic("unsupported ring size: %u", args.ring_size);
    }
    struct rte_mempool *pkt_pool = rte_pktmbuf_pool_create("pkt_pool",
            n, cache, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!pkt_pool)
        rte_exit(1, "cannot allocate pkt pool: %s\n", rte_strerror(rte_errno));
    Pkt_Args pargs = {
        .eth_src        = sr.eth_src,
        .eth_dst        = mcast_i2e(args.dst_addr),
        .src            = args.src_addr,
        .src_port       = args.src_port,
        .dst            = args.dst_addr,
        .dst_port       = args.dst_port,
        .offload_chksum = args.offload_chksum
    };
    r = read_noise(pargs.noise, sizeof pargs.noise);
    if (r) {
        perror("couldn't read random noise");
        return 1;
    }
    RTE_LOG(INFO, USER1, "using destination MAC address: "
            "%02x:%02x:%02x:%02x:%02x:%02x\n",
            pargs.eth_dst.addr_bytes[0], pargs.eth_dst.addr_bytes[1],
            pargs.eth_dst.addr_bytes[2], pargs.eth_dst.addr_bytes[3],
            pargs.eth_dst.addr_bytes[4], pargs.eth_dst.addr_bytes[5]);
    rte_mempool_obj_iter(pkt_pool, init_pkt_headers, &pargs);


    struct rte_mempool *cmd_pool = rte_mempool_create("cmd_pool",
            16 * 1024 - 1, sizeof(Command_Block), 0, 0, 0, 0, 0, 0,
            rte_socket_id(), MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
    if (!cmd_pool)
        rte_exit(1, "cannot allocate cmd pool: %s\n", rte_strerror(rte_errno));

    struct rte_ring *cmd_ring = rte_ring_create("cmd_ring", 16 * 1024,
            rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!cmd_ring)
        rte_exit(1, "cannot allocate cmd ring: %s\n", rte_strerror(rte_errno));

    Sender_Args sargs = {
        .pkt_pool       = pkt_pool,
        .src            = args.src_addr,
        .eth_dst        = pargs.eth_dst,
        .dst            = args.dst_addr,
        .sport          = args.src_port,
        .dport          = args.dst_port,
        .offload_chksum = args.offload_chksum,
        .cmd_pool       = cmd_pool,
        .cmd_ring       = cmd_ring
    };
    assert(sargs.cmd_ring);
    Reader_Args rargs = {
        .file           = args.file,
        .cmd_pool       = cmd_pool,
        .cmd_ring       = cmd_ring
    };

    unsigned lcore_id = rte_get_next_lcore(-1, 1 /* skip main */, 0);
    if (lcore_id >= RTE_MAX_LCORE)
        rte_panic("need a worker thread!\n");

    RTE_LOG(INFO, USER1, "launching sender thread on core %u\n", lcore_id);
    r = rte_eal_remote_launch(sender_main, &sargs, lcore_id);
    if (r)
        rte_panic("cannot launch worker thread: %s\n", rte_strerror(-r));

    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    RTE_LOG(INFO, USER1, "launching reader thread on core %u\n", lcore_id);
    if (lcore_id >= RTE_MAX_LCORE)
        rte_panic("need another  worker thread!\n");
    r = rte_eal_remote_launch(reader_main, &rargs, lcore_id);
    if (r)
        rte_panic("cannot launch reader thread: %s\n", rte_strerror(-r));

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        int r = rte_eal_wait_lcore(lcore_id);
        if (r)
            rte_exit(1, "worker thread %u failed with: %d\n", lcore_id, r);
    }

    rte_eal_cleanup();
    return 0;
}


