
// SPDX-FileCopyrightText: © 2021 Georg Sauthoff <mail@gms.tf>
// SPDX-License-Identifier: GPL-3.0-or-later

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_ring.h>
#include <rte_cycles.h>

#include <inttypes.h>

struct Worker_Args {
    struct rte_ring *in;
    struct rte_ring *out;
};
typedef struct Worker_Args Worker_Args;


static void print_delta(unsigned x, uint64_t start, uint64_t stop, uint64_t freq)
{
    uint64_t delta = stop - start;
    uint64_t ns = delta * 1000000000lu;
    ns /= freq;
    RTE_LOG(INFO, USER1, "delta%u: %" PRIu64 " ns\n", x, ns);
}

static int worker_main(void *v)
{
    const Worker_Args *args = v;
    uint64_t freq = rte_get_tsc_hz();
    for (unsigned i = 0; i < 10000; ++i) {
        void *x = 0;
        while (rte_ring_dequeue(args->in, &x))
            rte_pause();
        uint64_t stop = rte_rdtsc_precise();
        uint64_t start = (uintptr_t)x;

        print_delta(1, start, stop, freq);


        rte_delay_us_block(999);
        while (1) {
            void *x = (void*) rte_rdtsc_precise();
            rte_ring_enqueue(args->out, x);
            break;
        }

    }
    return 0;
}

int main(int argc, char **argv) {
    int r = rte_eal_init(argc, argv);
    if (r < 0)
        rte_exit(1, "cannot init eal\n");

    struct rte_ring *m2w = rte_ring_create("m2w", 1024,
            rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!m2w)
        rte_exit(1, "create ring m2w: %s\n", rte_strerror(rte_errno));
    struct rte_ring *w2m = rte_ring_create("w2m", 1024,
            rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!w2m)
        rte_exit(1, "create ring w2m: %s\n", rte_strerror(rte_errno));

    Worker_Args wargs = { .in = m2w, .out = w2m };

    unsigned lcore_id = 0;
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        r = rte_eal_remote_launch(worker_main, &wargs, lcore_id);
        if (r)
            rte_exit(1, "cannot launch: %s\n", rte_strerror(rte_errno));
        break;
    }

    uint64_t freq = rte_get_tsc_hz();
    for (unsigned i = 0; i < 10000; ++i) {
        rte_delay_us_block(999);
        while (1) {
            void *x = (void*) rte_rdtsc_precise();
            rte_ring_enqueue(m2w, x);
            break;
        }

        void *x = 0;
        while (rte_ring_dequeue(w2m, &x))
            rte_pause();
        uint64_t stop = rte_rdtsc_precise();
        uint64_t start = (uintptr_t)x;

        print_delta(0, start, stop, freq);

    }

    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        r = rte_eal_wait_lcore(lcore_id);
        if (r)
            rte_exit(1, "worker failed with: %d\n", r);
        break;
    }

    rte_eal_cleanup();
    return 0;
}
