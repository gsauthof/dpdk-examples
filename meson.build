project('dpdk-examples', 'c')


dpdk = dependency('libdpdk')


pp_src = files('pingpong.c')
executable('pingpong', pp_src, dependencies: dpdk)

mcast_src = files('mcast_send.c')
executable('mcast_send', mcast_src, dependencies: dpdk)
