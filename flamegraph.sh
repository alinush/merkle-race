# image width
w=4000

sudo -u alinush cargo flamegraph --image-width 4000 --root -b merkle-race -- -t=merkle_sha3 -a 2 -h 28 -u 200000
