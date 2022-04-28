# image width
w=4000

sudo -u alinush cargo flamegraph --image-width 4000 --root -b merkle-race -o merkle++-flame -- -t=merkle++ -a 16 -l 500000000 -u 20000

sudo -u alinush cargo flamegraph --image-width 4000 --root -b merkle-race -o verkle-flame -- -t=verkle -a 16 -l 500000000 -u 20000
