This was benchmarked with `flamegraph.sh`:

    sudo -u alinush cargo flamegraph --image-width 4000 --root -b merkle-race -- -t=merkle_sha3 -a 2 -h 28 -u 200000

..at commit 7ae9e4d388ab037c9ec0bc43b7163079c73fae9e
