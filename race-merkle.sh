num_leaves="
1,000,000
10,000,000 
100,000,000
1,000,000,000
2,000,000,000
"

arity="
2
4
8
16
32
64
128
256
512
1024"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <merkle-type>"
    echo
    echo "<merkle-type> can be either 'merkle_sha3', 'merkle_blake2s' or 'merkle++'"
    exit 1
fi

type=$1

updates="200,000"
        
echo "type,arity,num_leaves,num_updates,upds_per_sec,hashes_per_sec,num_hashes"

# remove commas from 'updates'
u=`echo "$updates" | tr -d ','`

for nn in $num_leaves; do
    for a in $arity; do
        echo >&2
        echo "Updating $updates out of $nn leaves in arity-$a $type tree..." >&2

        # remove commas from 'n'
        n=`echo "$nn" | tr -d ','`

        output=`cargo run --release -- -t=$type -a $a -l $n -u $u 2>&1`

        #echo "----"
        #echo "$output"
        #echo "----"

        upds_per_sec=`echo "$output" | grep -e 'Updates per second' | tr -d ',' | tr -dc '0-9'`
        hashes_per_sec=`echo "$output" | grep -e 'Hashes per second' | tr -d ',' | tr -dc '0-9'`
        num_hashes=`echo "$output" | grep -e 'hashes computed' | tr -d ',' | tr -dc '0-9'` 

        echo "$type,$a,$n,$u,$upds_per_sec,$hashes_per_sec,$num_hashes"
    done
done
