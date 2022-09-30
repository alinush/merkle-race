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

if [ $# -lt 2 ]; then
    echo "Usage: $0 <merkle-type> <output-csv-file> [<batch_size>]"
    echo
    echo "<merkle-type> can be either 'merkle_sha3', 'merkle_tiny_sha3', 'merkle_blake2s', 'merkle_blake2b', 'merkle++', or 'verkle'"
    exit 1
fi

type=$1; shift;
output_file=$1; shift;
updates="${1:-200,000}"

touch $output_file || { echo "ERROR: Cannot touch '$output_file'"; exit 1; }
        
echo "type,arity,num_leaves,num_updates,upds_per_sec,hashes_per_sec,num_hashes" >>$output_file

# remove commas from 'updates'
u=`echo "$updates" | tr -d ','`

for nn in $num_leaves; do
    n=`echo "$nn" | tr -d '#'`
    if echo $nn | grep "^#.*" &>/dev/null; then
        echo "Skipping benchmark for $n leaves..."
        continue
    fi

    for a in $arity; do
        if echo $a | grep "^#.*" &>/dev/null; then
            aa=`echo "$a" | tr -d '#'`
            echo "Skipping benchmark for $n leaves arity-$aa..."
            continue
        fi

        echo "Updating $updates out of $nn leaves in arity-$a $type tree..."

        # remove commas from 'n'
        n=`echo "$nn" | tr -d ','`

        #cargo run --release -- -t=$type -a $a -l $n -u $u 2>&1
        output=`cargo run --release -- -t=$type -a $a -l $n -u $u 2>&1`
        #echo "Return: $?"

        if [ $? -ne 0 ]; then
            echo
            echo "ERROR: cargo run failed to run benchmark"
            echo "---------------------"
            echo "$output"
            echo "---------------------"
            echo
        else
            upds_per_sec=`echo "$output" | grep -e 'Updates per second' | tr -d ',' | tr -dc '0-9'`
            hashes_per_sec=`echo "$output" | grep -e 'Hashes per second' | tr -d ',' | tr -dc '0-9'`
            num_hashes=`echo "$output" | grep -e 'hashes computed' | tr -d ',' | tr -dc '0-9'` 
            exp_time=`echo "$output" | grep -e 'Average time per exponentiation'` 

            echo "$upds_per_sec updates / sec"
            echo "$hashes_per_sec hashes / sec"
            echo "$num_hashes total hashes"
            [ -n "$exp_time" ] && echo "$exp_time"
            echo
            echo "$type,$a,$n,$u,$upds_per_sec,$hashes_per_sec,$num_hashes" >>$output_file
        fi
    done
done
