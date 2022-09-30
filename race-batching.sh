#!/bin/sh

num_leaves_friendly="2,000,000,000"
#num_leaves_friendly="2,000,000"

# Batch size from 1 through all the powers of 2 until 2^20.
batch_sizes="1"
u=1
for i in `seq 1 20`; do
  u=$(($u*2))
  batch_sizes=`echo "$batch_sizes\n$u"`
done

if [ $# -lt 3 ]; then
    echo "Usage: $0 <merkle-type> <arities> <output-csv-file>"
    echo
    echo "<merkle-type> can be either 'merkle_sha3', 'merkle_tiny_sha3', 'merkle_blake2s', 'merkle_blake2b', 'merkle++', or 'verkle'"
    echo "<arities> is a space-separated list of arities to benchmark. For example '2 4 8 16'."
    exit 1
fi

type=$1; shift;
arities=`echo "$1" | tr ' ' '\n'`; shift;
output_file=$1; shift;

touch $output_file || { echo "ERROR: Cannot touch '$output_file'"; exit 1; }

num_leaves=`echo $num_leaves_friendly | tr -d ','`
        
echo "type,arities,num_leaves,batch_size,upds_per_sec,hashes_per_sec,num_hashes" >>$output_file

for arity in $arities; do
    if echo $arity | grep "^#.*" &>/dev/null; then
        aa=`echo "$arity" | tr -d '#'`
        echo "Skipping benchmark for arity-$aa..."
        continue
    fi

    for batch_size in $batch_sizes; do
        bs=`echo "$batch_size" | tr -d '#'`
        if echo $batch_size | grep "^#.*" &>/dev/null; then
            echo "Skipping benchmark for arity-$arity batch size $bs..."
            continue
        fi

        echo "Updating $batch_size out of $num_leaves_friendly leaves in arity-$arity $type tree..."

        # remove commas from '$batch_size', if any
        batch_size=`echo "$batch_size" | tr -d ','`

        #echo "cargo run --release -- -t=$type --arity=$arity -l=$num_leaves -u=$batch_size 2>&1"
        output=`cargo run --release -- -t=$type --arity=$arity -l=$num_leaves -u=$batch_size 2>&1`
        #echo "$output"
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
            echo "$type,$arity,$num_leaves,$batch_size,$upds_per_sec,$hashes_per_sec,$num_hashes" >>$output_file
        fi
    done
done
