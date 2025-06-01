#!/bin/bash
# TA ARXIA POY DIMIOURGOUNTE APO PINTOOL(TRACE, INJECTIONS) DIMIOURGOUNTE SE APPEND MODE


pkill bucket_server
pkill mid_tier_server

cd /MicroSuite/src/HDSearch/bucket_service/service || exit 1
make clean
make
pin -t /MicroPinfi/pin-3.31/source/tools/ManualExamples/obj-intel64/micro_pinfi_FPU.so -n 500 -- ./bucket_server /home/image_feature_vectors.dat 0.0.0.0:50050 2 -1 0 1 &

sleep 120


cd /MicroSuite/src/HDSearch/mid_tier_service/service || exit 1
make clean
make
./mid_tier_server 1 13 1 1 bucket_servers_IP.txt /home/image_feature_vectors.dat 2 0.0.0.0:50051 1 4 4 0 &


sleep 20


cd /MicroSuite/src/HDSearch/load_generator || exit 1
make clean
make
./load_generator_open_loop /home/image_feature_vectors.dat ./results/ 1 2000 0.01 0.0.0.0:50051 dummy1 dummy2 dummy3


pkill bucket_server
pkill mid_tier_server

cd /MicroSuite/src/HDSearch/bucket_service/service || exit 1

# Loop over all files that start with "OutFile_child_"
for child_file in OutFile_child_*.txt; do
    # Extract the ID from the filename (after the second underscore)
    id=$(echo "$child_file" | cut -d'_' -f3 | cut -d'.' -f1)

    # Construct the corresponding parent filename
    parent_file="OutFile_parent_${id}.txt"
    diff_file="differences_${id}.txt"

    # If the corresponding parent file exists, perform the diff
    if [[ -f "$parent_file" ]]; then
        echo "Comparing: $child_file vs $parent_file"
        diff "$child_file" "$parent_file" > "$diff_file"
    else
        echo "Missing parent for ID $id: $parent_file not found"
    fi
done
