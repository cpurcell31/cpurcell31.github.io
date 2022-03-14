#!/bin/bash

printf "–––––––– Pictures Health Check ––––––––\n\n"

for kitten in $(seq 1 10); do
    printf "Testing Kitten $kitten: "
 
    wget -q --spider "http://localhost/assets/$kitten.jpg"

    if [[ $? == 0 ]] 
    then
        printf "OK!\n\n"    
    else
        printf "Not OK!\n\n"
    fi
done

printf "––––––––––––– Tests done –––––––––––––\n\n"