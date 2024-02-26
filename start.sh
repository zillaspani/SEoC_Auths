#!/bin/bash

lista=("a1" "a2" "a3")

for elemento in "${lista[@]}"
do
    rm "${elemento}/app.py"
    # Execute the cp command, replacing "a1" with the current element of the list
    cp "./app.py" "${elemento}/app.py"
done

docker-compose up --build

#sleep 5
#lista2=("a3" "a2" "a1")
#for elemento in "${lista[@]}"
#do
#    sleep 5
#    docker kill ${elemento}
#done
