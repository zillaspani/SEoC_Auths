#!/bin/bash

lista=("a1" "a2" "a3" "a4" "a5")
for elemento in "${lista[@]}"
do
    rm "${elemento}/app.py"
    # Execute the cp command, replacing "a1" with the current element of the list
    cp "./app.py" "${elemento}/app.py"
    cp "./migration_plan.json" "${elemento}/data/config/plan.json"
done

docker-compose up --build -d

sleep 180
lista2=("a1" "a2" "a3" "a4")
for elemento in "${lista2[@]}"
do
    docker kill ${elemento}
    sleep 180
done

sleep 180
docker kill a5
docker kill logger
