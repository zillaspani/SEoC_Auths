#!/bin/bash

lista=("a1" "a2" "a3" "a4" "a5" "logger")

for elemento in "${lista[@]}"
do
    # Esegui il comando rm sostituendo "a1" con l'elemento corrente della lista
    rm "${elemento}/data/log/${elemento}_log.log"
done
