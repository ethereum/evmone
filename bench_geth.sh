#! /usr/bin/env bash

for file in synthetic_benchmarks/*
do
	echo $file
	go-ethereum/build/bin/evm --code $(xxd -c 30000 -p $file) --bench run
done
