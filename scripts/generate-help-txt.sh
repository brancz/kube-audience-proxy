#!/usr/bin/env bash

echo "$ kube-audience-proxy -h" > _output/help.txt
_output/linux/amd64/kube-audience-proxy -h 2>> _output/help.txt
exit 0
