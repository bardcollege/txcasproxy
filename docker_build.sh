#!/bin/bash

IMG="bard-cas/txcasproxy:latest"
SRV="k8s-master01.bard.edu:5000"

sudo docker build -t $IMG .
sudo docker tag $IMG $SRV/$IMG
sudo docker push $SRV/$IMG
