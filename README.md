# MicroSuite
µSuite: A Benchmark Suite for Microservices

µSuite is a suite of OLDI services that are each composed of front-end, mid-tier, and leaf microservice tiers. μSuite includes four OLDI services that incorporate open-source software: a content-based high dimensional search for image similarity — HDSearch, a replication-based protocol router for scaling fault-tolerant key-value stores — Router, a service for performing set algebra on posting lists for document retrieval — Set Algebra, and a user-based item recommender system for predicting user ratings — Recommend.
µSuite was originally written to evaluate OS and network overheads faced by microservices. You can find more details about µSuite in our IISWC paper (http://akshithasriraman.eecs.umich.edu/pubs/IISWC2018-%CE%BCSuite-preprint.pdf).

This µSuite Fork has been amended by ALPS in order to achieve the following:
- Correct and confirm all the installation/compilations commands to run on Ubuntu Linux 18.04
- Provide instructions to compile and run docker and prepare a docker image with the complete µSuite for easier deployment
- Provide instructions and the configuration to run the applications on single node using docker-compose.yaml
- Provide intrusctions and the configuration to run the applications on multiple nodes using docker-compose-swarm.yml
- Provide instructions and source code to run the application on single node allowing the system to enter c6.

# License & Copyright
µSuite is free software; you can redistribute it and/or modify it under the terms of the BSD License as published by the Open Source Initiative, revised version.

µSuite was originally written by Akshitha Sriraman at the University of Michigan, and per the the University of Michigan policy, the copyright of this original code remains with the Trustees of the University of Michigan.

If you use this software in your work, we request that you cite the µSuite paper ("μSuite: A Benchmark Suite for Microservices", Akshitha Sriraman and Thomas F. Wenisch, IEEE International Symposium on Workload Characterization, September 2018), and that you send us a citation of your work.

# Installation
To install µSuite, please follow these steps (works on Ubuntu 18.04):

# (1) ** Setup docker, cli and compose **

```
curl -fsSL https://get.docker.com -o get-docker.sh
DRY_RUN=1 sh ./get-docker.sh
sudo sh get-docker.sh
sudo apt -y install docker-compose
```
## for saving docker login to be able to push images
```
sudo apt -y install gnupg2 pass 
```
## change the storage folder for more space to commit the image (in our case when we use Cloudlab)
```
sudo docker rm -f $(docker ps -aq); docker rmi -f $(docker images -q)
sudo systemctl stop docker
umount /var/lib/docker
sudo rm -rf /var/lib/docker
sudo mkdir /var/lib/docker
sudo mount --rbind /mydata /var/lib/docker
sudo systemctl start docker
```

## Clone repository
```
mkdir microsuite
cd microsuite
git clone git@github.com:kendeasdimitriou/MicroSuite-hdsearch-pinjector.git
cd MicroSuite-hdsearch-pinjector
```
## Change to docker group
```
cd MicroSuite
sudo newgrp docker
```
## Run docker compose
```
sudo docker-compose up
```
Now we need to open a new terminal
# (2) ** Before entering the docker instance  **

## Send MicroPinfi
```
docker ps
cd microsuite
docker cp MicroPinfi microsuite_hdsearch_1:/
```
## Send updated files
```
cd changedFiles
docker cp bucket_server.cc microsuite_hdsearch_1:/MicroSuite/src/HDSearch/bucket_service/service
docker cp mid_tier_server.cc microsuite_hdsearch_1:/MicroSuite/src/HDSearch/mid_tier_service/service
docker cp load_generator_open_loop.cc microsuite_hdsearch_1:/MicroSuite/src/HDSearch/load_generator
docker cp atomics.cpp microsuite_hdsearch_1:/MicroSuite/src/HDSearch/mid_tier_service/src
```
At this point we need to login on the docker instance to execute our benchmark
```
cd MicroSuite
sudo docker-compose exec hdsearch sh
```
## Inside terminal Uptade ~/.bashrc
```
nano ~/.bashrc

export PIN_HOME=/MicroPinfi/pin-3.31
export PIN_ROOT=/MicroPinfi/pin-3.31
export PATH=$PIN_HOME:$PATH

source ~/.bashrc
```

From this point on we can execute each benchmark based on the commands provided in section (3)


# (3) ** Run benchmarks **

## ** HDSearch **

### Dataset for HDSearch
```
wget https://akshithasriraman.eecs.umich.edu/dataset/HDSearch/image_feature_vectors.dat 
mv ./image_feature_vectors.dat /home

```
### Bucket Service Command
```
cd /MicroSuite/src/HDSearch/bucket_service/service
make clean
make
./bucket_server /home/image_feature_vectors.dat 0.0.0.0:50050 2 -1 0 1

```
### Mid Tier Service - sudo command not found...
```
cd /MicroSuite/src/HDSearch/mid_tier_service/service
make clean
make
touch bucket_servers_IP.txt
echo "0.0.0.0:50050" > bucket_servers_IP.txt
./mid_tier_server 1 13 1 1 bucket_servers_IP.txt /home/image_feature_vectors.dat 2 0.0.0.0:50051 1 4 4 0   

```
### Client 
```
cd /MicroSuite/src/HDSearch/load_generator
make clean
make
mkdir ./results
./load_generator_open_loop /home/image_feature_vectors.dat ./results/ 1 30 100 0.0.0.0:50051 dummy1 dummy2 dummy3

```
# (4) ** Using Pin injection tools **
```
pin -t /MicroPinfi/pin-3.31/source/tools/ManualExamples/obj-intel64/[injection tool name you want to use].so -- ./sevice

example:
pin -t /MicroPinfi/pin-3.31/source/tools/ManualExamples/obj-intel64/fault_injection_specific_query_instr_forked_application2.so -- ./bucket_server /home/image_feature_vectors.dat 0.0.0.0:50050 2 -1 0 1
```
