#!/bin/bash

packages_tar_path=$1

mkdir -p /tmp/packages

tar -xzvf $packages_tar_path -C /tmp/
sudo cp /tmp/packages/libarchive13_3.6.0-1ubuntu1.5_amd64.deb /var/cache/apt-cacher-ng/svc.ni.vmware.com/repo/ubuntu22/pool/main/liba/libarchive/
sudo cp /tmp/packages/libglib2.0-0_2.72.4-0ubuntu2.6_amd64.deb /var/cache/apt-cacher-ng/svc.ni.vmware.com/repo/ubuntu22/pool/main/g/glib2.0/
sudo cp /tmp/packages/libglib2.0-data_2.72.4-0ubuntu2.6_all.deb /var/cache/apt-cacher-ng/svc.ni.vmware.com/repo/ubuntu22/pool/main/g/glib2.0/

sudo dpkg -i /tmp/packages/*.deb

sudo apt purge libwireshark-data -y

sudo rm -rf /var/hadoop-backup/log4j-1.2.17.jar

echo "After upgrade Please Verify below packages"
echo "=========================================="
sudo dpkg -l | grep libarchive13
sudo dpkg -l | grep libglib2.0-0
sudo dpkg -l | grep libglib2.0-data
sudo dpkg -l | grep libwireshark-data
sudo ls -ltrh /var/hadoop-backup/log4j-1.2.17.jar
