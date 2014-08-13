#!/bin/bash

mkdir -p /var/pysec
groupadd pysec > /dev/null 2>&1
useradd -d /var/pysec -s /sbin/nologin pysec -G pysec -c "Pysec secure user" > /dev/null 2>&1
chown pysec:pysec /var/pysec
