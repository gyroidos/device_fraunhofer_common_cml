#!/bin/bash
export SOFTHSM2_CONF=$(pwd)/softhsm2.conf

mkdir /tmp/testtokens

./p11test

rm -rf /tmp/testtokens