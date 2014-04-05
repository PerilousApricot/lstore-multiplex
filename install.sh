#!/bin/bash
set -x
mkdir -p /lstore-multiplex
chmod 775 /lstore-multiplex
chown uscms01:cms /lstore-multiplex
cp /scratch/meloam/lstore-multiplex/lstore-multiplex /etc/init.d/
/etc/init.d/lstore-multiplex start
[ -h /store ] && unlink /store
[ -h /store ] && rm /store
ln -s /scratch/meloam/lstore-multiplex/testmount /store
