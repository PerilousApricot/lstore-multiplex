#!/bin/bash
set -x
mkdir -p /lstore-multiplex
chmod 775 /lstore-multiplex
chown uscms01:cms /lstore-multiplex
cp /scratch/meloam/lstore-multiplex/lstore-multiplex.hellermf /etc/init.d/lstore-multiplex
/etc/init.d/lstore-multiplex start
[ -h /store ] && unlink /store
[ -h /store ] && rm /store
ln -s /lstore-multiplex /store
