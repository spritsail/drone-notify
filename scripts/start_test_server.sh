#/bin/bash
docker run \
    --rm -it -e DRONE_SECRET=test -p 1337:5000 \
    -v `pwd`/notify.conf.example:/config/notify.conf ${1:-drone-notify}