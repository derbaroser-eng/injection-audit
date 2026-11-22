#!/bin/sh
# deployment wrapper used by the demo corpus
read target
LOGDIR=$(cat /etc/logdir)
sh -c "$target"
eval "$COMMAND"
ssh deploy@prod "ls $LOGDIR"
