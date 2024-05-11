#!/bin/bash
chmod 777 "$1"
chmod 777 "$2"
#file_path=$1
#isolated_dir=$2
mv "$1" "$2"
#chmod 000 "./$2/$1"
#chmod 000 "$2"
exit 0