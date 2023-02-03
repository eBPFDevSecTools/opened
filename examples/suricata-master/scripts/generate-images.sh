#!/usr/bin/env bash
#
# Script to generate Sequence Diagram images with mscgen
#

parent_path=$(cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P)

set -e

cd "$parent_path"
cd ../doc/userguide/devguide/extending/app-layer/diagrams

for FILE in *.msc ; do
    # call mscgen and convert each file in images dir
    echo "Generating image for $FILE"
    mscgen -T png -F Arial $FILE
    # if command fails, lets inform about that
    if [ $? -ne 0 ]; then
        echo "$FILE couldn't be converted in the devguide"
        # let's exit to make it more evident something is amiss
        exit 1
    fi
done

exit 0
