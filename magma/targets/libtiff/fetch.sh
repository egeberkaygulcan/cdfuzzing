#!/bin/bash

##
# Pre-requirements:
# - env TARGET: path to target work dir
##

# Retry git clone up to 3 times with backoff — needed because 60 workers can
# hit GitLab simultaneously and trigger rate-limiting/transient failures.
for attempt in 1 2 3; do
    rm -rf "$TARGET/repo"
    git clone --no-checkout https://gitlab.com/libtiff/libtiff.git \
        "$TARGET/repo" && break
    echo "libtiff clone attempt $attempt failed; retrying in $((attempt * 30))s..."
    sleep $((attempt * 30))
    [ "$attempt" -eq 3 ] && { echo "ERROR: libtiff clone failed after 3 attempts"; exit 1; }
done

git -C "$TARGET/repo" checkout c145a6c14978f73bb484c955eb9f84203efcb12e

cp "$TARGET/src/tiff_read_rgba_fuzzer.cc" \
    "$TARGET/repo/contrib/oss-fuzz/tiff_read_rgba_fuzzer.cc"
