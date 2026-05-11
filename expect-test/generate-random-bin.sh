#!/bin/bash
dd if=/dev/urandom of=random.bin bs=1M count=1024 status=progress
sha256sum random.bin | tee random.bin.sha256
