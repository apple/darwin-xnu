#!/bin/sh

echo Raising process limits
echo limit maxproc 1000 2000 >> /etc/launchd.conf

echo Done.
