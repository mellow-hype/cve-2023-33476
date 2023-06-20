#!/bin/bash

patch -ruN -p1 -d ./minidlna-1.3.0 --verbose < patches/upnphttp-fix.patch
