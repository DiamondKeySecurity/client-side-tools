#!/bin/sh
# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
#
# Script to import CrypTech code into DKS HSM folders.
#
rm -rf cryptech
mkdir -p cryptech/cryptech
cp -f ../../CrypTech/sw/libhal/cryptech_backup cryptech/backup.py
cp -f ../../CrypTech/sw/libhal/cryptech/* cryptech/cryptech/
echo '#!/usr/bin/env python\n# Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.\n#\n\n__all__ = ["muxd", "backup"]' > cryptech/__init__.py
echo 'DO NOT add or modify files or sub-folders in this folder. This folder contains unmodified Cryptech code that is automatically pulled from Cryptech. Any changes will be overwritten.' > cryptech/X_DO_NOT_MODIFY_FOLDER_X.txt
echo 'Copy Complete'
