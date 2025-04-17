#!/bin/bash

set -e

DEB_FILE=$1
EXTRACT_DIR=work

if [ -z "$DEB_FILE" ]; then
  echo "Usage: $0 your.deb"
  exit 1
fi

mkdir -p $EXTRACT_DIR
dpkg-deb -x "$DEB_FILE" $EXTRACT_DIR
dpkg-deb -e "$DEB_FILE" $EXTRACT_DIR/control
