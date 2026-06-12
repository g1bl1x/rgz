#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (use sudo)"
    exit 1
fi

INSTALL_DIR="/usr/local/bin"
LIB_DIR="/usr/local/lib"

echo "Installing cryptum to $INSTALL_DIR"
cp build/cryptum $INSTALL_DIR/
chmod 755 $INSTALL_DIR/cryptum

echo "Installing crypto libraries to $LIB_DIR"
cp build/libvigenere.so $LIB_DIR/
cp build/libdes.so $LIB_DIR/
cp build/libshamir.so $LIB_DIR/
chmod 644 $LIB_DIR/lib*.so

echo "Installation complete"
echo "Usage: cryptum --help"