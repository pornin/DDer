#! /bin/sh

CSC=$(which mono-csc || which dmcs || echo "none")

if [ $CSC = "none" ]; then
	echo "Error: Please install mono-devel."
	exit 1
fi

set -e
echo "DDer..."
$CSC /out:DDer.exe /main:DDer DDer/*.cs Asn1/*.cs
echo "MDer..."
$CSC /out:MDer.exe /main:MDer MDer/*.cs Asn1/*.cs ZInt/*.cs
