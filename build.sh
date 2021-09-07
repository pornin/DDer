#! /bin/sh

CSC=$(which mono-csc || which dmcs || echo "none")

if [ $CSC = "none" ]; then
	echo "Error: Please install mono-devel."
	exit 1
fi

set -e
echo "DDer..."
$CSC /out:DDer.exe /main:DDerCLI CLI/DDerCLI.cs Asn1/*.cs BigInt/*.cs
echo "MDer..."
$CSC /out:MDer.exe /main:MDerCLI CLI/MDerCLI.cs Asn1/*.cs BigInt/*.cs
