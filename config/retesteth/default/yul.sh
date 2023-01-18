#!/bin/sh
solc=$(which solc)
if [ -z $solc ]; then
   >&2 echo "yul.sh \"Yul compilation error: 'solc' not found!\""
   echo "0x"
else
    out=$(solc --assemble $1 2>&1)
    a=$(echo "$out" | grep "Binary representation:" -A 1 | tail -n1)
    case "$out" in
    *Error*) >&2 echo "yul.sh \"Yul compilation error: \"\n$out";;
    *       )  echo 0x$a;;
    esac
fi
