#!/bin/sh
if [ $1 = "-v" ]; then
    /Users/rodia/projects/evmone/build/bin/evmone-t8n -v
else
    stateProvided=0
    readErrorLog=0
    errorLogFile=""
    cmdArgs=""
    for index in ${1} ${2} ${3} ${4} ${5} ${6} ${7} ${8} ${9} ${10} ${11} ${12} ${13} ${14} ${15} ${16} ${17} ${18} ${19} ${20} ; do
        if [ $index = "--input.alloc" ]; then
            stateProvided=1
        fi
        if [ $readErrorLog -eq 1 ]; then
            errorLogFile=$index
            readErrorLog=0
            continue
        fi
        if [ $index = "--output.errorlog" ]; then
            readErrorLog=1
        fi
        if [ $readErrorLog -eq 0 ]; then
            cmdArgs=$cmdArgs" "$index
        fi
    done
    if [ $stateProvided -eq 1 ]; then
        /Users/rodia/projects/evmone/build/bin/evmone-t8n $cmdArgs 2> $errorLogFile
    else
        exit 13
    fi
fi
