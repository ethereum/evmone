#!/bin/sh
# You can call a custom executable here
# The code src comes in argument $1 as a path to a file containing the code
# So if you have custom compiler installed in the system the command would look like:
# mycompiler $1

# Make sure your tool output clean bytecode only with no log or debug messages
echo "0x600360005500"

# Copy this file under any name you want and make the changes
# In config file replace add the keyword and path to executable accordingly
#    "customCompilers" : {
#        ":mycompiler" : "mycompiler.sh",
#         ":keyword" : "myscript.sh"
#    },
# Where :keyword would be looked in test's Filler files
# And myscript.sh located in the system or .retesteth/default/myscript.sh with a call to your custom tool
# just like described in this file."
