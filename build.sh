#!/bin/bash

# Set the directory for auto-search if dynamorio path is not given.
auto_search_dir=$HOME

# Locate DynamoRIO
script_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
if [ "$#" -ne 0 ]; then
    if [ "$#" -ne 1 ]; then
        echo "$0: Usage: $0 <DynamoRIO_dir>"
        exit 1
    else
        dynamorio_path=$1
    fi
else
    echo "$0: DynamoRIO path is not given. Looking for it in $auto_search_dir ..."
    auto_find_target_file="DynamoRIOConfig.cmake"
    dynamorio_config_cmake=$(find $auto_search_dir -name $auto_find_target_file | head -n 1)
    if [ -z "$dynamorio_config_cmake" ]; then
        echo "$0: Cannot find DynamoRIO. Please provide DynamoRIO path mannually with \"$0 <DynamoRIO_dir>\"."
        exit 1
    fi
    dynamorio_path=${dynamorio_config_cmake/"/cmake/$auto_find_target_file"/"/"}
    echo "$0: Found DynamoRIO at "$dynamorio_path
fi

# Build libpeekaboo
make

# Check Dynamorio
if [ -d $dynamorio_path ]; then
    echo "$0: Building Peekaboo DynamoRIO tracer..."
    cd peekaboo_dr
    rm -rf build && mkdir -p build 
    cd build && DynamoRIO_DIR=$dynamorio_path cmake .. && make
    cd ../../
    drrun_path=$dynamorio_path"/drrun"
    if [ -f $drrun_path ]; then
        # We found drrun
        echo "$0: Found drrun at "$drrun_path
    else
        drrun_path=$dynamorio_path"/bin64/drrun"
        if [ -f $drrun_path ]; then
            # We found drrun
            echo "$0: Found drrun at "$drrun_path
        else
            # Where is it?
            echo "$0: Unable to locate drrun for DynamoRIO."
            exit 1
        fi
    fi
    echo -e "#!/bin/bash\n$drrun_path -c $script_dir/peekaboo_dr/build/libpeekaboo_dr.so -- \$@" > $script_dir/peekaboo.sh
    chmod 777 $script_dir/peekaboo.sh
    echo "$0: Done. Run \"peekaboo.sh <application>\" to start tracing."
else # Unable to find DynamoRIO
    echo "Cannot open dynamorio directory $1."
fi
