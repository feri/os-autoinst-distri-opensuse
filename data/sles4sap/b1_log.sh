#!/bin/bash -e
#
# Summary: script that parses a given B1 validation results log (usually found 
# under /var/log/SAPBusinessOne/B1Installer_<date>.log) and return 1 in case of 
# failures found in log, otherwise return 0.
# Maintainer: QE-SAP <qe-sap@suse.de>

# check if log file is given
if [[ $# -eq 0 ]] ; then
    echo 'No parameters given'
    exit 1
fi

# Read the input file line by line, combine broken lines without timestamp
fix_broken_log(){
    while IFS= read -r line; do
        line=$(echo $line | sed 's/[\/&]/\\&/g')
        if [[ $line =~ ^[[:space:]]*\[[0-2][0-9]:[0-5][0-9]:[0-5][0-9]\].* ]]; then
            echo "$line" >> "$fixed"
        else
            if [[ -s $fixed ]]; then
                sed -i -e '$ s/$/ '"$line"'/g' "$fixed" || exit 1
            fi
        fi
    done < "$1"
}

# parse B1 log file and look for line with possible failures
# first pass
first=$(mktemp /tmp/tempXXXX)
failures=0
warnings=0
success=0
info=0
sed -n '/^-\{80\}$/,/^-\{80\}$/ { /^-\{80\}$/!p }' "$1"  > $first
echo "Validation results:"
while IFS="" read -r line; do
    echo $line | grep -q ERROR && failures=$((failures+1))
    echo $line | grep -q WARNING && warnings=$((warnings+1))
    echo $line | grep -q SUCCESS && success=$((success+1))
    echo $line | grep -q INFO && info=$((info+1))
    echo $line
done < $first

echo -e ""

# second pass
second=$(mktemp /tmp/tempXXXX)
fixed=$(mktemp /tmp/tempXXXX)
sed -n 'H;${x;s/.*\(^\(-\{80\}\).*\)/\1/;p}' "$1" | sed -n '/^-\{80\}$/,$p' > $second
#cleanup removing lines starting with a timestap YYYY-MM-DD
sed -i -e '/\[[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}\].*/d' $second
fix_broken_log $second
# keep only lines with Sap Note
sed -i -e '/.*\[Sap Note.*/!d' $fixed
echo "Sap Notes:"
while IFS="" read -r line; do
    echo $line | grep -q ERROR && failures=$((failures+1))
    echo $line | grep -q SUCCESS && success=$((success+1))
    echo $line | grep -q INFO && info=$((info+1))
    echo $line | grep -q WARNING && warnings=$((warnings+1))
    echo $line
done < $fixed

# clean temp files
rm -f $first
rm -f $second
rm -f $fixed

# test results
echo -e ""
echo "Test results:"
echo "SUCCESS: $success"
echo "INFO: $info"
echo "WARNING: $warnings"
echo "ERROR: $failures"

# Check for failures
if [ $failures -gt 0 ]; then
    echo "============= Some failures found ============="
    echo "=============== Check logs!!  ================="
    exit 1
else
    # else, no failures found
    exit 0
fi

