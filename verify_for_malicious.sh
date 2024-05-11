#!/bin/bash
chmod 777 "$1"
file_path=$1
isolated_dir=$2
shift 2
if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <file_path> <isolated_dir> <keyword1> [<keyword2> ...]"
    chmod 000 "$1"
    exit 1
fi

if [ ! -f "$file_path" ]; then
    echo "Error: File '$file_path' does not exist."
    chmod 000 "$1"
    exit 1
fi
ok=0
line_count=$(wc -l < "$file_path") 
word_count=$(wc -w < "$file_path")
char_count=$(wc -m < "$file_path")

#echo "Line count: $line_count"
#echo "Word count: $word_count"
#echo "Character count: $char_count"

if [ $line_count -lt 3 ]; then
    #echo "Warning: Line count is less than 3"
    ok=1
    #exit 1
fi

if [ $word_count -gt 1000 ]; then
    #echo "Warning: Word count is greater than 1000"
    ok=1
    #exit 1
fi

if [ $char_count -gt 2000 ]; then
    #echo "Warning: Character count is greater than 2000"
    ok=1
    #exit 1
fi

if grep -qP '[^\x00-\x7F]' "$file_path"; then   
    #echo "Warning: File '$file_path' has non-Ascii characters."
    ok=1
fi

for keyword in "$@"; do
    if grep -q "$keyword" "$file_path"; then
        #echo "Warning: File '$file_path' may be potentially malicious (contains keyword: $keyword)."
        ok=1
        #mv "$file_path" "$isolated_dir"
        break
    fi
done

if [ $ok -eq 1 ]; then
    echo "$file_path"
    chmod 000 "$1"
    exit 1
    else 
    echo "SAFE"
fi


chmod 000 "$1"
exit 0
