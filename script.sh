SRC_DIR='./linux-6.2.10'

# TODO: support multiple definitions, and remove wrong definitions
# Currently ignoring COMPAT_SYSCALL_DEFINE
# Currently ignoring user-space syscalls
# Currently taking average of number of arguments
get_syscall_args() {
    echo $1 $2
    definition=$(find $SRC_DIR \( -not -path "$SRC_DIR/arch/*" -o -path "$SRC_DIR/arch/x86/*" \) \
        -not -path "*/um/*" -name '*.c' | xargs grep -Pzoh "\bSYSCALL_DEFINE\d?\($2(,[^)]*)?\)")
    
    # if no definition found, return
    if [ -z "$definition" ]; then
        echo "No definition found\n"
        return
    fi
    nparen=$(echo $definition | tr -cd '(' | wc -c)
    ncomma=$(echo $definition | tr -cd ',' | wc -c)
    nargs=$(echo $ncomma $nparen | awk '{print $1/($2*2)}')
    echo $definition
    echo $nargs
    echo
}

# OKay now I see that the number after SYSCALL_DEFINE
# is the number of arguments
get_nargs() {
    nargs=$(find $SRC_DIR \( -not -path "$SRC_DIR/arch/*" -o -path "$SRC_DIR/arch/x86/*" \) \
        -not -path "*/um/*" -name '*.c' | xargs grep -Pzoh "\bSYSCALL_DEFINE\d?\($2[,)]" |\
        tr -dc '[:digit:]' | head -c 1;)
    echo "$1 $nargs"
}

# Analytical version, count no. of ','
#grep -E '^[0-9]+\s+(64|common)' $SRC_DIR/arch/x86/entry/syscalls/syscall_64.tbl |\
#    awk -F " " '{print $1 " " $3}' | while read syscall; do get_syscall_args $syscall; done

# Heuristic version, extract the number after SYSCALL_DEFINE
grep -E '^[0-9]+\s+(64|common)' $SRC_DIR/arch/x86/entry/syscalls/syscall_64.tbl |\
    awk -F " " '{print $1 " " $3}' | while read syscall; do get_nargs $syscall; done