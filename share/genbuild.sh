#!/bin/sh

if [ $# -gt 0 ]; then
    FILE="$1"
    shift
    if [ -f "$FILE" ]; then
        INFO="$(head -n 2 "$FILE")"
    fi
else
    echo "Usage: $0 <filename>"
    exit 1
fi

if [ -e "$(which git)" ]; then
    # clean 'dirty' status of touched files that haven't been modified
    git diff >/dev/null 2>/dev/null 

    # get only commit hash, but format like describe
    DESCHASH="$(git rev-parse --short=9 HEAD 2>/dev/null)"

    # append dirty indicator
    if [ -n "$DESCHASH" ]; then
        if ! git diff-index --quiet HEAD -- 2>/dev/null
            then DESCHASH="${DESCHASH}-dirty" ; fi
    fi

    # get a string like "2012-04-10 16:27:19 +0200"
    TIME="$(git log -n 1 --format="%ci")"
fi

if [ -n "$DESCHASH" ]; then
    NEWINFO="#define BUILD_DESCHASH \"$DESCHASH\""
else
    NEWINFO="// No build information available"
fi

BUILD_SEQ="$(echo "$INFO" |grep "BUILD_DESCSEQ" |cut -d' ' -f3 )"
if [ "$BUILD_SEQ" -ge 0 ]; then
	if [ $BUILD_SEQ -ge 99 ]; then
		BUILD_SEQ=2
	else
		BUILD_SEQ=$((BUILD_SEQ+1))
	fi
	NEWINFO="$NEWINFO
#define BUILD_DESCSEQ $BUILD_SEQ"
else
	NEWINFO="$NEWINFO
#define BUILD_DESCSEQ 0"
fi



# only update build.h if necessary
if [ "$INFO" != "$NEWINFO" ]; then
    echo "$NEWINFO" >"$FILE"
    echo "#define BUILD_DATE \"$TIME\"" >>"$FILE"
fi
