#!/bin/bash

while true; do
    filename=$(inotifywait -r -e MOVED_TO --format '%f' .)
    end="end.txt"
    echo "$filename"
    if [ "$filename" == "vote.txt" ]; then
	        head -n 1 vote.txt >> ballot.txt
			mv vote.txt ../TallyOfficial/TallyFiles
	elif [ "$filename" == "sign.sha256" ]; then
	        mv sign.sha256 ../TallyOfficial/TallyFiles
	elif [ "$filename" == "voter_cert.crt" ]; then
	        mv voter_cert.crt ../TallyOfficial/TallyFiles
			cd ../TallyOfficial
			./tally		
			cd ../Ballot
	fi
	if [ -f "$end" ]; then
			rm end.txt
	        break;
	fi

done