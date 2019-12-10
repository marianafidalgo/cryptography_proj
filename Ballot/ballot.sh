#!/bin/sh

while inotifywait -e MOVED_TO -r .; do
  cat vote.txt >> ballot.txt
  mv vote.txt /home/mariana/Desktop/Project/TallyOfficial
  mv vote_sig.txt /home/mariana/Desktop/Project/TallyOfficial
  cd ..
  ./tally
done
