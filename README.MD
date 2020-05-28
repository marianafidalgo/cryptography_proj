# Homomorphic Vote Tally
--------------------------
### *IMPORTANT NOTE: To run some of the files you need to adjust to your PC directories. 
(In the administrator: line 147  and in the counter: line 40
### *IMPORTANT NOTE: you need to run the following command to allow the use of Shamir Secret Sharing. 
## Run in terminal:
$cargo install --git https://github.com/dsprenkels/sss-cli --branch v0.1

*To begin the election you should compile the .cpp inside the
Administrator directory (inside you'll find the respective README file).

*You should now go to the Ballot directory, and run the bash script. This with allow
the voting process to be automated, by fowarding the votes (sent by the voters) to the 
TallyOfficial directory.
To be automated install:
$sudo apt-get install -y inotify-tools

*The script mentioned above is monitoring the Ballot directory and it compiles the .cpp inside the 
TallyOfficial directory.

*If there was at least one valid vote, if the user wants, it can show the election result.

*Our election is prepared to only have three voters, so you can send votes from each one of
these. Go inside the Voter(1,2,3) directory and run the .cpp file.

*The election is prepared to delete all created files and directories, when it ends.
