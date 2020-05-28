Administrator
---------------------------
Run in terminal:
$cmake .
$make
$./adm
In this file we:
-generate the election keys
-create the certificates for the root
-define the number of candidates
-create the certificates for the 3 voters
-assign a weight to each voter and encrypt them with the election public key
-split the election private key by three trustees using Shamir's secret sharing
NOTE: we also signed all the files sent to the Tally (weights, number of candidates, result)
