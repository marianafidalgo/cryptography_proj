#include <iostream>
#include <unistd.h>
using namespace std;

void generate_root_CA()
{
    system("cd Administrator\n mkdir root_CA\n chmod 0770 root_CA\n");

    system("cd Administrator/root_CA\n openssl genrsa -des3 -out admin_ca.key 2048\n"); 
    system("cd Administrator/root_CA\n openssl req -new -x509 -days 3650 -key admin_ca.key -out admin_ca.crt\n");

    // Put the root certificate in the tally official app;  
    system("cd Administrator/root_CA\n cp admin_ca.crt /mnt/c/Users/maria/Desktop/Uni/Mestrado/4oano/Cripto/Project/Tally_Official\n");
}

void generate_Voter_C (string name)
{
    string vk("cd Administrator/root_CA\nopenssl genrsa -des3 -out ");
    vk.append(name);
    vk.append("_cert.key 1024\n");

    const char * voter_key = vk.c_str();
    
    system(voter_key); 

    string vc("cd Administrator/root_CA\nopenssl req -new -key ");
    vc.append(name);
    vc.append("_cert.key -out ");
    vc.append(name);
    vc.append("_cert.csr\n");

    const char * voter_crt = vc.c_str();

    system(voter_crt); 

    string vca("cd Administrator/root_CA\nopenssl x509 -req -in ");
    vca.append(name);
    vca.append("_cert.csr -out ");
    vca.append(name);
    vca.append("_cert.crt -sha1 -CA admin_ca.crt -CAkey admin_ca.key -CAcreateserial -days 3650\n");

    const char * voter_CA = vca.c_str();

    system(voter_CA); 

    //Create Buddle

    string vpkcs12("cd Administrator/root_CA\nopenssl pkcs12 -export -in ");
    vpkcs12.append(name);
    vpkcs12.append("_cert.crt -inkey ");
    vpkcs12.append(name);
    vpkcs12.append("_cert.key -name \"");
    vpkcs12.append(name);
    vpkcs12.append(" Cert\" -out ");
    vpkcs12.append(name);
    vpkcs12.append("_cert.p12\n");

    const char * voter_pkcs12 = vpkcs12.c_str();

    system(voter_pkcs12); 

    string vchmod("cd Administrator/root_CA\nchmod 444 ");
    vchmod.append(name);
    vchmod.append("_cert.p12\n");

    const char * voter_chmod = vchmod.c_str();

    system(voter_chmod); 

    string vcp("cd Administrator/root_CA\ncp ");
    vcp.append(name);
    vcp.append("_cert.p12 /mnt/c/Users/maria/Desktop/Uni/Mestrado/4oano/Cripto/Project/");
    vcp.append(name);
    vcp.append("\n");

    const char * voter_cp = vcp.c_str();

    system(voter_cp);


}
// Generate the election key - a special homomorphic key pair (e.g. using Microsoft SEAL library, see below)

// Install on each voter app:
    // The root CA certificate
    // The voter private key and certificate
    // The election public key

// Split the election private key using Shamir’s secret sharing, distribute each of the shares by the trustees, and erase the private key.

// Assigns a weight to each voter, encrypts it with the election public key and publishes the list of encrypted weights.


int main() 
{
    //Generate a root CA certificate and private key;
    //generate_root_CA();

    //Generate a certificate for every voter
    
    generate_Voter_C("mariana");
    //generate_Voter_C("matilde");
    generate_Voter_C("xico");
    //generate_Voter_C("calamar");
    //generate_Voter_C("miguel");


}

