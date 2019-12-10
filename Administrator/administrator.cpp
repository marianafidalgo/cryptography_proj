#include "../Header.h"

#include <iostream>
#include <unistd.h>
#include <fstream>

#include <algorithm>
#include "seal/keygenerator.h"
#include "seal/randomtostd.h"
#include "seal/util/common.h"
#include "seal/util/uintcore.h"
#include "seal/util/uintarith.h"
#include "seal/util/uintarithsmallmod.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/clipnormal.h"
#include "seal/util/polycore.h"
#include "seal/util/smallntt.h"
#include "seal/util/rlwe.h"

using namespace std;
using namespace seal;


void generate_root_CA()
{
    system("mkdir root_CA\n chmod 0770 root_CA\n");

    system("cd root_CA\n openssl genrsa -des3 -out root_ca.key 2048\n");
    system("cd root_CA\n openssl req -new -x509 -days 3650 -key root_ca.key -out root_ca.crt\n");

    // Put the root certificate in the tally official app
    system("cd root_CA\n cp root_ca.crt /home/mariana/Desktop/Project/Tally_Official\n");
}

void generate_Voter_C (string name)
{
    string vk("cd root_CA\nopenssl genrsa -out "); //removed -des3 to create without pass
    vk.append(name);
    vk.append("_private.key 1024\n");

    const char * voter_key = vk.c_str();

    system(voter_key);

    string vc("cd root_CA\nopenssl req -new -key ");
    vc.append(name);
    vc.append("_private.key -out ");
    vc.append(name);
    vc.append("_req.csr\n");

    const char * voter_csr = vc.c_str();

    system(voter_csr);

    string vcrt("cd root_CA\nopenssl x509 -req -in ");
    vcrt.append(name);
	vcrt.append("_req.csr -out ");
	vcrt.append(name);
	vcrt.append("_cert.crt -sha1 -CA root_ca.crt -CAkey root_ca.key -CAcreateserial -days 3650\n");

    const char * voter_crt = vcrt.c_str();

    system(voter_crt);

	string vpub("cd root_CA\nopenssl req -in ");
	vpub.append(name);
	vpub.append("_req.csr -noout -pubkey -out ");
	vpub.append(name);
	vpub.append("_publickey.pem\n");

	const char* voter_pubkey = vpub.c_str();

	system(voter_pubkey);

}

void install_in_voter_app(string name)
{

    // The root CA certificate
    string rca("cd root_CA\ncp root_ca.crt /home/mariana/Desktop/Project/");
    rca.append(name);
    rca.append("\n");

    const char * root_ca = rca.c_str();

    system(root_ca);

    // The election public key
    string epk("cd Administrator/Homomorphic_keys\ncp SEAL_publickey.key /home/mariana/Desktop/Project/");
    epk.append(name);
    epk.append("\n");

    const char * election_public_key = epk.c_str();

    system(election_public_key);

    // The voter certificate
    string vct("cd root_CA\ncp ");
	vct.append(name);
	vct.append("_cert.crt /home/mariana/Desktop/Project/");
	vct.append(name);
	vct.append("\n");

    const char * voter_ct = vct.c_str();

    system(voter_ct);

	// The voter private key
	string vk("cd root_CA\ncp ");
	vk.append(name);
	vk.append("_private.key /home/mariana/Desktop/Project/");
	vk.append(name);
	vk.append("\n");

	const char* voter_k = vk.c_str();

	system(voter_k);

	// The voter public key
	string pk("cd root_CA\ncp ");
	pk.append(name);
	pk.append("_publickey.pem /home/mariana/Desktop/Project/");
	pk.append(name);
	pk.append("\n");

	const char* voter_pk = pk.c_str();

	system(voter_pk);
}

void shamir_secret_sharing()
{

    //put secret key in the folder
    system("cd Administrator/Homomorphic_keys\n cp SEAL_secretkey.key /home/mariana/.cargo/bin \n");

    //Make 3 shares with recombination threshold 3 and in the end remove it
    system("cd ~/.cargo/bin \n cat SEAL_secretkey.key | ./secret-share-split -n 3 -t 3 > splitted.txt\n cp  splitted.txt /home/mariana/Desktop/Project/\n rm SEAL_secretkey.key\n");

    //split in files
    string line;
    std::ifstream myfile("splitted.txt");
    std::ofstream out1("trustee1.txt");
    std::ofstream out2("trustee2.txt");
    std::ofstream out3("trustee3.txt");
    if (myfile)  // same as: if (myfile.good())
    {
        getline( myfile, line );
        out1 << line;
        out1.close();
        getline( myfile, line );
        out2 << line;
        out2.close();
        getline( myfile, line );
        out3 << line;
        out3.close();
        myfile.close();
    }

    //copy files to voters folder
    system("cp trustee1.txt /home/mariana/Desktop/Project/mariana \n");
    system("cp trustee1.txt /home/mariana/Desktop/Project/matilde\n");
    system("cp trustee1.txt /home/mariana/Desktop/Project/xico \n");
    system("rm splitted.txt");
    //remove private key
    system("cd Administrator/Homomorphic_keys\n rm SEAL_secretkey.key \n");

    //Take the first 3 shares and combine them
    //system("cd ~/.cargo/bin \n cat splitted.txt | ./secret-share-combine > reu.key \n");

}

void assigns_voters_weights()
{
    int N = 3;

	//put secret key in the folder

	//split in files
	string line;
	std::ofstream weight1("weight_1.txt");
    std::ofstream weight2("weight_2.txt");
    std::ofstream weight3("weight_3.txt");
    std::ofstream candi("n_candidates.txt");

    // //Estão em hexa
    // int um = 5;
    // int dois = 3;
	// int tres = 2;
    // //encrypts

    // Plaintext plain_1(um.to_string());
    // Plaintext plain_2(dois.to_string());
    // Plaintext plain_3(tres.to_string());


    //Parametros do Encryptor
	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree = 8192;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
	auto context = SEALContext::Create(parms);

	print_line(__LINE__);
	std::cout << "Set encryption parameters and print" << endl;
	print_parameters(context);

	//Load das Keys
	ifstream stream_public_Key;
	ifstream stream_private_Key;

	PublicKey public_key;
	SecretKey secret_key;

	stream_public_Key.open("/home/mariana/Desktop/Project/Administrator/Homomorphic_keys/SEAL_public.key", ios::binary);
	stream_private_Key.open("/home/mariana/Desktop/Project/Administrator/Homomorphic_keys/SEAL_secretkey.key",  ios::binary);

	public_key.load(context, stream_public_Key);
	secret_key.load(context, stream_private_Key);

	//Criação do Encryptor
	Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
	BatchEncoder batch_encoder(context);
    size_t slot_count = batch_encoder.slot_count();
	size_t row_size = slot_count / 2;

    vector<uint64_t> pod_matrix1(slot_count, 0ULL);
    vector<uint64_t> pod_matrix2(slot_count, 0ULL);
    vector<uint64_t> pod_matrix3(slot_count, 0ULL);
    vector<uint64_t> pod_matrix4(slot_count, 0ULL);
    // vector<uint64_t> pod_result1(slot_count, 0ULL);
    // vector<uint64_t> pod_result2(slot_count, 0ULL);
    // vector<uint64_t> pod_result3(slot_count, 0ULL);

    Plaintext plain_matrix1, plain_matrix2, plain_matrix3, plain_matrix4;

    for (int i = 0; i < slot_count; i++) {
		pod_matrix1[i] = 5;
        pod_matrix2[i] = 3;
        pod_matrix3[i] = 2;
        pod_matrix4[i] = N;
    }


	cout << "Input plaintext matrix:" << endl;
	print_matrix(pod_matrix1, row_size);
    print_matrix(pod_matrix2, row_size);
    print_matrix(pod_matrix3, row_size);
    print_matrix(pod_matrix4, row_size);

	cout << "Encode plaintext matrix:" << endl;
	batch_encoder.encode(pod_matrix1, plain_matrix1);
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    batch_encoder.encode(pod_matrix3, plain_matrix3);
    batch_encoder.encode(pod_matrix4, plain_matrix4);

	/*
	Next we encrypt the encoded plaintext.
	*/
	Ciphertext encrypted_1;
    Ciphertext encrypted_2;
    Ciphertext encrypted_3;
    Ciphertext encrypted_4;
	print_line(__LINE__);
	cout << "Encrypt plain_matrix to encrypted_matrix." << endl;
	encryptor.encrypt(plain_matrix1, encrypted_1);
    encryptor.encrypt(plain_matrix2, encrypted_2);
	encryptor.encrypt(plain_matrix3, encrypted_3);
    encryptor.encrypt(plain_matrix4, encrypted_4);


    // Ciphertext encrypted_1;
    // Ciphertext encrypted_2;
    // Ciphertext encrypted_3;
	// print_line(__LINE__);
	// cout << "Encrypt plain_matrix to encrypted_matrix." << endl;
	// encryptor.encrypt(plain_1, encrypted_1);
    // encryptor.encrypt(plain_2, encrypted_2);
    // encryptor.encrypt(plain_3, encrypted_3);

    // decryptor.decrypt(encrypted_1, um);
    // decryptor.decrypt(encrypted_2, dois);
    // decryptor.decrypt(encrypted_3, tres);

    // cout << um.to_string() << "\n";
    // cout << dois.to_string() << "\n";
    // cout << tres.to_string() << "\n";

	encrypted_1.save(weight1);
    encrypted_2.save(weight2);
    encrypted_3.save(weight3);
    encrypted_4.save(candi);

    Plaintext cenas1, cenas2, cenas3;

    // decryptor.decrypt(encrypted_1, cenas1);
    // batch_encoder.decode(cenas1, pod_result1);
    // print_matrix(pod_result1, row_size);
    // decryptor.decrypt(encrypted_2, cenas2);
    // batch_encoder.decode(cenas2, pod_result2);
    // print_matrix(pod_result2, row_size);
    // decryptor.decrypt(encrypted_3, cenas3);
    // batch_encoder.decode(cenas3, pod_result3);
    // print_matrix(pod_result3, row_size);

    weight1.close();
    weight2.close();
    weight3.close();

	//copy files to voters folder
    system("cp weight_1.txt weight_2.txt weight_3.txt n_candidates.txt /home/mariana/Desktop/Project/TallyOfficial \n");

}


void generates_election_keys()
{
    EncryptionParameters parms(scheme_type::BFV);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(1024);
    auto context = SEALContext::Create(parms);

    EncryptionParameters params(scheme_type::BFV);
    size_t poly_modulus_degreee = 8192;
    params.set_poly_modulus_degree(poly_modulus_degreee);
    params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degreee));
    params.set_plain_modulus(PlainModulus::Batching(poly_modulus_degreee, 20));
    auto context1 = SEALContext::Create(params);

    ofstream stream_public_Key;
    ofstream stream_private_key;
    ofstream stream_galois_keys;
    stream_public_Key.open("/home/mariana/Desktop/Project/Administrator/Homomorphic_keys/SEAL_public.key");
    stream_private_key.open("/home/mariana/Desktop/Project/Administrator/Homomorphic_keys/SEAL_secretkey.key");
    stream_galois_keys.open("/home/mariana/Desktop/Project/Administrator/Homomorphic_keys/galois.key");

    KeyGenerator keygen(context1);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();
    GaloisKeys gal_keys = keygen.galois_keys();

    public_key.save(stream_public_Key );
    secret_key.save(stream_private_key);
    gal_keys.save(stream_galois_keys);

}

int main()
{
    //Generate a root CA certificate and private key;
    //generate_root_CA();

    //Generate a certificate for every voter
    printf("ADMIN\n");
   //generate_Voter_C("ter");
    /*generate_Voter_C("matilde");
    generate_Voter_C("xico");*/

	//Generate the election key - a special homomorphic key pair (e.g. using Microsoft SEAL library, see below)
   // generates_election_keys();

    // Install on each voter app:
    /*install_in_voter_app("mariana");
    install_in_voter_app("matilde");
    install_in_voter_app("xico");*/


    // Split the election private key using Shamir’s secret sharing, distribute each of the shares by the trustees, and erase the private key.
    //shamir_secret_sharing();

    // Assigns a weight to each voter, encrypts it with the election public key and publishes the list of encrypted weights.
	assigns_voters_weights();



}