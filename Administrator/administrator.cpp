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
    cout << "\n\n Gerar chave do Administrador\n";
    system("cd root_CA\n openssl genrsa -out root_ca.key 2048\n");  //removed -des3 to create without pass
    cout << "\n\n Gerar certificado do Administrador\n";
    system("cd root_CA\n openssl req -new -x509 -days 3650 -key root_ca.key -out root_ca.crt\n");

    // Put the root certificate in the tally official app
    system("mkdir TallyFiles\n chmod 0770 TallyFiles\n mv TallyFiles ../TallyOfficial\n");
    system("cd root_CA\n cp root_ca.crt ../../TallyOfficial/TallyFiles\n");

}

void generate_Voter_C (string name)
{
    cout << "\n\nGerar chave privada "<< name <<"\n\n";

    string vk("cd root_CA\n openssl genrsa -out "); //removed -des3 to create without pass
    vk.append("Voter");
    vk.append("_private.key 1024\n");

    const char * voter_key = vk.c_str();
    system(voter_key);

    cout << "\n\nGerar csr "<< name <<"\n\n";

    string vc("cd root_CA\n openssl req -new -key ");
    vc.append("Voter");
    vc.append("_private.key -out ");
    vc.append("Voter");
    vc.append("_req.csr\n");

    const char * voter_csr = vc.c_str();
    system(voter_csr);

    cout << "\n\nGerar certificado "<< name <<"\n\n";

    string vcrt("cd root_CA\nopenssl x509 -req -in ");
    vcrt.append("Voter");
	vcrt.append("_req.csr -out ");

    vcrt.append("Voter");
	vcrt.append("_cert.crt -sha1 -CA root_ca.crt -CAkey root_ca.key -CAcreateserial -days 3650\n");

    const char * voter_crt = vcrt.c_str();

    system(voter_crt);

}

void install_in_voter_app(string name)
{
    string dir("mkdir ");
    dir.append(name);
    dir.append("_Files\n chmod 0770 ");
    dir.append(name);
    dir.append("_Files\n mv ");
    dir.append(name);
    dir.append("_Files ../");
    dir.append(name);

    const char * V_dir = dir.c_str();

    system(V_dir);

    // The root CA certificate
    string rca("cd root_CA\ncp root_ca.crt ../../");
    rca.append(name);
    rca.append("/");
    rca.append(name);
    rca.append("_Files\n");

    const char * root_ca = rca.c_str();

    system(root_ca);

    // The election public key
    string epk("cd Homomorphic_keys\ncp SEAL_public.key ../../");
    epk.append(name);
    epk.append("/");
    epk.append(name);
    epk.append("_Files\n");

    const char * election_public_key = epk.c_str();

    system(election_public_key);

    // The voter certificate
    string vct("cd root_CA\n mv ");
    vct.append("Voter");
	vct.append("_cert.crt ../../");
    vct.append(name);
	vct.append("/");
    vct.append(name);
    vct.append("_Files\n");

    const char * voter_ct = vct.c_str();

    system(voter_ct);

	// The voter private key
	string vk("cd root_CA\n mv ");
    vk.append("Voter");
	vk.append("_private.key ../../");
	vk.append(name);
	vk.append("/");
    vk.append(name);
    vk.append("_Files\n");

	const char* voter_k = vk.c_str();

	system(voter_k);
}

void shamir_secret_sharing()
{

    //put secret key in the folder
    system("cd Homomorphic_keys\n cp SEAL_secretkey.key ~/.cargo/bin \n");

    //Make 3 shares with recombination threshold 3 and in the end remove it
    system("cd ~/.cargo/bin \n cat SEAL_secretkey.key | ./secret-share-split -n 3 -t 3 > splitted.txt\n cp splitted.txt /home/mariana/Desktop/Project/Administrator\n rm SEAL_secretkey.key\n");

    //split in files
    string line;
    std::ifstream myfile("splitted.txt");
    std::ofstream out1("trustee1.txt");
    std::ofstream out2("trustee2.txt");
    std::ofstream out3("trustee3.txt");
    if (myfile)
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
    system("mv trustee1.txt ../Counter \n");
    system("mv trustee2.txt ../Counter \n");
    system("mv trustee3.txt ../Counter \n");
    system("rm splitted.txt \n");
    //remove private key
    system("cd Homomorphic_keys\n rm SEAL_secretkey.key \n");

}

void assigns_voters_weights(string N)
{
	//put secret key in the folder

	//split in files
	string line;
	std::ofstream weight1("root_CA/weight_1.txt");
    std::ofstream weight2("root_CA/weight_2.txt");
    std::ofstream weight3("root_CA/weight_3.txt");
    std::ofstream candi("root_CA/n_candidates.txt");
    std::ofstream result("root_CA/result.txt");


    //Parametros do Encryptor
	EncryptionParameters parms(scheme_type::BFV);
	size_t poly_modulus_degree = 8192;
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
	auto context = SEALContext::Create(parms);

	//Load das Keys
	ifstream stream_public_Key;
	ifstream stream_private_Key;

	PublicKey public_key;
	SecretKey secret_key;

	stream_public_Key.open("Homomorphic_keys/SEAL_public.key", ios::binary);
	stream_private_Key.open("Homomorphic_keys/SEAL_secretkey.key",  ios::binary);

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
    vector<uint64_t> pod_matrix5(slot_count, 0ULL);

    Plaintext plain_matrix1, plain_matrix2, plain_matrix3, plain_matrix4, plain_matrix5;

    for (int i = 0; i < slot_count; i++) {
		pod_matrix1[i] = 5;
        pod_matrix2[i] = 3;
        pod_matrix3[i] = 2;
        pod_matrix4[i] = stoi(N);
    }


	batch_encoder.encode(pod_matrix1, plain_matrix1);
    batch_encoder.encode(pod_matrix2, plain_matrix2);
    batch_encoder.encode(pod_matrix3, plain_matrix3);
    batch_encoder.encode(pod_matrix4, plain_matrix4);
    batch_encoder.encode(pod_matrix5, plain_matrix5);

	//Next we encrypt the encoded plaintext.

	Ciphertext encrypted_1;
    Ciphertext encrypted_2;
    Ciphertext encrypted_3;
    Ciphertext encrypted_4;
    Ciphertext encrypted_5;

	encryptor.encrypt(plain_matrix1, encrypted_1);
    encryptor.encrypt(plain_matrix2, encrypted_2);
	encryptor.encrypt(plain_matrix3, encrypted_3);
    encryptor.encrypt(plain_matrix4, encrypted_4);
    encryptor.encrypt(plain_matrix5, encrypted_5);

	encrypted_1.save(weight1);
    encrypted_2.save(weight2);
    encrypted_3.save(weight3);
    encrypted_4.save(candi);
    encrypted_5.save(result);

    weight1.close();
    weight2.close();
    weight3.close();
    candi.close();
    result.close();

	//sign votes weights & number of candidates
    system("openssl dgst --sha256 -sign root_CA/root_ca.key -out root_CA/w1.sha256 root_CA/weight_1.txt\n");
    system("openssl dgst --sha256 -sign root_CA/root_ca.key -out root_CA/w2.sha256 root_CA/weight_2.txt\n");
    system("openssl dgst --sha256 -sign root_CA/root_ca.key -out root_CA/w3.sha256 root_CA/weight_3.txt\n");
    system("openssl dgst --sha256 -sign root_CA/root_ca.key -out root_CA/n_candidates.sha256 root_CA/n_candidates.txt\n");
    system("openssl dgst --sha256 -sign root_CA/root_ca.key -out root_CA/result.sha256 root_CA/result.txt\n");
    //copy files to voters folder
    system("cp root_CA/weight_1.txt root_CA/weight_2.txt root_CA/weight_3.txt root_CA/n_candidates.txt root_CA/result.txt ../TallyOfficial/TallyFiles \n");
    system("cp root_CA/w1.sha256 root_CA/w2.sha256 root_CA/w3.sha256 root_CA/n_candidates.sha256 root_CA/result.sha256 ../TallyOfficial/TallyFiles\n");
}


void generates_election_keys()
{
    system("mkdir Homomorphic_keys\n chmod 0770 Homomorphic_keys\n");

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
    stream_public_Key.open("Homomorphic_keys/SEAL_public.key");
    stream_private_key.open("Homomorphic_keys/SEAL_secretkey.key");
    stream_galois_keys.open("Homomorphic_keys/galois.key");

    KeyGenerator keygen(context1);
    PublicKey public_key = keygen.public_key();
    SecretKey secret_key = keygen.secret_key();
    GaloisKeys gal_keys = keygen.galois_keys();

    public_key.save(stream_public_Key );
    secret_key.save(stream_private_key);
    gal_keys.save(stream_galois_keys);

}

std :: string number_candi()
{
    string N;
    cout << "Quantos candidatos existem na eleição?\n";
    cin >> N;
    while(stoi(N) < 1)
    {
        cout << "Por favor, insira um número válido...\n";
        cin >> N;
    }

    ofstream N_file("nmr_candi.txt");
    N_file << N;
    N_file.close();

    system("openssl dgst --sha256 -sign root_CA/root_ca.key -out nmr_c.sha256 nmr_candi.txt\n");
    system("mv nmr_candi.txt nmr_c.sha256 ../TallyOfficial/TallyFiles\n");

    return N;

}

int main()
{
    string N;
    //Generate the election key - a special homomorphic key pair (e.g. using Microsoft SEAL library, see below)
    generates_election_keys();

    //Generate a root CA certificate and private key;
    generate_root_CA();

    //Define number of candidates
    N = number_candi();

    //Generate a certificate for every voter
    // Install on each voter app:
    generate_Voter_C("Voter1");
    install_in_voter_app("Voter1");
    generate_Voter_C("Voter2");
    install_in_voter_app("Voter2");
    generate_Voter_C("Voter3");
    install_in_voter_app("Voter3");

    // Assigns a weight to each voter, encrypts it with the election public key and publishes the list of encrypted weights.
	assigns_voters_weights(N);

    // Split the election private key using Shamir’s secret sharing, distribute each of the shares by the trustees, and erase the private key.
    shamir_secret_sharing();
}