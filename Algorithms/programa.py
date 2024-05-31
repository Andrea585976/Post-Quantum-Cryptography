''' 
2nd.Project: Post-Quantum Cryptography Project
Group: 02

 **Students:**
* Aguilar Corona Fernanda
* Andres Urbano Andrea
* Barrios López Francisco
* Castillo Montes Pamela
* Ramírez Gómez María Emilia
'''


## IMPORT LIBRARIES

import oqs
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from timeit import default_timer
from pprint import pprint
import os, binascii
from pyspx import shake_128f,shake_192f,shake_256f
from pyspx import sha2_128f,sha2_192f,sha2_256f
import importlib

#-----------------ML-KEM------------------
def ML_KEM(plain_text: str, ML_KEM_alg: str) -> dict:
    """Function that uses the ML-KEM scheme and encrypt and decrypt a message"""
    with oqs.KeyEncapsulation(ML_KEM_alg) as client:
        with oqs.KeyEncapsulation(ML_KEM_alg) as server:
            # Dictionary to save timestamps
            ML_KEM_time = {
                "key_pair_generation": [],
                "encap_secret": [],
                "decap_secret": []
                }

            ML_KEM_time["key_pair_generation"].append(default_timer())
            # Client generates its keypair, in this case, he only gets his public key
            # but he can get his provate key using export_secret_key()
            public_key_client = client.generate_keypair()
            ML_KEM_time["key_pair_generation"].append(default_timer())

            ML_KEM_time["encap_secret"].append(default_timer())
            # The server encapsulates its secret using the client's public key
            ciphertext, shared_secret_server = server.encap_secret(public_key_client)
            ML_KEM_time["encap_secret"].append(default_timer())

            ML_KEM_time["decap_secret"].append(default_timer())
            # The client decapsulates the server's ciphertext to obtain the shared secret
            shared_secret_client = client.decap_secret(ciphertext)
            ML_KEM_time["decap_secret"].append(default_timer())

            # We compare in both shared secret keys are equal
            if shared_secret_client == shared_secret_server:
                msg=plain_text.encode('utf-8')
                msgPad=pad(msg, 256)

                #Cifrado Simétrico con la llave generada
                AES_ECBcypher=AES.new(shared_secret_client, AES.MODE_ECB)

                ciphertext_ld = AES_ECBcypher.encrypt(msgPad)
                descifrado_aes_ld = AES_ECBcypher.decrypt(ciphertext_ld)

            return ML_KEM_time

#--------------------- ML-DSA Scheme--------------------



def ML_DSA(message: str, ML_DSA_alg: str) -> dict:
    """Function that uses the ML-DSA to sign and verify a message"""
    with oqs.Signature(ML_DSA_alg) as signer:
        with oqs.Signature(ML_DSA_alg) as verifier:
            # Dictionary to save timestamps
            ML_DSA_time = {
                "key_pair_generation": [],
                "sign_message": [],
                "verify_signature": []
                }

            # Signer generates its keypair
            ML_DSA_time["key_pair_generation"].append(default_timer())
            signer_public_key = signer.generate_keypair()
            # Optionally, the secret key can be obtained by calling export_secret_key()
            # and the signer can later be re-instantiated with the key pair:
            # secret_key = signer.export_secret_key()

            # Store key pair, wait... (session resumption):
            # signer = oqs.Signature(sigalg, secret_key)
            ML_DSA_time["key_pair_generation"].append(default_timer())

            # Signer signs the message
            ML_DSA_time["sign_message"].append(default_timer())
            signature = signer.sign(message)
            ML_DSA_time["sign_message"].append(default_timer())

            # Verifier verifies the signature
            ML_DSA_time["verify_signature"].append(default_timer())
            is_valid = verifier.verify(message, signature, signer_public_key)
            ML_DSA_time["verify_signature"].append(default_timer())

            #print("\nValid signature?", is_valid)

            return ML_DSA_time


# -----------------------------SLH-DSA Scheme--------------------


 
def slh_shake_128_Fast():
  # Key generation: private + public key
  seed = os.urandom(shake_128f.crypto_sign_SEEDBYTES)
  public_key, secret_key = shake_128f.generate_keypair(seed)

  # Sign message and verify signature
  message = b'Message for SPHINCS+ shake256_128f signing'
  signature = shake_128f.sign(message, secret_key)
  valid = shake_128f.verify(message, signature, public_key)




def SLH_DSA(message, SLH_DSA_alg):
  """Function that uses the SLH_DSA scheme to generate a pair of keys,
  sign a message and verify the signature"""
  # Dictionary to save timestamps
  SLH_DSA_time = {
    "key_pair_generation": [],
    "sign_message": [],
    "verify_signature": []
  }

  # Key generation: private + public key
  SLH_DSA_time["key_pair_generation"].append(default_timer())
  seed = os.urandom(SLH_DSA_alg.crypto_sign_SEEDBYTES)
  public_key, secret_key = SLH_DSA_alg.generate_keypair(seed)
  SLH_DSA_time["key_pair_generation"].append(default_timer())

  # Sign message
  SLH_DSA_time["sign_message"].append(default_timer())
  signature = SLH_DSA_alg.sign(message, secret_key)
  SLH_DSA_time["sign_message"].append(default_timer())

  # Verify signature
  SLH_DSA_time["verify_signature"].append(default_timer())
  valid = SLH_DSA_alg.verify(message, signature, public_key)
  SLH_DSA_time["verify_signature"].append(default_timer())

  return SLH_DSA_time



def main():
    option = 0

    #--------------------ML-KEM DICTIONARY FOR EVALUATION-----------------
    average_time_mlkem = {
        "key_pair_generation_ML-KEM-512": [],
        "encap_secret_ML-KEM-512": [],
        "decap_secret_ML-KEM-512": [],
        "total_ML-KEM-512": [],
        "key_pair_generation_ML-KEM-768": [],
        "encap_secret_ML-KEM-768": [],
        "decap_secret_ML-KEM-768": [],
        "total_ML-KEM-768": [],
        "key_pair_generation_ML-KEM-1024": [],
        "encap_secret_ML-KEM-1024": [],
        "decap_secret_ML-KEM-1024": [],
        "total_ML-KEM-1024": [],
        }
    #-----------------------ML-DSA DICTIONARY FOR EVALUATION, MESSAGE AND SCHEMES----------------------
    message = "This is the message to sign".encode()

    ML_DSA_alg = ['ML-DSA-44',
                'ML-DSA-65',
                'ML-DSA-87']
    
    average_time_mldsa = {
    "key_pair_generation_ML-DSA-44": [],
    "sign_message_ML-DSA-44": [],
    "verify_signature_ML-DSA-44": [],
    "total_ML-DSA-44": [],

    "key_pair_generation_ML-DSA-65": [],
    "sign_message_ML-DSA-65": [],
    "verify_signature_ML-DSA-65": [],
    "total_ML-DSA-65": [],

    "key_pair_generation_ML-DSA-87": [],
    "sign_message_ML-DSA-87": [],
    "verify_signature_ML-DSA-87": [],
    "total_ML-DSA-87": [],
    }


    #--------------------SLH-DSA DICTIONARY FOR EVALUATION-----------------

    paramsets = [
        'shake_128f',
        'shake_192f',
        'shake_256f',
        'sha2_128f',
        'sha2_192f',
        'sha2_256f',
    ]

    instances = []

    for paramset in paramsets:
        instances.append(importlib.import_module('pyspx.' + paramset))

    average_time = {
        "key_pair_generation_shake_128f": [],
        "sign_message_shake_128f": [],
        "verify_signature_shake_128f": [],
        "total_shake_128f": [],
        "key_pair_generation_shake_192f": [],
        "sign_message_shake_192f": [],
        "verify_signature_shake_192f": [],
        "total_shake_192f": [],
        "key_pair_generation_shake_256f": [],
        "sign_message_shake_256f": [],
        "verify_signature_shake_256f": [],
        "total_shake_256f": [],

        "key_pair_generation_sha2_128f": [],
        "sign_message_sha2_128f": [],
        "verify_signature_sha2_128f": [],
        "total_sha2_128f": [],
        "key_pair_generation_sha2_192f": [],
        "sign_message_sha2_192f": [],
        "verify_signature_sha2_192f": [],
        "total_sha2_192f": [],
        "key_pair_generation_sha2_256f": [],
        "sign_message_sha2_256f": [],
        "verify_signature_sha2_256f": [],
        "total_sha2_256f": [],
        }

    #-----------MENU---------------------------
    while(option!=4):
        option = int(input("Ingrese la opcion del algoritmo que desea ejecutar:\n1. ML-KEM\n2.ML-DSA\n3.SLH-DSA\n4.Terminar programa\n"))
        #--------ML-KEM-----------
        if option == 1:
            # We repeat each algorithm a hundred times to evaluate it
            for _ in range(1000):
                for algorithm in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
                    times = ML_KEM("hello world", algorithm)
                    total_time = 0
                    for key, value in times.items():
                        total_time += value[1] - value[0]
                        average_time_mlkem[key+"_"+algorithm].append(value[1] - value[0])
                    average_time_mlkem["total_"+algorithm].append(total_time)

            # We show the final results of ML-KEM
            for key, value in average_time_mlkem.items():
                if "key_pair_generation" in key: print(f"\t ### {key[20:]} ###")
                print(f"{key}")
                print(sum(value))


        #--------ML-DSA-----------
        elif option == 2:
            # We repeat each algorithm a hundred times
            for _ in range(1000):
                for algorithm in ML_DSA_alg:
                    times = ML_DSA(message, algorithm)
                    total_time = 0
                    for key, value in times.items():
                        total_time += value[1] - value[0]
                        average_time_mldsa[key+"_"+algorithm].append(value[1] - value[0])
                    average_time_mldsa["total_"+algorithm].append(total_time)


            # We show the final results
            for key, value in average_time_mldsa.items():
                if "key_pair_generation" in key: print(f"\t ### {key[20:]} ###")
                print(f"{key}")
                print(sum(value))

         #--------SLH-DSA-----------
        elif option == 3:
              '''          
            # We repeat each algorithm a hundred times
            message = b'Message for SPHINCS+ signing'
            for _ in range(1000):
                apunt_algorithm = 0
                for algorithm in instances:
                    times = SLH_DSA(message, algorithm)
                    total_time = 0
                    for key, value in times.items():
                        total_time += value[1] - value[0]
                        average_time[key+"_"+paramsets[apunt_algorithm]].append(value[1] - value[0])
                    average_time["total_"+paramsets[apunt_algorithm]].append(total_time)

                    if (apunt_algorithm == 5):
                        apunt_algorithm = 0
                    else:
                        apunt_algorithm += 1


            # We show the final results
            for key, value in average_time.items():
                if "key_pair_generation" in key: print(f"\t ### {key[20:]} ###")
                print(f"{key}")
                print(sum(value))
            '''
            #break


        elif option == 4:
            break

        else:
            print("Por favor ingrese una opcion correcta")



# Execution
main()
            

        

    

