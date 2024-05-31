import oqs
from pprint import pprint
from timeit import default_timer

message = "This is the message to sign".encode()

ML_DSA_alg = ['ML-DSA-44',
              'ML-DSA-65',
              'ML-DSA-87']

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


average_time = {
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


# We repeat each algorithm a hundred times
for _ in range(1000):
    #for algorithm in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
    for algorithm in ML_DSA_alg:
        times = ML_DSA(message, algorithm)
        total_time = 0
        for key, value in times.items():
            total_time += value[1] - value[0]
            average_time[key+"_"+algorithm].append(value[1] - value[0])
        average_time["total_"+algorithm].append(total_time)


# We show the final results
for key, value in average_time.items():
    if "key_pair_generation" in key: print(f"\t ### {key[20:]} ###")
    print(f"{key}")
    print(sum(value))