import oqs
from pprint import pprint
from timeit import default_timer

message = "This is the message to sign".encode()

SLH_DSA_alg = ['SPHINCS+-SHAKE-128f-simple',
            'SPHINCS+-SHAKE-192f-simple',
            'SPHINCS+-SHAKE-256f-simple',
            'SPHINCS+-SHA2-128f-simple',
            'SPHINCS+-SHA2-192f-simple',
            'SPHINCS+-SHA2-256f-simple',]

def SLH_DSA(message: str, SLH_DSA_alg: str) -> dict:
    """Function that uses the ML-DSA to sign and verify a message"""
    with oqs.Signature(SLH_DSA_alg) as signer:
        with oqs.Signature(SLH_DSA_alg) as verifier:
            #print("\nSignature details:")
            #pprint(signer.details)

            # Dictionary to save timestamps
            SLH_DSA_time = {
                "key_pair_generation": [],
                "sign_message": [],
                "verify_signature": []
                }

            # Signer generates its keypair
            SLH_DSA_time["key_pair_generation"].append(default_timer())
            signer_public_key = signer.generate_keypair()
            # Optionally, the secret key can be obtained by calling export_secret_key()
            # and the signer can later be re-instantiated with the key pair:
            # secret_key = signer.export_secret_key()

            # Store key pair, wait... (session resumption):
            # signer = oqs.Signature(sigalg, secret_key)
            SLH_DSA_time["key_pair_generation"].append(default_timer())

            # Signer signs the message
            SLH_DSA_time["sign_message"].append(default_timer())
            signature = signer.sign(message)
            SLH_DSA_time["sign_message"].append(default_timer())

            # Verifier verifies the signature
            SLH_DSA_time["verify_signature"].append(default_timer())
            is_valid = verifier.verify(message, signature, signer_public_key)
            SLH_DSA_time["verify_signature"].append(default_timer())

            #print("\nValid signature?", is_valid)

            return SLH_DSA_time


average_time = {
    "key_pair_generation_SPHINCS+-SHAKE-128f-simple": [],
    "sign_message_SPHINCS+-SHAKE-128f-simple": [],
    "verify_signature_SPHINCS+-SHAKE-128f-simple": [],
    "total_SPHINCS+-SHAKE-128f-simple": [],

    "key_pair_generation_SPHINCS+-SHAKE-192f-simple": [],
    "sign_message_SPHINCS+-SHAKE-192f-simple": [],
    "verify_signature_SPHINCS+-SHAKE-192f-simple": [],
    "total_SPHINCS+-SHAKE-192f-simple": [],

    "key_pair_generation_SPHINCS+-SHAKE-256f-simple": [],
    "sign_message_SPHINCS+-SHAKE-256f-simple": [],
    "verify_signature_SPHINCS+-SHAKE-256f-simple": [],
    "total_SPHINCS+-SHAKE-256f-simple": [],

    "key_pair_generation_SPHINCS+-SHA2-128f-simple": [],
    "sign_message_SPHINCS+-SHA2-128f-simple": [],
    "verify_signature_SPHINCS+-SHA2-128f-simple": [],
    "total_SPHINCS+-SHA2-128f-simple": [],

    "key_pair_generation_SPHINCS+-SHA2-192f-simple": [],
    "sign_message_SPHINCS+-SHA2-192f-simple": [],
    "verify_signature_SPHINCS+-SHA2-192f-simple": [],
    "total_SPHINCS+-SHA2-192f-simple": [],

    "key_pair_generation_SPHINCS+-SHA2-256f-simple": [],
    "sign_message_SPHINCS+-SHA2-256f-simple": [],
    "verify_signature_SPHINCS+-SHA2-256f-simple": [],
    "total_SPHINCS+-SHA2-256f-simple": [],
    }


# We repeat each algorithm a hundred times
for _ in range(1000):
    #for algorithm in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
    for algorithm in SLH_DSA_alg:
        times = SLH_DSA(message, algorithm)
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