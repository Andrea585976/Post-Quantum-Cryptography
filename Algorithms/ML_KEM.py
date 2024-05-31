import oqs
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from timeit import default_timer

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

average_time = {
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

# We repeat each algorithm a hundred times
for _ in range(1000):
    for algorithm in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]:
        times = ML_KEM("hello world", algorithm)
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