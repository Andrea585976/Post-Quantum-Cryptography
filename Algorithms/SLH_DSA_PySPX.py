from pyspx import shake_128f,shake_192f,shake_256f
from pyspx import sha2_128f,sha2_192f,sha2_256f
from timeit import default_timer
import os
import importlib

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