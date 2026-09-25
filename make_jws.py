import json
import base64
from cryptography.hazmat.primitives import serialization

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

with open("public.pem", "rb") as f:
    key = serialization.load_pem_public_key(f.read())

numbers = key.public_numbers()

n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")

jwks = {
    "keys": [
        {
            "kty": "RSA",
            "n": b64url(n),
            "e": b64url(e),
            "alg": "RS256",
            "use": "sig",
            "kid": "ctf-key"
        }
    ]
}

with open("jwks.json", "w") as f:
    json.dump(jwks, f, indent=2)

print(json.dumps(jwks, indent=2))