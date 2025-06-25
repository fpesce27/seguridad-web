import hashlib
from typing import Callable, Generator
import json
def md5_hexdigest(input: str) -> str:
    return hashlib.md5(input.encode()).hexdigest()

def generate_combinations(max_length: int, allowed_chars: str) -> Generator[str, None, None]:
    """
    Generate all possible combinations of characters from allowed_chars up to max_length.
    
    Args:
        max_length: Maximum length of combinations to generate
        allowed_chars: String containing all allowed characters
    
    Yields:
        Each combination as a string
    """
    
    # Generate combinations of each length from 1 to max_length
    for length in range(1, max_length + 1):
        # Use a stack to track current combination being built
        stack = [("", length)]
        
        while stack:
            current, remaining = stack.pop()
            
            if remaining == 0:
                yield current
            else:
                # Add all possible next characters to the stack
                for char in allowed_chars:
                    stack.append((current + char, remaining - 1))
                    

def txt_to_generator(file_path: str) -> Generator[str, None, None]:
    """
    Read a text file and yield each line as a string.
    
    Args:
        file_path: Path to the text file
        
    Yields:
        Each line in the file as a string
    """
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            yield line.strip()                    

def crack_salt_brute_force(hash: str, 
                           password: str, 
                           hash_function: Callable[[str], str], 
                           possible_values_generator: Generator[str, None, None],
                           salt_before: bool = False) -> str | None:
    
    """
    Given a hash and the password that generated it, 
    this function will try to return the salt used in the hash.
    """
    
    attempts = 0
    
    possible_value = next(possible_values_generator)
    while possible_value:
        # Generate the hash with the current possible value as salt
        if salt_before:
            generated_hash = hash_function(possible_value + password)
        else:
            generated_hash = hash_function(password + possible_value)
        
        if generated_hash == hash:
            return possible_value
        
        attempts += 1
        if attempts % 1000 == 0:
            print(f"Attempts: {attempts}, Current salt: {possible_value}")
        
        try:
            possible_value = next(possible_values_generator)
        except StopIteration:
            break


def create_dictionary_attack_with_salt(hash_function: Callable[[str], str],
                                       salt: str,
                                       top_passwords_path: str,
                                       salt_before: bool = False,
                                       max_entries: int = 15_000) -> dict:
    
    """
    Take the n most used passwords from a text file, encode them with the hash and create a dict
    hash(salt + password) : password
    """
    password_dict = {}
    count = 0
    for password in txt_to_generator(top_passwords_path):
        if count >= max_entries:
            break
            
        # Create the salted password based on salt_before parameter
        if salt_before:
            salted_password = salt + password
        else:
            salted_password = password + salt
        
        # Hash the salted password and store in dictionary
        hashed_password = hash_function(salted_password)
        password_dict[hashed_password] = password
        count += 1
    
    return password_dict



if __name__ == "__main__":
    # Example usage
    hash_to_crack = "207acd61a3c1bd506d7e9a4535359f8a"
    password = "123456"
    
    from string import ascii_lowercase
    
    # Generate possible salts
    random_combinations_generator = generate_combinations(4, ascii_lowercase)
    
    common_word_generator = txt_to_generator("3000_words.txt")
    
    # Attempt to crack the salt
    found_salt = crack_salt_brute_force(hash_to_crack, password, md5_hexdigest, common_word_generator)
    
    if found_salt:
        print(f"Found salt: {found_salt}")
        
        hash_dict = create_dictionary_attack_with_salt(md5_hexdigest, found_salt, "most_used_passwords.txt")
        
        if hash_dict:

            with open("hash_dictionary.json", "w") as f:
                json.dump(hash_dict, f)
                
        
        hash_to_crack = "b305cadbb3bce54f3aa59c64fec00dea"
        
        if hash_to_crack in hash_dict:
            print(f"Password found: {hash_dict[hash_to_crack]}")
        else:
            print("Password not found in dictionary.")
        
        
    else:
        print("Salt not found.")
        
    