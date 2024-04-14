import pwgen
import secrets

def generate1(length):
    random_string = pwgen.pwgen(length, capitalize=True, no_symbols=True)
    return random_string

random_string = generate1(10)
print("pwgen_gen: ",random_string)

def generate2(length):
    random_string = secrets.token_urlsafe(length)[:length]
    return random_string

random_string = generate2(10)
print("token_urlsafe_gen: ",random_string)
