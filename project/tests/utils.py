import json
import string
import random

def random_identifier_suffix_4():
    length = 4
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def login_response_to_authorization_header(response):
    """ given a response from login or register, return a dictionary containing a header for Authorization """
    return dict(
                    Authorization='Bearer ' + json.loads(
                        response.data.decode()
                    )['auth_token']
                )
