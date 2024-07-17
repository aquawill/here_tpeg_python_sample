import gzip
import time
import xml.etree.cElementTree as xml

import requests
from Crypto import Random
from Crypto.Cipher import AES as aes

# app_id = ''
# app_code = ''
api_key = ''

try:
    app_id
except NameError:
    app_id = ''
try:
    app_code
except NameError:
    app_code = ''
try:
    api_key
except NameError:
    api_key = ''

sample_init_body = open('initsession.xml', 'r').read().replace('\t', '').replace('\n', '')
print('sample_init_body:', sample_init_body)

sample_getmessage_body = open('getmessages.xml', 'r').read().replace('\t', '').replace('\n', '')
print('sample_getmessage_body:', sample_getmessage_body)


def compress_body(input):
    """
    Compresses the input XML string using gzip and prepends the size of the gzipped body.

    Args:
        input (str): The XML string to compress.

    Returns:
        bytes: The gzipped and padded payload.
    """
    # Check if the input string is XML string.
    if isinstance(xml.fromstring(input), xml.Element):
        # Compress the XML string using gzip
        x = gzip.compress(bytes(input, 'utf-8'))

        # Prepend size of gzipped body. The size should be encoded to bytes type with "little" endian.
        payload = len(x).to_bytes(4, 'little') + x

        return pad(payload)


def gen_random_iv():
    """
    Generates a random initialization vector (IV) for encryption.

    Returns:
        bytes: A random 16-byte IV.
    """
    return Random.get_random_bytes(16)


def encrypt(key, body, iv):
    """
    Encrypts the input 'body' using AES encryption with the provided 'key' and 'iv'.

    Args:
        key (str): The encryption key in hexadecimal format.
        body (bytes): The data to be encrypted.
        iv (bytes): The initialization vector for encryption.

    Returns:
        bytes: The encrypted data.
    """
    key_hex = bytes.fromhex(
        key)  # Convert the hexadecimal key string into bytes.
    cipher = aes.new(key_hex, aes.MODE_CBC, iv=iv)
    encrypted_data = iv + cipher.encrypt(body)
    return encrypted_data


def decrypt(body, key):
    """
    Decrypts the input 'body' using AES decryption with the provided 'key'.

    Args:
        body (bytes): The data to be decrypted.
        key (str): The decryption key in hexadecimal format.

    Returns:
        bytes: The decrypted data.
    """
    # Extract the initialization vector (IV) from the 'body'
    iv = bytes(body)[:aes.block_size]  # The 'Session Key' described in dev guide is actually an IV.

    # Convert the hexadecimal 'key' into bytes
    key_hex = bytes.fromhex(
        key)  # The 'key' value is a string type that holds hexadecimal values. Translate them into bytes type.

    # Create a new AES cipher using the key and IV
    cipher = aes.new(key_hex, aes.MODE_CBC, IV=iv)

    # Extract the encrypted part of the body
    remainder = bytes(body)[aes.block_size:]

    # Decrypt the body
    decrypt_body = unpad(cipher.decrypt(remainder))

    # Extract the size of the decrypted body
    size = int.from_bytes(decrypt_body[:4], 'little')

    # Extract the gzipped body from the decrypted body
    gzipped_body = decrypt_body[4:]

    # Check if the size of the gzipped body matches the expected size
    if len(gzipped_body) != size:
        print("Error. Packet is not fully downloaded")

    # Decompress the gzipped body and return the result
    return gzip.decompress(gzipped_body)


def decrypt_body_test(body: bytes, iv: bytes, key: bytes) -> bytes:
    """
    Decrypts the body using AES in CBC mode with the provided initialization vector (IV) and key.

    Args:
        body (bytes): The encrypted data.
        iv (bytes): The initialization vector.
        key (bytes): The decryption key.

    Returns:
        bytes: The decrypted data.
    """
    # Create a new AES cipher using the key and IV
    cipher = aes.new(key, aes.MODE_CBC, iv)

    # Decrypt the body
    decrypted_body = cipher.decrypt(body)

    return decrypted_body


pad = lambda s: s + (aes.block_size - (len(s) % aes.block_size)) * b'\x00'  # HERE TPEG API uses zero padding.


# Use 'size' data in the packet for check the actual gzipped payload size. The Unpad (zeros) from the decrypted code.
def unpad(s: bytes) -> bytes:
    """
    Unpads the input data 's' according to the zero padding scheme.

    Args:
        s (bytes): The data to be unpadded.

    Returns:
        bytes: The unpadded data.
    """
    # Extract the size of the padded data
    size = int.from_bytes(s[:4], 'little')

    # Retrieve the actual data part after the size
    data = s[4:]

    # Check if the data size is less than or equal to the expected size
    if len(data) - size <= 0:
        return s
    # Check for extra data after the expected size and zero padding
    elif len(data) - size > 0 and data[size:].startswith(b'\x00'):
        return s[:size + 4]
    else:
        return s


def init_request(xml_body):
    """
    Initializes a request to the specified URL with the given XML body.

    Args:
        xml_body (str): The XML body to send in the request.

    Returns:
        bytes: The content of the response.

    Raises:
        requests.RequestException: If an error occurs during the request.
    """
    # Construct the URL
    url = 'https://tpeg.traffic.cc.api.here.com/tpeg/1.0/initsession?{}'

    # Determine the credential based on app_id existence
    if len(app_id) > 0:
        credential = 'app_id={}&app_code={}'.format(app_id, app_code)
    else:
        credential = 'apiKey={}'.format(api_key)

    # Format the URL with credential
    url = url.format(credential)
    print('initsession', url)

    try:
        # Make the POST request with XML body
        response = requests.post(url=url, data=xml_body, headers={"Content-Type": "application/xml"})
        print(response.content.decode())

        # Check the status code and return content
        if response.status_code != 200:
            return None
        return response.content
    except requests.RequestException as re:
        print('{} Exception'.format(type(re)))
        print(re.response)
        return None



def get_msg_request(url: str, key: str, body: bytes) -> bytes:
    """
    Sends a POST request to the specified URL with the given body and returns the decrypted response.

    Args:
        url (str): The URL to send the request to.
        key (str): The encryption key used to decrypt the response.
        body (bytes): The data to send in the request.

    Returns:
        bytes: The decrypted response from the server.

    Raises:
        requests.RequestException: If an error occurs during the request.
    """
    try:
        # Generate a random initialization vector (IV)
        iv = gen_random_iv()

        # Encrypt the body using the provided key and IV
        enc_body = encrypt(key, compress_body(body), iv)

        # Send the POST request to the specified URL with the encrypted body
        response = requests.post(url=url, data=enc_body, headers={'Content-Type': 'application/octet-stream'})

        # Print the reason for the response
        print('response: ', response.reason)

        # Check if the response was successful (status code 200)
        if response.status_code != 200:
            # Print the response text if it was not successful
            print(response.text)
            return None

        # Decrypt the response content using the provided key
        dec_resp = decrypt(response.content, key)

        # Generate a file name for the decrypted response
        dump_file_name = 'message_dump_{}.tpeg'.format(time.strftime("%a_%d_%b_%Y_%H_%M_%S", time.gmtime(time.time())))

        # Write the decrypted response to a file
        with open(dump_file_name, mode='wb') as file:
            file.write(dec_resp)

        return dec_resp
    except requests.RequestException as re:
        # Print the type of exception and the response if an exception occurs
        print('{} Exception'.format(type(re)))
        print(re.response)
        return None


def crypto(key: str, body: bytes) -> bytes:
    """
    Encrypts and decrypts the input 'body' using AES encryption with the provided 'key'.

    Args:
        key (str): The encryption key in hexadecimal format.
        body (bytes): The data to be encrypted and decrypted.

    Returns:
        bytes: The decrypted data.
    """
    # Generate a random initialization vector (IV)
    iv = gen_random_iv()

    # Encrypt the body using the provided key and IV
    enc_body = encrypt(key, compress_body(body), iv)

    # Decrypt the body using the concatenated key and encrypted body
    dec_body = decrypt(key.encode() + enc_body, iv)

    # Print the decrypted body
    print(dec_body)

    return dec_body


def main():
    """
    Executes the main logic of the program.

    Steps:
    1. Initialize a request using the sample init body.
    2. Parse the XML response.
    3. Extract the URL and key from the response.
    4. Send a message request using the URL and key.
    """
    # Step 1: Initialize a request using the sample init body
    init_resp = init_request(sample_init_body)

    # Step 2: Parse the XML response
    if not init_resp:
        return
    init_resp_xml = xml.fromstring(init_resp)

    # Step 3: Extract the URL and key from the response
    req_url = init_resp_xml.get('url')
    key = init_resp_xml.get('key')  # Key, key never changes in the session.

    # Step 4: Send a message request using the URL and key
    get_msg_response = get_msg_request(req_url, key, sample_getmessage_body)
    # crypto(key, get_msg_response)


if __name__ == '__main__':
    main()
