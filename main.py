import gzip
import time
import xml.etree.cElementTree as xml

import requests
from Crypto import Random
from Crypto.Cipher import AES as aes

api_key = ''
app_id = ''
app_code = ''

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
    # Check if the input string is XML string.
    if isinstance(xml.fromstring(input), xml.Element):
        x = gzip.compress(bytes(input, 'utf-8'))  # compress XML by gzip returned in bytes
        payload = len(x).to_bytes(4,
                                  'little') + x  # Prepend size of gzipped body. The size should be encoded to bytes type with "little" endian.
        return pad(payload)


def gen_random_iv():
    return Random.get_random_bytes(16)


def encrypt(key, body, iv):
    key_hex = bytes.fromhex(
        key)  # The 'key' value is string type which holds hexadecimal values. Translate them into bytes type.
    cipher = aes.new(key_hex, aes.MODE_CBC, iv=iv)
    returning = iv + cipher.encrypt(body)
    return returning


def decrypt(body, key):
    iv = bytes(body)[:aes.block_size]  # The 'Session Key' described in dev guide is actually an IV.
    key_hex = bytes.fromhex(
        key)  # The 'key' value is string type which holds hexadecimal values. Translate them into bytes type.
    cipher = aes.new(key_hex, aes.MODE_CBC, IV=iv)
    remainder = bytes(body)[aes.block_size:]
    decrypt_body = unpad(cipher.decrypt(remainder))
    size = int.from_bytes(decrypt_body[:4], 'little')
    # print(size)
    gzipped_body = decrypt_body[4:]
    # print(len(gzipped_body))
    if len(gzipped_body) != size:
        print("Error. Packet is not fully downloaded")
    return gzip.decompress(gzipped_body)


def decrypt_body_test(body, iv, key):
    cipher = aes.new(key, aes.MODE_CBC, iv)
    dec = cipher.decrypt(body)
    return dec


pad = lambda s: s + (aes.block_size - (len(s) % aes.block_size)) * b'\x00'  # HERE TPEG API uses zero padding.


# Use 'size' data in the packet for check the actual gzipped payload size. The Unpad (zeros) from the decrypted code.
def unpad(s):
    size = int.from_bytes(s[:4], 'little')
    # print(size)
    b = s[4:]
    if len(b) - size <= 0:
        return s
    elif len(b) - size > 0 and b[size:].startswith(b'\x00'):
        return s[:size + 4]
    else:
        return s


def init_request(xml_body):
    url = 'https://tpeg.traffic.cc.api.here.com/tpeg/1.0/initsession?{}'

    if len(app_id) > 0:
        credential = 'app_id={}&app_code={}'.format(app_id, app_code)
    else:
        credential = 'apiKey={}'.format(api_key)
    url = url.format(credential)
    print('initsession', url)
    try:
        response = requests.post(url=url, data=xml_body, headers={"Content-Type": "application/xml"})
        if response.status_code != 200:
            print(response.content.decode())
            return None
        return response.content
    except requests.RequestException as re:
        print('{} Exception'.format(type(re)))
        print(re.response)
        return None


def get_msg_request(url, key, body):
    try:
        iv = gen_random_iv()
        enc_body = encrypt(key, compress_body(body), iv)
        response = requests.post(url=url, data=enc_body, headers={'Content-Type': 'application/octet-stream'})
        print('response: ', response.reason)
        if response.status_code != 200:
            print(response.text)
            return None
        dec_resp = decrypt(response.content, key)
        dump_file_name = 'message_dump_{}.tpeg'.format(time.strftime("%a_%d_%b_%Y_%H_%M_%S", time.gmtime(time.time())))
        open(dump_file_name, mode='wb').write(dec_resp)
        return dec_resp
    except requests.RequestException as re:
        print('{} Exception'.format(type(re)))
        print(re.response)
        return None


def crypto(key, body):
    iv = gen_random_iv()
    enc_body = encrypt(key, compress_body(body), iv)
    dec_body = decrypt(key.encode() + enc_body, iv)
    print(dec_body)


def main():
    init_resp = init_request(sample_init_body)
    if not init_resp:
        return
    init_resp_xml = xml.fromstring(init_resp)
    req_url = init_resp_xml.get('url')
    key = init_resp_xml.get('key')  # Key, key never changes in the session.
    get_msg_response = get_msg_request(req_url, key, sample_getmessage_body)
    # crypto(key, get_msg_response)


if __name__ == '__main__':
    main()
