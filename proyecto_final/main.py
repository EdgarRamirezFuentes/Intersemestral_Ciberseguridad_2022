'''
    Name: main.py
    Author: Edgar Ramírez
    Date: 01/28/2022
    Description: Basic GUI used to encrypt/decrypt files using the cryptographic algorithms RSA, AES, and DES 
'''
# The code for changing pages was derived from: http://stackoverflow.com/questions/7546050/switch-between-two-frames-in-tkinter
# License: http://creativecommons.org/licenses/by-sa/3.0/	

import tkinter as tk
from tkinter import filedialog
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import os
import re


LARGE_FONT= ("Verdana", 12)        
FILE_PATH = ''
PUBLIC_KEY_PATH = ''
PRIVATE_KEY_PATH = ''
LOCATION_PATH = ''


class SeaofBTCapp(tk.Tk):

    def __init__(self, *args, **kwargs):
        
        tk.Tk.__init__(self, *args, **kwargs)
        container = tk.Frame(self)

        container.pack(side="top", fill="both", expand = True)

        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}

        for F in (StartPage, AesMenu, AesEncryption, AesDecryption, DesMenu, DesEncryption, DesDecryption, RsaMenu, RsaEncryption, RsaDecryption):

            frame = F(container, self)

            self.frames[F] = frame

            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(StartPage)

    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()


class StartPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self,parent)
        
        title_lbl = tk.Label(self, text="Cybersecurity Project", font=LARGE_FONT)
        title_lbl.pack(pady=10,padx=10)
        
        author_lbl = tk.Label(self, text="Edgar Alejandro Ramirez Fuentes", font=LARGE_FONT)
        author_lbl.pack(pady=10,padx=10)
        
        options_lbl = tk.Label(self, text="Cryptographic algorithms", font=LARGE_FONT)
        options_lbl.pack(pady=10,padx=10)

        aes_btn = tk.Button(self, text="AES",
                            command=lambda: controller.show_frame(AesMenu))
        aes_btn.pack(pady=10,padx=10)

        des_btn = tk.Button(self, text="DES",
                            command=lambda: controller.show_frame(DesMenu))
        des_btn.pack(pady=10,padx=10)

        rsa_btn = tk.Button(self, text="RSA",
                            command=lambda: controller.show_frame(RsaMenu))
        rsa_btn.pack(pady=10,padx=10)


class AesMenu(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        title_lbl = tk.Label(self, text="AES Menu", font=LARGE_FONT)
        encryption_btn = tk.Button(self, text="Encryption",
                            command=lambda: controller.show_frame(AesEncryption))
        decryption_btn = tk.Button(self, text="Decryption",
                            command=lambda: controller.show_frame(AesDecryption))
        back_btn = tk.Button(self, text="Back to Home",
                            command=lambda: controller.show_frame(StartPage))
        title_lbl.pack(pady=10,padx=10)
        encryption_btn.pack(pady=10,padx=10)
        decryption_btn.pack(pady=10,padx=10)
        back_btn.pack(pady=10,padx=10)

class AesEncryption(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        global MESSAGE
        title_lbl = tk.Label(self, text="AES Encryption", font=LARGE_FONT)
        file_lbl = tk.Label(self, text="Select the file", font=LARGE_FONT)
        file_btn = tk.Button(self, text = "Browse Files", 
                            command=self.__get_file)
        location_lbl = tk.Label(self, text=f"Select the folder to store the files", font=LARGE_FONT)
        location_btn = tk.Button(self, text="Browse directories",
                            command=self.__get_location)
        encrypt_btn = tk.Button(self, text="Encrypt file",
                            command=self.__encrypt_file)
        back_btn = tk.Button(self, text="Back to the AES Menu",
                            command=lambda: controller.show_frame(AesMenu))
        title_lbl.pack(pady=10,padx=10)
        file_lbl.pack(pady=10,padx=10)
        file_btn.pack(pady=10,padx=10)
        location_lbl.pack(pady=10,padx=10)
        location_btn.pack(pady=10,padx=10)
        encrypt_btn.pack(pady=10,padx=10)
        back_btn.pack(pady=10,padx=10)
    
    def __encrypt_file(self):
        global LOCATION_PATH, FILE_PATH

        # Generating key
        key = get_random_bytes(16)
        try:
            if not FILE_PATH: 
                raise ValueError('You must select a file to be encrypted')
            if not LOCATION_PATH:
                raise ValueError('You must select a directory to store the files')

            # Reading the file content to be encrypted
            with open(FILE_PATH, "rb") as file:
                file_data = file.read()
            
            # Creating the AES Cipher
            aes_cipher = AES.new(key, AES.MODE_CFB)

            # Encrypting the data
            encrypted_data = aes_cipher.encrypt(file_data)

            filename = re.sub(r'\.', '_', os.path.basename(FILE_PATH))

            # Storing the encrypted data and its key
            with open(f"{LOCATION_PATH}/{filename}.bin", "wb") as encrypted_file:
                encrypted_file.write(key)
                encrypted_file.write(aes_cipher.iv)
                encrypted_file.write(encrypted_data)
            self.__alert('Success', 'File encrypted successfully', 'info')
        except Exception as e:
            self.__alert('Error', e, 'error')
        else:
            # Cleaning path variables
            FILE_PATH = ''
            LOCATION_PATH = ''

    def __get_file(self):
        global FILE_PATH
        FILE_PATH = filedialog.askopenfilename(initialdir = "./",
                                                    title = "Select a File",
                                                    filetypes = (("All files","*.*"),),)

    def __get_location(self):
        global LOCATION_PATH
        LOCATION_PATH = filedialog.askdirectory(initialdir="./")

    def __alert(self, title, message, kind='info'):
        if kind not in ('error', 'warning', 'info'):
            raise ValueError('Unsupported alert kind.')
        show_method = getattr(tk.messagebox, 'show{}'.format(kind))
        show_method(title, message)


class AesDecryption(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        global MESSAGE
        title_lbl = tk.Label(self, text="AES Decryption", font=LARGE_FONT)
        file_lbl = tk.Label(self, text="Select the file", font=LARGE_FONT)
        file_btn = tk.Button(self, text = "Browse Files", 
                            command=self.__get_file)
        location_lbl = tk.Label(self, text=f"Select the folder to store the files", font=LARGE_FONT)
        location_btn = tk.Button(self, text="Browse directories",
                            command=self.__get_location)
        encrypt_btn = tk.Button(self, text="Decrypt file",
                            command=self.__decrypt_file)
        back_btn = tk.Button(self, text="Back to the AES Menu",
                            command=lambda: controller.show_frame(AesMenu))
        title_lbl.pack(pady=10,padx=10)
        file_lbl.pack(pady=10,padx=10)
        file_btn.pack(pady=10,padx=10)
        location_lbl.pack(pady=10,padx=10)
        location_btn.pack(pady=10,padx=10)
        encrypt_btn.pack(pady=10,padx=10)
        back_btn.pack(pady=10,padx=10)

    def __get_file(self):
        global FILE_PATH
        FILE_PATH = filedialog.askopenfilename(initialdir = "./",
                                                    title = "Select a File",
                                                    filetypes = (("All files","*.*"),),)

    def __get_location(self):
        global LOCATION_PATH
        LOCATION_PATH = filedialog.askdirectory(initialdir="./")

    def __decrypt_file(self):
        global LOCATION_PATH, FILE_PATH

        try:
            if not FILE_PATH: 
                raise ValueError('You must select a file to be encrypted')
            if not LOCATION_PATH:
                raise ValueError('You must select a directory to store the files')

            filename = re.sub(r'\_', '.', re.sub(r'\.bin', '', os.path.basename(FILE_PATH)))
            print(FILE_PATH)

            # Reading the file content to be encrypted
            with open(FILE_PATH, "rb") as file:
                key = file.read(16)
                iv = file.read(16)
                encrypted_data = file.read()
            
            # Creating the AES Cipher
            aes_cipher = AES.new(key, AES.MODE_CFB, iv=iv)

            # Encrypting the data
            decrypted_data = aes_cipher.decrypt(encrypted_data)

            # Storing the encrypted data and its key
            with open(f"{LOCATION_PATH}/{filename}", "wb") as encrypted_file:
                encrypted_file.write(decrypted_data)
                self.__alert('Success', 'File decrypted successfully', 'info')
        except Exception as e:
            self.__alert('Error', e, 'error')

    def __alert(self, title, message, kind='info'):
        if kind not in ('error', 'warning', 'info'):
            raise ValueError('Unsupported alert kind.')
        show_method = getattr(tk.messagebox, 'show{}'.format(kind))
        show_method(title, message)


class DesMenu(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        title_lbl = tk.Label(self, text="DES Menu", font=LARGE_FONT)
        title_lbl.pack(pady=10,padx=10)
        encryption_btn = tk.Button(self, text="Encryption",
                            command=lambda: controller.show_frame(DesEncryption))
        decryption_btn = tk.Button(self, text="Decryption",
                            command=lambda: controller.show_frame(DesDecryption))
        back_btn = tk.Button(self, text="Back to Home",
                            command=lambda: controller.show_frame(StartPage))
        encryption_btn.pack(pady=10, padx=10)
        decryption_btn.pack(pady=10, padx=10)
        back_btn.pack(pady=10, padx=10)


class DesEncryption(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        global MESSAGE
        title_lbl = tk.Label(self, text="DES Encryption", font=LARGE_FONT)
        file_lbl = tk.Label(self, text="Select the file", font=LARGE_FONT)
        file_btn = tk.Button(self, text = "Browse Files", 
                            command=self.__get_file)
        location_lbl = tk.Label(self, text=f"Select the folder to store the files", font=LARGE_FONT)
        location_btn = tk.Button(self, text="Browse directories",
                            command=self.__get_location)
        encrypt_btn = tk.Button(self, text="Encrypt file",
                            command=self.__encrypt_file)
        back_btn = tk.Button(self, text="Back to the DES Menu",
                            command=lambda: controller.show_frame(DesMenu))
        title_lbl.pack(pady=10,padx=10)
        file_lbl.pack(pady=10,padx=10)
        file_btn.pack(pady=10,padx=10)
        location_lbl.pack(pady=10,padx=10)
        location_btn.pack(pady=10,padx=10)
        encrypt_btn.pack(pady=10,padx=10)
        back_btn.pack(pady=10,padx=10)
    
    def __encrypt_file(self):
        global LOCATION_PATH, FILE_PATH

        # Generating key
        key = get_random_bytes(8)
        try:
            if not FILE_PATH: 
                raise ValueError('You must select a file to be encrypted')
            if not LOCATION_PATH:
                raise ValueError('You must select a directory to store the files')

            # Reading the file content to be encrypted
            with open(FILE_PATH, "rb") as file:
                file_data = file.read()
            
            # Creating the AES Cipher
            des_cipher = DES.new(key, DES.MODE_CFB)

            # Encrypting the data
            encrypted_data = des_cipher.encrypt(file_data)

            filename = re.sub(r'\.', '_', os.path.basename(FILE_PATH))

            # Storing the encrypted data and its key
            with open(f"{LOCATION_PATH}/{filename}.bin", "wb") as encrypted_file:
                encrypted_file.write(key)
                encrypted_file.write(des_cipher.iv)
                encrypted_file.write(encrypted_data)
            self.__alert('Success', 'File encrypted successfully', 'info')
        except Exception as e:
            self.__alert('Error', e, 'error')
        else:
            # Cleaning path variables
            FILE_PATH = ''
            LOCATION_PATH = ''

    def __get_file(self):
        global FILE_PATH
        FILE_PATH = filedialog.askopenfilename(initialdir = "./",
                                                    title = "Select a File",
                                                    filetypes = (("All files","*.*"),),)

    def __get_location(self):
        global LOCATION_PATH
        LOCATION_PATH = filedialog.askdirectory(initialdir="./")

    def __alert(self, title, message, kind='info'):
        if kind not in ('error', 'warning', 'info'):
            raise ValueError('Unsupported alert kind.')
        show_method = getattr(tk.messagebox, 'show{}'.format(kind))
        show_method(title, message)


class DesDecryption(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        global MESSAGE
        title_lbl = tk.Label(self, text="DES Decryption", font=LARGE_FONT)
        file_lbl = tk.Label(self, text="Select the file", font=LARGE_FONT)
        file_btn = tk.Button(self, text = "Browse Files", 
                            command=self.__get_file)
        location_lbl = tk.Label(self, text=f"Select the folder to store the files", font=LARGE_FONT)
        location_btn = tk.Button(self, text="Browse directories",
                            command=self.__get_location)
        encrypt_btn = tk.Button(self, text="Decrypt file",
                            command=self.__decrypt_file)
        back_btn = tk.Button(self, text="Back to the DES Menu",
                            command=lambda: controller.show_frame(DesMenu))
        title_lbl.pack(pady=10,padx=10)
        file_lbl.pack(pady=10,padx=10)
        file_btn.pack(pady=10,padx=10)
        location_lbl.pack(pady=10,padx=10)
        location_btn.pack(pady=10,padx=10)
        encrypt_btn.pack(pady=10,padx=10)
        back_btn.pack(pady=10,padx=10)

    def __get_file(self):
        global FILE_PATH
        FILE_PATH = filedialog.askopenfilename(initialdir = "./",
                                                    title = "Select a File",
                                                    filetypes = (("All files","*.*"),),)

    def __get_location(self):
        global LOCATION_PATH
        LOCATION_PATH = filedialog.askdirectory(initialdir="./")

    def __decrypt_file(self):
        global LOCATION_PATH, FILE_PATH

        try:
            if not FILE_PATH: 
                raise ValueError('You must select a file to be encrypted')
            if not LOCATION_PATH:
                raise ValueError('You must select a directory to store the files')

            filename = re.sub(r'\_', '.', re.sub(r'\.bin', '', os.path.basename(FILE_PATH)))

            # Reading the file content to be encrypted
            with open(FILE_PATH, "rb") as file:
                key = file.read(8)
                iv = file.read(8)
                encrypted_data = file.read()
            
            # Creating the AES Cipher
            des_cipher = DES.new(key, DES.MODE_CFB, iv=iv)

            # Encrypting the data
            decrypted_data = des_cipher.decrypt(encrypted_data)

            # Storing the encrypted data and its key
            with open(f"{LOCATION_PATH}/{filename}", "wb") as encrypted_file:
                encrypted_file.write(decrypted_data)
                self.__alert('Success', 'File decrypted successfully', 'info')
        except Exception as e:
            self.__alert('Error', e, 'error')

    def __alert(self, title, message, kind='info'):
        if kind not in ('error', 'warning', 'info'):
            raise ValueError('Unsupported alert kind.')
        show_method = getattr(tk.messagebox, 'show{}'.format(kind))
        show_method(title, message)



class RsaMenu(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        title_lbl = tk.Label(self, text="RSA Menu", font=LARGE_FONT)
        title_lbl.pack(pady=10,padx=10)
        encryption_btn = tk.Button(self, text="Encryption",
                            command=lambda: controller.show_frame(RsaEncryption))
        decryption_btn = tk.Button(self, text="Decryption",
                            command=lambda: controller.show_frame(RsaDecryption))
        back_btn = tk.Button(self, text="Back to Home",
                            command=lambda: controller.show_frame(StartPage))
        encryption_btn.pack(pady=10, padx=10)
        decryption_btn.pack(pady=10, padx=10)
        back_btn.pack(pady=10, padx=10)

class RsaEncryption(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        global MESSAGE
        title_lbl = tk.Label(self, text="RSA Encryption", font=LARGE_FONT)
        file_lbl = tk.Label(self, text="Select the file", font=LARGE_FONT)
        file_btn = tk.Button(self, text = "Browse Files", 
                            command=self.__get_file)
        public_lbl = tk.Label(self, text="Select the receiver public key", font=LARGE_FONT)
        public_btn = tk.Button(self, text = "Browse Files", 
                            command=self.__get_public_key)
        location_lbl = tk.Label(self, text=f"Select the folder to store the files", font=LARGE_FONT)
        location_btn = tk.Button(self, text="Browse directories",
                            command=self.__get_location)
        encrypt_btn = tk.Button(self, text="Encrypt file",
                            command=self.__encrypt_file)
        back_btn = tk.Button(self, text="Back to the RSA Menu",
                            command=lambda: controller.show_frame(RsaMenu))
        title_lbl.pack(pady=10,padx=10)
        file_lbl.pack(pady=10,padx=10)
        file_btn.pack(pady=10,padx=10)
        public_lbl.pack(pady=10, padx=10)
        public_btn.pack(pady=10, padx=10)
        location_lbl.pack(pady=10,padx=10)
        location_btn.pack(pady=10,padx=10)
        encrypt_btn.pack(pady=10,padx=10)
        back_btn.pack(pady=10,padx=10)
    
    def __encrypt_file(self):
        global LOCATION_PATH, FILE_PATH, PUBLIC_KEY_PATH

        try:
            if not FILE_PATH: 
                raise ValueError('You must select a file to be encrypted')
            if not LOCATION_PATH:
                raise ValueError('You must select a directory to store the files')
            if not PUBLIC_KEY_PATH:
                raise ValueError('You must select the receiver public key')

            # Reading the file content to be encrypted
            with open(FILE_PATH, "rb") as file:
                file_data = file.read()
            
            # Getting the receiver public key
            with open(PUBLIC_KEY_PATH, 'rb') as public_file:
                public_key = RSA.import_key(public_file.read())

            filename = re.sub(r'\.', '_', os.path.basename(FILE_PATH))

            # Generating the AES session key 
            session_key = get_random_bytes(16)

            # Encrypting the session key using the receiver public key
            rsa_cipher = PKCS1_OAEP.new(public_key)
            encrypted_session_key = rsa_cipher.encrypt(session_key)

            # Encrypting the document using the AES session key
            aes_cipher = AES.new(session_key, AES.MODE_EAX)
            encrypted_data, tag = aes_cipher.encrypt_and_digest(file_data)

            # Storing the encrypted data
            with open(f"{LOCATION_PATH}/{filename}.bin", "wb") as encrypted_file:
                [ encrypted_file.write(x) for x in (encrypted_session_key, aes_cipher.nonce, tag, encrypted_data) ]
            self.__alert('Success', 'File encrypted successfully', 'info')
        except Exception as e:
            self.__alert('Error', e, 'error')
        else:
            # Cleaning path variables
            FILE_PATH = ''
            LOCATION_PATH = ''
            PUBLIC_KEY_PATH = ''

    def __get_file(self):
        global FILE_PATH
        FILE_PATH = filedialog.askopenfilename(initialdir = "./",
                                                    title = "Select a File",
                                                    filetypes = (("All files","*.*"),),)

    def __get_public_key(self):
        global PUBLIC_KEY_PATH
        PUBLIC_KEY_PATH = filedialog.askopenfilename(initialdir = "./",
                                                    title = "Select a File",
                                                    filetypes = (("All files","*.*"),),)

    def __get_location(self):
        global LOCATION_PATH
        LOCATION_PATH = filedialog.askdirectory(initialdir="./")

    def __alert(self, title, message, kind='info'):
        if kind not in ('error', 'warning', 'info'):
            raise ValueError('Unsupported alert kind.')
        show_method = getattr(tk.messagebox, 'show{}'.format(kind))
        show_method(title, message)

class RsaDecryption(tk.Frame):
        def __init__(self, parent, controller):
            tk.Frame.__init__(self, parent)
            global MESSAGE
            title_lbl = tk.Label(self, text="RSA Encryption", font=LARGE_FONT)
            file_lbl = tk.Label(self, text="Select the file", font=LARGE_FONT)
            file_btn = tk.Button(self, text = "Browse Files", 
                                command=self.__get_file)
            public_lbl = tk.Label(self, text="Select your private key", font=LARGE_FONT)
            public_btn = tk.Button(self, text = "Browse Files", 
                                command=self.__get_private_key)
            location_lbl = tk.Label(self, text=f"Select the folder to store the files", font=LARGE_FONT)
            location_btn = tk.Button(self, text="Browse directories",
                                command=self.__get_location)
            encrypt_btn = tk.Button(self, text="Decrypt file",
                                command=self.__decrypt_file)
            back_btn = tk.Button(self, text="Back to the AES Menu",
                                command=lambda: controller.show_frame(AesMenu))
            title_lbl.pack(pady=10,padx=10)
            file_lbl.pack(pady=10,padx=10)
            file_btn.pack(pady=10,padx=10)
            public_lbl.pack(pady=10, padx=10)
            public_btn.pack(pady=10, padx=10)
            location_lbl.pack(pady=10,padx=10)
            location_btn.pack(pady=10,padx=10)
            encrypt_btn.pack(pady=10,padx=10)
            back_btn.pack(pady=10,padx=10)

        def __get_file(self):
            global FILE_PATH
            FILE_PATH = filedialog.askopenfilename(initialdir = "./",
                                                    title = "Select a File",
                                                    filetypes = (("All files","*.*"),),)

        def __get_private_key(self):
            global PRIVATE_KEY_PATH
            PRIVATE_KEY_PATH = filedialog.askopenfilename(initialdir = "./",
                                                        title = "Select a File",
                                                        filetypes = (("All files","*.*"),),)

        def __get_location(self):
            global LOCATION_PATH
            LOCATION_PATH = filedialog.askdirectory(initialdir="./")

        def __alert(self, title, message, kind='info'):
            if kind not in ('error', 'warning', 'info'):
                raise ValueError('Unsupported alert kind.')
            show_method = getattr(tk.messagebox, 'show{}'.format(kind))
            show_method(title, message)

        def __decrypt_file(self):
            global LOCATION_PATH, FILE_PATH, PUBLIC_KEY_PATH

            try:
                if not FILE_PATH: 
                    raise ValueError('You must select a file to be decrypted')
                if not LOCATION_PATH:
                    raise ValueError('You must select a directory to store the files')
                if not PRIVATE_KEY_PATH:
                    raise ValueError('You must select your private key')

                # Reading the file content to be encrypted
                file_data = open(FILE_PATH, "rb")
                
                # Getting the receiver public key
                with open(PRIVATE_KEY_PATH, 'rb') as private_file:
                    private_key = RSA.import_key(private_file.read())


                filename = re.sub(r'\_', '.', re.sub(r'\.bin', '', os.path.basename(FILE_PATH)))

                # Getting the necessary information to decrypt the document
                encrypted_session_key, nonce, tag, ciphertext = \
                [ file_data.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

                # Decrypting the session key using the receiver private key
                rsa_cipher = PKCS1_OAEP.new(private_key)
                session_key = rsa_cipher.decrypt(encrypted_session_key)

                # Decrypting the document using the AES session key
                cipherAES = AES.new(session_key, AES.MODE_EAX, nonce)

                decrypted_document = cipherAES.decrypt_and_verify(ciphertext, tag)

                # Storing the encrypted data
                with open(f"{LOCATION_PATH}/{filename}", "wb") as decrypted_file:
                    decrypted_file.write(decrypted_document)
                    
                self.__alert('Success', 'File decrypted successfully', 'info')
            except Exception as e:
                self.__alert('Error', e, 'error')
            else:
                # Cleaning path variables
                FILE_PATH = ''
                LOCATION_PATH = ''
                PUBLIC_KEY_PATH = ''


app = SeaofBTCapp()
app.mainloop()