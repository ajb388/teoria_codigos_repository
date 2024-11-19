import os
import tkinter as tk
import base64
import json
from hashlib import sha256
from kyber.kyber import Kyber512, Kyber768, Kyber1024
from Crypto.Hash import SHA256
from tkinter import filedialog
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Random import random
from tkinter import filedialog, messagebox
import sys

# Variables globales
private_app = ""
public_app = ""
clave_aes_app = b"pepitoperez"
lista_usuarios = []
certificado = ""

lista_claves = {}
ruta_archivo = ""
ruta_salida = ""
ruta_claves = ""
usuario = ""
contrasena = ""
    # Define el directorio base automáticamente
directorio_base = os.path.join(os.path.dirname(__file__))

def salir_app():
    ventana.quit()

def seleccionar_archivos():
    # Abre un diálogo para seleccionar uno o varios archivos
    global ruta_archivo
    ruta_archivo = filedialog.askopenfilenames(
                    title="Seleccionar archivo(s)",
                    filetypes=[("Todos los archivos", ".*")]
    )
    
    # Si se seleccionan archivos, muestra sus nombres
    if ruta_archivo:
        archivos_seleccionados = "\n".join(ruta_archivo)
        messagebox.showinfo("Archivos Seleccionados", f"Has seleccionado:\n{archivos_seleccionados}")
    else:
        messagebox.showinfo("No se seleccionaron archivos", "No se ha seleccionado ningún archivo.")

def leer_archivo(ruta_archivo):
    with open(ruta_archivo, 'rb') as f:
        return f.read()

def leer_claves(ruta_claves):
    claves_leidas = {}
    try:
        with open(ruta_claves,'rb') as f:
                while True:
                    len_nombre = f.read(1)
                    if not len_nombre:
                        break
                    len_nombre = int.from_bytes(len_nombre,'big')
                    nombre = f.read(len_nombre).decode('utf-8')
                
                    len_clave = f.read(1)
                    if not len_clave:
                        break
                    len_clave = int.from_bytes(len_clave,'big')
                    clave = f.read(len_clave)

                    len_extension = f.read(1)
                    if not len_extension:
                        break
                    len_extension = int.from_bytes(len_extension,'big')
                    extension = f.read(len_extension).decode('utf-8')
                
                    claves_leidas[nombre] = (clave, extension)
                return claves_leidas
    except FileNotFoundError:
        return claves_leidas

def escribir_archivo(ruta_archivo, datos):
    with open(ruta_archivo, 'wb') as f:
        f.write(datos)

def crear_kyber():

    key=Kyber512
    #Guardamos las claves generadas publica y privada tal y como lo devuelve la funcion keygen()
    public_key, private_key = key.keygen()

    user_directory = os.path.join("practica4", usuario)
    ruta_privada = os.path.normpath(os.path.join(user_directory, "private_kyber.pem"))
    ruta_publica = os.path.normpath(os.path.join(user_directory, "public_kyber.pem"))

    if os.path.exists(ruta_privada) and os.path.exists(ruta_publica):
        messagebox.showerror("Error", "Las claves pública y privada ya existen.")
        return
    #Colocamos en el formato de base64 para poder crear el archivo pem de forma correcta 
    with open(ruta_privada, "wb") as f:
        f.write(b"----BEGIN PRIVATE KEY----\n")
        f.write(base64.b64encode(private_key)+b"\n")
        f.write(b"\n----END PRIVATE KEY----")
    with open(ruta_publica, "wb") as f:
        f.write(b"----BEGIN PUBLIC KEY----\n")
        f.write(base64.b64encode(public_key)+b"\n")
        f.write(b"\n----END PUBLIC KEY----")

def encriptar_kyber():
    while True:
        print("Necesitamos que nos facilite el archivo de claves")
        ruta_archivo_cifrado = filedialog.askopenfilename(
            title="Seleccionar archivo de claves",
            filetypes=[("Todos los archivos", "*.bin")]
        )
        root = tk.Tk()
        root.withdraw()  # Oculta la ventana principal de Tkinter
        print("Necesitamos que nos facilite la clave publica para encriptar el archivo de claves")
        ruta_archivo = filedialog.askopenfilename(
                title="Seleccionar archivo",
                filetypes=[("Todos los archivos", "*.pem")] #Seleccionamos donde queremos el archivo de clave publica
            )
        if ruta_archivo:
                with open(ruta_archivo, "rb") as f:
                    public_key = f.read() #Leemos su contenido y lo importamos como clave Kyber
                    
                #Realizamos el proceso de reconstrucción para recuperar la clave en su formato util
                public_key = public_key.decode("utf-8")
                public_key = public_key.replace("----BEGIN PUBLIC KEY----","")
                public_key = public_key.replace("----END PUBLIC KEY----","")
                public_key = public_key.replace("\n","")
                public_key = base64.b64decode(public_key)

                #Dependiendo del taamaño de la clave, podemos averiguar que tipo de kyber se utilizó a la hora de crear las claves
                with open(ruta_archivo_cifrado, "rb") as f:
                    datos = f.read()
                if len(public_key) == 800:
                    kyberobject = Kyber512
                elif len(public_key) == 1184:
                    kyberobject = Kyber768
                elif len(public_key) == 1568:
                    kyberobject = Kyber1024
                    
                tamanio = 32
                datos_cifrados = []
                #Al ser mensajes demasiado grandes para el encriptador, dividimos el mensaje en mensajes del tamaño útil de kyber
                for i in range(0, len(datos), tamanio):
                    bloque = datos[i:i+tamanio]
                    bloque = bloque.ljust(tamanio, b'\0')
                    datos_cifrados.append(kyberobject._cpapke_enc(public_key, bloque, tamanio.to_bytes(32, byteorder='big')))
                #Unificamos todos los bloques del mensaje en uno solo, obteniendo así el archivo de claves encriptado.
                encrypted_data = b''.join(datos_cifrados)
        
                with open(ruta_archivo_cifrado, "wb") as f:
                    f.write(encrypted_data)
                break

def desencriptar_kyber(ruta_archivo_cifrado):
    print("Necesitamos que nos facilite la clave privada para desencriptar el archivo de claves")
    while True:
        root = tk.Tk()
        root.withdraw()  # Oculta la ventana principal de Tkinter
        ruta_archivo = filedialog.askopenfilename(
                        title="Seleccionar archivo",
                        filetypes=[("Todos los archivos", "*.pem")] #Seleccionamos el archivo clave privada
                    )
        if not ruta_archivo:
            print("Cancelando proceso...")
            return False
        else:   
                with open(ruta_archivo, "rb") as f:
                    private_key = f.read() #Leemos su contenido y lo importamos como clave Kyber
                
                #Ajustamos el formato del contenido del archivo para poder obtener la clave en su forma útil
                private_key = private_key.decode("utf-8")
                private_key = private_key.replace("----BEGIN PRIVATE KEY----","")
                private_key = private_key.replace("----END PRIVATE KEY----","")
                private_key = private_key.replace("\n","")
                private_key = base64.b64decode(private_key)
                with open(ruta_archivo_cifrado, "rb") as f:
                    datos = f.read() #Leemos el archivo de claves.bin 
                    
                    kyberobject = Kyber512
                    tamanio = 768
                    
                datos_descifrados = []
            
                for i in range(0, len(datos), tamanio):
                    bloque = datos[i:i+tamanio]
                    if isinstance(bloque,int):
                        bloque = bloque.to_bytes((bloque.bit_length()+7)//8,byteorder='big')
                    bloquedes = kyberobject._cpapke_dec(private_key, bloque)
                    bloquedes = bloquedes.rstrip(b'\0')
                    datos_descifrados.append(bloquedes)
                        
                dencrypted_data = b''.join(datos_descifrados)
                dencrypted_data = dencrypted_data.rstrip(b'\0')
    
                with open(ruta_archivo_cifrado, "wb") as f:
                    f.write(dencrypted_data)
                break

def crear_RSA():
   
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    user_directory = os.path.join("practica4", usuario)
    ruta_privada = os.path.normpath(os.path.join(user_directory, "private_rsa.pem"))
    ruta_publica = os.path.normpath(os.path.join(user_directory, "public_rsa.pem"))

    if os.path.exists(ruta_privada) and os.path.exists(ruta_publica):
        messagebox.showerror("Error", "Las claves pública y privada ya existen.")
        return
    
    with open(ruta_privada, "wb") as f:
        f.write(private_key)
    with open(ruta_publica, "wb") as f:
        f.write(public_key)


def crearClavesAplicacion():
    global private_app
    global public_app
    
    #key=RSA.generate(2048)
    private_app = b'-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAzwaGMLVGcvjj827zJMFdfc5/eG4CmomZVL7j140tw0XwB3aC\nZ6o33u0IoRWYCen/czTsQSSj+YReFyF/4trcCbXs8nKVLurQY/D9PdcswGrOrf66\nIkBiDWatXGal7PPFQ6gpwyWd22z9GNlvJLaqNGk6hNuzDoGh7AtrTs/XraalZ2gI\ns3+KOuoX8KGtXFc6JeieBIAr5b8jxlujpQR1LWHWqCLCSDcAEVaWsd6GJy06TM+U\nevM81Yj3uhXvpn9rni87QzUwZ/keFc39CUBFx5WrYOpv5PfvZHShsScXzO4/Dzml\nsHJVuB6XSmQ5FEM804fzGOrpu182AinOzp8BZwIDAQABAoIBAFDks7qEmqqCJlAQ\nomFSTT3DWnusQMgxzAAZNt4bBC6xPUEtRXdMQ9iPtjd7QJVfIbnajBZIQupUlo9j\nP51c922z8Iory68xgYwLtmhbk9j74xaJ2iFYFvg1jrf0RBF6jzIIm4jtQeljhOIY\n1Bz8YzVniL4xOp4IeUTKkXuSKyxmpVxfUE8pwQwUpoZkBoVPYSzsQZ5u+sNZhqPE\nMUgNDMkhVKLzUU3HVu+TWwFYT6VnyLxQ6Uw+B009yFyTKvbObZsoClYD0z28n4gY\nBjcPPcjk/rliRYBriflD5dJ6Bz/Is/FyUL1IflODAukyFfKojHfH5MhsE2MTT3w9\nnAWwzoECgYEA3SD+r4UF+u8sfSDskYv/KOt3+Jg4/YFqlweSRqcBvaiLv87Pk8f1\nwpLRugjiDTEfro/XjfYY2tACup+9v3SjV29ln9J4RT+8kuYLEYGRnmliqagSK5q2\nTS6rzvID51BkPqkp99TMreGyoapFsORlVZQaumW9NEQu9EC+zVxCOn8CgYEA76ws\nR9eZ8pEFotvCGHEI6Dzx5n7n/75CYCVyOFI9sKjDjrBMV1t1vJXZSi3Ko17n5W3b\naxN0ig5uRSglFr4zr/VPHEywB7FQpQ0i/Kdgta6gVhykxiR/bi2l9pd4qlmroj8h\nfeCDY+YVXMBMmyxxYs5MYtf1Xk0ieb4WjKZ1NRkCgYBplEZmEXJwhF/OgrjRKXGz\n3PGULUIQsAjvgXry5uxq3J2VAC6WFcQembEvTOx5dfn1g9JcgqMNXoHfD0QutIcE\nyThRXdF05uCnltS0EBQx+YlVDd1XGnBuW5lGnsEEYZrrXCOgo+byIrAChmTt9672\ndFdqpgb3fJKaposzTBiHCwKBgB0EzKu6KBKdioAoeXy6Guj7kBJnZTGq2KCJiCXX\nl06PcHYTVHrzQPMfdZqspq9XK161CW8SgPbCPomzDaKOTvXMDtMPWfTkfC4vw/+x\nSF1XEmS6vRyciK1Pa5vKxTpi9wwC9swl5eKvlgCP6/aRz/y1m7wQB85uKnFxGYvY\nD7LpAoGBANlPzxk0Xu06ZJwh3UMILfF2GCYUpkBLnLMkaXJ92sChUgtfkYse0u6a\nKZ1ClrYcVCv5yct5OZwY/yOp9SdsiSz+EH8CK1NeJKQyrkMfeP3R7RjqbBgePiLO\nEmFPODqLHXKnuzLtwaflIe5fbq9jvDWjxdT9NahDWSTKnS+ySjWu\n-----END RSA PRIVATE KEY-----'
    public_app = b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzwaGMLVGcvjj827zJMFd\nfc5/eG4CmomZVL7j140tw0XwB3aCZ6o33u0IoRWYCen/czTsQSSj+YReFyF/4trc\nCbXs8nKVLurQY/D9PdcswGrOrf66IkBiDWatXGal7PPFQ6gpwyWd22z9GNlvJLaq\nNGk6hNuzDoGh7AtrTs/XraalZ2gIs3+KOuoX8KGtXFc6JeieBIAr5b8jxlujpQR1\nLWHWqCLCSDcAEVaWsd6GJy06TM+UevM81Yj3uhXvpn9rni87QzUwZ/keFc39CUBF\nx5WrYOpv5PfvZHShsScXzO4/DzmlsHJVuB6XSmQ5FEM804fzGOrpu182AinOzp8B\nZwIDAQAB\n-----END PUBLIC KEY-----'
    encriptarPrivate_app()

def desencriptarPrivate_app():
    global private_app

    salt = private_app[:16]
    iv = private_app[16:32]
    ciphertext = private_app[32:]
    derived_key = PBKDF2(clave_aes_app, salt, dkLen=32)
    cipher = AES.new(derived_key, AES.MODE_CBC, iv)
    private_app = unpad(cipher.decrypt(ciphertext), AES.block_size)

def encriptarPrivate_app():
    global private_app

    if isinstance(private_app, bytes):
        private_app_bytes = private_app
    else:
        private_app_bytes = private_app.export_key()

    salt = get_random_bytes(16)
    derived_key = PBKDF2(clave_aes_app, salt, dkLen=32)
    cipher = AES.new(derived_key, AES.MODE_CBC)
    padded_rsa_key = pad(private_app_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_rsa_key)
    private_app = salt + cipher.iv + ciphertext

def registrarUsuarioApp(nombre, contrasena):
    global private_app
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    #encriptamos clave privada del user con su contraseña
    salt = get_random_bytes(16)
    derived_key = PBKDF2(contrasena, salt, dkLen=32)
    cipher = AES.new(derived_key, AES.MODE_CBC)
    padded_rsa_key = pad(private_key, AES.block_size)
    ciphertext = cipher.encrypt(padded_rsa_key)
    private_key = salt + cipher.iv + ciphertext

    hash_object = SHA256.new()
    datos = nombre + " " + public_key.decode('utf-8')
    hash_object.update(datos.encode('utf-8'))
    #este es el hash del nombre y la clave publica del usuario para la firma del certificado
    #firmamos el hash con la clave privada de la aplicación
    desencriptarPrivate_app()
    private_app = RSA.import_key(private_app)
    signature = pkcs1_15.new(private_app).sign(hash_object)
    encriptarPrivate_app()
    public_key_base64 = base64.b64encode(public_key).decode('utf-8')
    
    #Creamos el certificado del usuario
    certificate = {
        "user": nombre,
        "public_key": public_key_base64,
        "signature": signature.hex()
    }

    # Crear el directorio para el nuevo usuario
    user_directory = os.path.join(directorio_base, nombre)
    if not os.path.exists(user_directory):
        os.makedirs(user_directory)

    #Creamos el certificado físicamente en el directorio para el usuario
    ruta_certificado = os.path.join(user_directory, f"certificate_{nombre}.json")
    with open(ruta_certificado, 'w') as cert_file:
        json.dump(certificate,cert_file, indent=4)

    messagebox.showinfo("Registro", f"Usuario registrado con éxito.\nCertificado guardado en: {user_directory}")

    #guardamos el certificado en la lista de usuarios de la app
    guardarUsuarioApp(certificate, private_key)

def guardarUsuarioApp(certificate, private_key):

    global lista_usuarios
    leerUsuariosApp()
    ruta_certificados = os.path.join(directorio_base, f"appCertificates.json")
    private_key_base64 = base64.b64encode(private_key).decode('utf-8')
    estructura = {
        "user": certificate["user"],
        "public_key": certificate["public_key"],
        "signature": certificate["signature"],
        "private_key": private_key_base64
    }
    lista_usuarios.append(estructura)
    with open(ruta_certificados, 'w') as f:
        json.dump(lista_usuarios, f, indent=4)

def leerUsuariosApp():
    global lista_usuarios
    ruta_certificados = os.path.join(directorio_base, f"appCertificates.json")
    if os.path.exists(ruta_certificados):
        with open(ruta_certificados, 'r') as file:
            estructura = file.read()
            if not estructura.strip():
                lista_usuarios = []
            else:
                estructura = json.loads(estructura)
                lista_usuarios = estructura
    else:
        with open(ruta_certificados, 'w') as file:
            json.dump([], file)

def validarUsuario(contraseña):
    global usuario
    global contrasena
    messagebox.showinfo("Certificado", certificado)

    with open(certificado, 'r') as file:
        certificate = file.read()
        if not certificate.strip():
            print("Error, no es correcto")
        else:
            leerUsuariosApp()
            certificate = json.loads(certificate)
            usuario = certificate["user"]
            for lista_user in lista_usuarios:
                if lista_user["user"] == usuario:
                    try:
                        public_key_user_base64 = certificate['public_key']
                        public_key_user = base64.b64decode(public_key_user_base64)

                        comprobante = certificate['user'] + " " + public_key_user.decode('utf-8')
                        hash_comprobante = SHA256.new(comprobante.encode('utf-8'))

                        public_app_comp = RSA.import_key(public_app)
                        certif=bytes.fromhex(certificate['signature'])
                        pkcs1_15.new(public_app_comp).verify(hash_comprobante,certif)
                             
                        private_key_base64 = lista_user["private_key"]
                        private_key = base64.b64decode(private_key_base64)

                        salt = private_key[:16]
                        iv = private_key[16:32]
                        ciphertext = private_key[32:]
                        derived_key = PBKDF2(contraseña, salt, dkLen=32)
                        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
                        private_key = unpad(cipher.decrypt(ciphertext), AES.block_size)
                        usuario = certificate["user"]
                        contrasena = contraseña
                        print("Usuario validado")
                        break
                    except(ValueError,TypeError):
                        print("Usuario no validado")
                        break

def listarUsuariosEncriptar():
    lista_temporal = []
    for usuario in lista_usuarios:
        lista_temporal.append(usuario['user'])
    return lista_temporal

def verificarUsuarioSeleccionado(usuario):
    leerUsuariosApp()
    for user in lista_usuarios:
        if user["user"] == usuario:
                    try:
                        public_key_user_base64 = user['public_key']
                        public_key_user = base64.b64decode(public_key_user_base64)

                        comprobante = user['user'] + " " + public_key_user.decode('utf-8')
                        hash_comprobante = SHA256.new(comprobante.encode('utf-8'))

                        public_app_comp = RSA.import_key(public_app)
                        certif=bytes.fromhex(user['signature'])
                        pkcs1_15.new(public_app_comp).verify(hash_comprobante,certif)

                        print("Usuario validado")
                        break
                    except (ValueError, TypeError):
                        print("Usuario no validado")
                        break

def encriptarArchivosUsers(lista_usuarios_encriptan, lista_rutas_archivos):
    leerUsuariosApp()
    lista_claves_cifradas = {}
    user_directory = os.path.join(directorio_base, usuario)
    ruta_salida_cortada = os.path.normpath(user_directory)
    for archivo in lista_rutas_archivos:
        nombre_archivo, extension = os.path.splitext(os.path.basename(archivo))
        with open(archivo, 'rb') as file:
            datos = file.read()

        clave = get_random_bytes(32)
        cipher_aes = AES.new(clave, AES.MODE_CBC)
        datos_pad = pad(datos,AES.block_size)
        texto_cifrado = cipher_aes.encrypt(datos_pad)
        datos_cifrados = cipher_aes.iv + texto_cifrado

        for user1 in lista_usuarios_encriptan:
            for user2 in lista_usuarios:
                if user2['user'] == user1:
                    public_key_base64 = user2['public_key']
                    public_key_bytes = base64.b64decode(public_key_base64)
                    public_key = RSA.import_key(public_key_bytes)
                    cipher = PKCS1_OAEP.new(public_key)
                    clave_user = cipher.encrypt(clave)
                    lista_claves_cifradas[user2['user']] = clave_user
        rutasalida2 = os.path.normpath(os.path.join(ruta_salida_cortada, f"{nombre_archivo}.bin"))
        with open(rutasalida2, 'wb') as f:
            for user in lista_claves_cifradas:
                nombre_bytes = user.encode('utf-8')
                f.write(len(nombre_bytes).to_bytes(1,'big'))
                f.write(nombre_bytes)

                clave_bytes = lista_claves_cifradas[user]
                f.write(len(clave_bytes).to_bytes(2,'big'))
                f.write(clave_bytes)

            f.write(b'\x00')
            extension_bytes = extension.encode('utf-8')
            f.write(len(extension_bytes).to_bytes(1,'big'))
            f.write(extension_bytes)

            nombre_archivo_bytes = nombre_archivo.encode('utf-8')
            f.write(len(nombre_archivo_bytes).to_bytes(1,'big'))
            f.write(nombre_archivo_bytes)

            f.write(datos_cifrados)

def desencriptarArchivosUsers(lista_rutas_archivos):
    leerUsuariosApp()
    user_directory = os.path.join(directorio_base, usuario)
    ruta_salida_cortada = os.path.normpath(user_directory)
    for archivo in lista_rutas_archivos:
        lista_claves_cifradas = {}
        with open (archivo, 'rb') as file:
            lista_claves_cifradas = {}
            while True:

                len_nombre = int.from_bytes(file.read(1),'big')
                if len_nombre == 0:
                    break
                nombre_usuario = file.read(len_nombre).decode('utf-8')

                len_clave = int.from_bytes(file.read(2),'big')
                clave_cifrada = file.read(len_clave)

                lista_claves_cifradas[nombre_usuario] = clave_cifrada

                separador = file.read(1)
                if separador == b'\x00':
                    break
                else:
                    file.seek(-1, os.SEEK_CUR)

            
            len_extension = int.from_bytes(file.read(1),'big')
            extension = file.read(len_extension).decode('utf-8')
            len_nombre_archivo = int.from_bytes(file.read(1),'big')
            nombre_archivo = file.read(len_nombre_archivo).decode('utf-8')

            datos_cifrados = file.read()
            iv_aes = datos_cifrados[:16]
            datos = datos_cifrados[16:]

            es_valido = False    

            for user in lista_claves_cifradas:
                for user2 in lista_usuarios:
                    if user == usuario == user2['user']:
                        es_valido = True
                        clave = lista_claves_cifradas[user]
                        private_key_base64 = user2['private_key']
                        private_key = base64.b64decode(private_key_base64)
                        #para la clave privada del usuario
                        salt = private_key[:16]
                        iv = private_key[16:32]
                        ciphertext = private_key[32:]
                        derived_key = PBKDF2(contrasena, salt, dkLen=32)
                        cipher_aes = AES.new(derived_key, AES.MODE_CBC, iv)
                        private_key = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
                        private_key_rsa = RSA.import_key(private_key)
                        cipher_rsa = PKCS1_OAEP.new(private_key_rsa)
                        clave_descifrada = cipher_rsa.decrypt(clave)

                        #para la clave aes del archivo
                        cipher_aes = AES.new(clave_descifrada, AES.MODE_CBC, iv_aes)
                        texto_descifrado = unpad(cipher_aes.decrypt(datos),AES.block_size)
                        
                        rutasalida2 = os.path.normpath(os.path.join(ruta_salida_cortada, f"{nombre_archivo}{extension}"))
                        with open (rutasalida2, 'wb') as file:
                            file.write(texto_descifrado)

            if not es_valido:
                messagebox.showerror("Error", f"No tiene permiso para descifrar el archivo {nombre_archivo}")

def descifrar_archivo():
    desencriptarArchivosUsers(ruta_archivo)

def cifrar_archivo():
    def seleccionar_usuarios():
        usuarios = listarUsuariosEncriptar()
        seleccionados = []

        def agregar_usuario():
            usuario_seleccionado = lista_usuarios.get(tk.ACTIVE)
            if usuario_seleccionado and usuario_seleccionado not in seleccionados:
                seleccionados.append(usuario_seleccionado)
                lista_seleccionados.insert(tk.END, usuario_seleccionado)

        def eliminar_usuario():
            usuario_seleccionado = lista_seleccionados.get(tk.ACTIVE)
            if usuario_seleccionado in seleccionados:
                seleccionados.remove(usuario_seleccionado)
                lista_seleccionados.delete(tk.ACTIVE)

        def confirmar_seleccion():
            if seleccionados:
                seleccionar_usuarios_ventana.destroy()
                encriptarArchivosUsers(seleccionados, ruta_archivo)
            else:
                messagebox.showerror("Error", "Debe seleccionar al menos un usuario.")

        seleccionar_usuarios_ventana = tk.Tk()
        seleccionar_usuarios_ventana.title("Seleccionar Usuarios")
        seleccionar_usuarios_ventana.geometry("1000x700")

        label_usuarios = tk.Label(seleccionar_usuarios_ventana, text="Usuarios Disponibles:")
        label_usuarios.pack(pady=5)
        lista_usuarios = tk.Listbox(seleccionar_usuarios_ventana)
        lista_usuarios.pack(pady=5, fill=tk.BOTH, expand=True)
        for usuario in usuarios:
            lista_usuarios.insert(tk.END, usuario)

        boton_agregar = tk.Button(seleccionar_usuarios_ventana, text="Agregar", command=agregar_usuario)
        boton_agregar.pack(pady=5)

        label_seleccionados = tk.Label(seleccionar_usuarios_ventana, text="Usuarios Seleccionados:")
        label_seleccionados.pack(pady=5)
        lista_seleccionados = tk.Listbox(seleccionar_usuarios_ventana)
        lista_seleccionados.pack(pady=5, fill=tk.BOTH, expand=True)

        boton_eliminar = tk.Button(seleccionar_usuarios_ventana, text="Eliminar", command=eliminar_usuario)
        boton_eliminar.pack(pady=5)

        boton_confirmar = tk.Button(seleccionar_usuarios_ventana, text="Confirmar", command=confirmar_seleccion)
        boton_confirmar.pack(pady=10)

        seleccionar_usuarios_ventana.mainloop()

    seleccionar_usuarios()

def login():
    def registrar_usuario():
        def guardar_usuario():
            nuevo_usuario = entry_nuevo_usuario.get()
            nueva_contrasena = entry_nueva_contrasena.get()

            registrarUsuarioApp(nuevo_usuario, nueva_contrasena)

            
            registro_ventana.destroy()

        # Crear ventana para el registro
        registro_ventana = tk.Tk()
        registro_ventana.title("Registrar Usuario")
        registro_ventana.geometry("400x200")

        label_nuevo_usuario = tk.Label(registro_ventana, text="Nuevo Usuario:")
        label_nuevo_usuario.pack(pady=5)
        entry_nuevo_usuario = tk.Entry(registro_ventana)
        entry_nuevo_usuario.pack(pady=5)

        label_nueva_contrasena = tk.Label(registro_ventana, text="Nueva Contraseña:")
        label_nueva_contrasena.pack(pady=5)
        entry_nueva_contrasena = tk.Entry(registro_ventana, show="*")
        entry_nueva_contrasena.pack(pady=5)

        boton_guardar = tk.Button(registro_ventana, text="Guardar", command=guardar_usuario)
        boton_guardar.pack(pady=10)

        registro_ventana.mainloop()


    login_ventana = tk.Tk()
    login_ventana.title("Login")
    login_ventana.geometry("600x300")
    
    def seleccionar_certificado():
        global certificado
        certificado = filedialog.askopenfilename(
            title="Seleccionar certificado",
            filetypes=[("Archivos JSON", "*.json")]
        )
        

    
    boton_seleccionar_certificado = tk.Button(login_ventana, text="Seleccionar Certificado", command=seleccionar_certificado)
    boton_seleccionar_certificado.pack(pady=10)

    label_contrasena = tk.Label(login_ventana, text="Contraseña:")
    label_contrasena.pack(pady=5)
    entry_contrasena = tk.Entry(login_ventana, show="*")
    entry_contrasena.pack(pady=5)

    def recoger_contrasena():
        contrasena = entry_contrasena.get()
        validarUsuario(contrasena)
        login_ventana.destroy()

    boton_login = tk.Button(login_ventana, text="Login", command=recoger_contrasena)
    boton_login.pack(pady=10)

    boton_registrar = tk.Button(login_ventana, text="Registrar", command=registrar_usuario)
    boton_registrar.pack(pady=10)

    login_ventana.mainloop()


    if not usuario or not contrasena:
        messagebox.showerror("Error", "No se ha proporcionado usuario o contraseña. El programa se cerrará.")
        sys.exit()

crearClavesAplicacion()

login()



ventana = tk.Tk()
ventana.title("Encriptación de PDFs")
ventana.geometry("800x600")

# Crear el menú principal
menu_principal = tk.Menu(ventana)
ventana.config(menu=menu_principal)

# Crear un mensaje de bienvenida
mensaje_bienvenida = tk.Label(ventana, text=f"Bienvenido, {usuario.upper()}!!", font=("Helvetica", 16, "bold"), fg="blue")
mensaje_bienvenida.pack(pady=10)

# Crear un frame para las instrucciones
frame_instrucciones = tk.Frame(ventana)
frame_instrucciones.pack(side=tk.RIGHT, padx=10, pady=10)


# Crear un label para mostrar la lista de archivos seleccionados
label_archivos_seleccionados = tk.Label(frame_instrucciones, text="No hay archivos seleccionados todavía", justify=tk.LEFT, font=("Helvetica", 11))

label_archivos_seleccionados.pack(pady=10)

def actualizar_label_archivos():
    if ruta_archivo:
        archivos_seleccionados = "\n".join(ruta_archivo)
        label_archivos_seleccionados.config(text=f"Archivos seleccionados:\n{archivos_seleccionados}")
    else:
        label_archivos_seleccionados.config(text="No hay archivos seleccionados todavía")

# Modificar la función seleccionar_archivos para actualizar el label
def seleccionar_archivos():
    global ruta_archivo
    ruta_archivo = filedialog.askopenfilenames(
        title="Seleccionar archivo(s)",
        filetypes=[("Todos los archivos", ".*")]
    )
    actualizar_label_archivos()

# Crear un mensaje de instrucciones
instrucciones = """
Instrucciones:
1. Seleccionar Archivos: Selecciona el archivo que deseas cifrar o descifrar.
2. Archivo de claves: Carga o crea un archivo de claves.
3. Cifrar Archivo: Cifra el archivo seleccionado.
4. Descifrar Archivo: Descifra el archivo seleccionado.
5. Salir de la aplicación: Cierra la aplicación.
"""
label_instrucciones = tk.Label(frame_instrucciones, text=instrucciones, justify=tk.LEFT, font=("Helvetica", 11, "bold"))
label_instrucciones.pack()

boton_seleccionar = tk.Button(ventana, text="Seleccionar Archivos", command=seleccionar_archivos)
boton_seleccionar.pack(expand=True)

boton_cifrar = tk.Button(ventana, text="Cifrar Archivo", command=cifrar_archivo)
boton_cifrar.pack(expand=True)

boton_descifrar = tk.Button(ventana, text="Descifrar Archivo", command=descifrar_archivo)
boton_descifrar.pack(expand=True)

boton_salir = tk.Button(ventana, text="Salir de la aplicación", command=salir_app)
boton_salir.pack(expand=True)

# Iniciar el loop de la aplicación
ventana.mainloop()