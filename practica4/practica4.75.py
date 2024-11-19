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

lista_claves = {}
ruta_archivo = ""
ruta_salida = ""
ruta_claves = ""
ruta_archivo = ""
usuario = ""
contrasena = ""
    # Define el directorio base automáticamente
directorio_base = os.path.join(os.path.dirname(__file__))

def salir_app():
    ventana.quit()

def seleccionar_archivos():
    # Abre un diálogo para seleccionar uno o varios archivos
    global ruta_archivo
    ruta_archivo = filedialog.askopenfilename(
                    title="Seleccionar archivo",
                    filetypes=[("Todos los archivos", ".*")]
    )
    
    # Si se seleccionan archivos, muestra sus nombres
    if ruta_archivo:
        messagebox.showinfo("Archivos Seleccionados", f"Has seleccionado:\n{ruta_archivo}")
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

def cifrar_archivo():
    
    datos = leer_archivo(ruta_archivo)  # Leer el archivo a cifrar
    clave = get_random_bytes(32)
    # Crear un cifrador AES en modo CBC
    cipher = AES.new(clave, AES.MODE_CBC)
    iv = cipher.iv  # Inicializar el vector de inicialización (IV)
    print(iv)

    # Añadir padding (relleno) a los datos para que sean múltiplos del tamaño de bloque (16 bytes)
    datos_padded = pad(datos, AES.block_size)

    # Cifrar los datos
    ciphertext = cipher.encrypt(datos_padded)
    print(ciphertext)

    nombre_archivo, extension = os.path.splitext(os.path.basename(ruta_archivo))

    user_directory = os.path.join("practica4", usuario)
    ruta_salida = os.path.join(user_directory, f"{nombre_archivo}_cifrado{extension}")
    # Guardar el IV y el texto cifrado en el archivo de salida
    with open(ruta_salida, 'wb') as f:
        f.write(iv)           # Guardar el IV (16 bytes)
        f.write(ciphertext)    # Guardar el texto cifrado
    guardar_clave(nombre_archivo, clave, extension)

def descifrar_archivo():
    global lista_claves
    lista_claves = leer_claves(ruta_claves)
    with open(ruta_archivo, 'rb') as f:

        iv = f.read(16)        # Leer el IV (16 bytes)
        print(iv)
        ciphertext = f.read()  # Leer el texto cifrado restante
        print(ciphertext)

    nombre_archivo, extension = os.path.splitext(os.path.basename(ruta_archivo))

    print(f"Descifrando '{nombre_archivo}'...")
    print(f"Usando el archivo de claves '{ruta_claves}'...")
    print(f"Usando extension '{extension}'...")
    
    if nombre_archivo in lista_claves:
        clave = lista_claves[nombre_archivo][0]
        extension = lista_claves[nombre_archivo][1]
    
    user_directory = os.path.join("practica4", usuario)
    ruta_salida = os.path.join(user_directory, f"{nombre_archivo}_descifrado{extension}")
    
    # Crear un descifrador AES en modo CBC con el mismo IV
    cipher = AES.new(clave, AES.MODE_CBC, iv=iv)

    # Descifrar los datos
    datos_padded = cipher.decrypt(ciphertext)

    try:
        # Eliminar el padding de los datos
        datos = unpad(datos_padded, AES.block_size)

        # Escribir el archivo descifrado
        escribir_archivo(ruta_salida, datos)
        print(f"Archivo descifrado guardado en {ruta_salida}")
    except ValueError:
        print("Error: el padding es incorrecto o los datos están corruptos.")

def guardar_clave(nombre, clave, extension):
    global lista_claves
    global ruta_claves
    lista_claves = leer_claves(ruta_claves)
    if nombre in lista_claves:
        lista_claves[nombre] = (clave, extension)
        with open(ruta_claves,'wb') as f:
            for name in lista_claves:
                name_bytes = name.encode('utf-8')
                f.write(len(name_bytes).to_bytes(1,'big'))
                f.write(name_bytes)
                
                f.write(len(lista_claves[name][0]).to_bytes(1, 'big'))
                f.write(lista_claves[name][0])

                ext_bytes = lista_claves[name][1].encode('utf-8')
                f.write(len(ext_bytes).to_bytes(1,'big'))
                f.write(ext_bytes)
    else:
        with open(ruta_claves,'ab') as f:
            nombre_bytes = nombre.encode('utf-8')
            f.write(len(nombre_bytes).to_bytes(1,'big'))
            f.write(nombre_bytes)
            
            f.write(len(clave).to_bytes(1,'big'))
            f.write(clave)

            extension_bytes = extension.encode('utf-8')
            f.write(len(extension_bytes).to_bytes(1,'big'))
            f.write(extension_bytes)

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

def habilitar_claves(ruta_archivo_cifrado):
    messagebox.showinfo("Información", "Necesitamos que nos facilite la clave privada para desencriptar el archivo de claves")
    while True:
        root = tk.Tk()
        root.withdraw()  # Oculta la ventana principal de Tkinter
        ruta_archivo = filedialog.askopenfilename(
                        title="Seleccionar archivo",
                        filetypes=[("Todos los archivos", "*.pem")] #Seleccionamos el archivo clave privada
                    )
        if not ruta_archivo:
            messagebox.showinfo("Cancelación", "Cancelando proceso...")
            return False
        else:    
            try:
                with open(ruta_archivo, "rb") as f:
                    private_key = RSA.import_key(f.read()) #Leemos su contenido y lo importamos como clave RSA

                cipher_rsa = PKCS1_OAEP.new(private_key) #Creamos el desencriptador con dicha clave privada
        
                with open(ruta_archivo_cifrado, "rb") as f:
                    encrypted_data = f.read() #Leemos el archivo de claves.bin 
            
                decrypted_data = cipher_rsa.decrypt(encrypted_data) #Desencriptamos su contenido
            
                with open(ruta_archivo_cifrado, "wb") as f:
                    f.write(decrypted_data) #Reescribimos el archivo de claves.bin, ahora desencriptado, en su mismo archivo
            
                return True
            except (TypeError, ValueError) as e:
                messagebox.showerror("Error", "Este archivo no corresponde con una clave privada o quizás el archivo de claves no lo requiera, vuelva a intentarlo")

def encriptar_claves():

    while True:
        opcion = tk.simpledialog.askstring("Opciones", "¿Desea crear un nuevo par de claves pública y privada, o desea utilizar una clave pública propia?\n1. Crear nuevas\n2. Utilizar mi clave\n3. Volver")
        if opcion == '1':
            tamanio = tk.simpledialog.askstring("Tamaño de clave RSA", "Seleccione el tamaño de clave RSA: (1) 2048 o (2) 4096:")

            ruta_archivo_cifrado = filedialog.asksaveasfilename(defaultextension=".bin",
                                                        initialfile="public_rsa",
                                                        filetypes=[("Archivos PEM", "*.pem"),("Todos los archivos", "*.*")])
            crear_RSA(ruta_archivo_cifrado) #Creamos las claves pública y privada en el mismo directorio que el archivo claves.bin

        elif opcion == '2':
            messagebox.showinfo("Información", "Necesitamos que nos facilite el archivo de claves")
            ruta_archivo_cifrado = filedialog.askopenfilename(
                title="Seleccionar archivo de claves",
                filetypes=[("Todos los archivos", "*.bin")]
            )
            root = tk.Tk()
            root.withdraw()  # Oculta la ventana principal de Tkinter
            messagebox.showinfo("Información", "Necesitamos que nos facilite la clave publica para encriptar el archivo de claves")
            ruta_archivo = filedialog.askopenfilename(
                    title="Seleccionar archivo",
                    filetypes=[("Todos los archivos", "*.pem")] #Seleccionamos el archivo clave publica
                )
            if ruta_archivo:
                try:
                    with open(ruta_archivo, "rb") as f:
                        public_key = RSA.import_key(f.read()) #Leemos su contenido y lo importamos como clave RSA
                    if public_key.has_private():
                        messagebox.showerror("Error", "Esta clave publica no es valida o puede no ser una clave publica, intentelo de nuevo")
                    else:
                        cipher_rsa = PKCS1_OAEP.new(public_key)
            
                        with open(ruta_archivo_cifrado, "rb") as f:
                            datos = f.read()
                        
                        encrypted_data = cipher_rsa.encrypt(datos)
            
                        with open(ruta_archivo_cifrado, "wb") as f:
                            f.write(encrypted_data)
                        break
                except ValueError:
                    messagebox.showerror("Error", "Esta clave está corrupta, intentelo de nuevo")
            else:
                messagebox.showinfo("No se seleccionó ningún archivo", "No se ha seleccionado ningún archivo.")
        elif opcion == '3':
            break
        else:
            messagebox.showerror("Error", "Opción no válida. Inténtalo de nuevo.")

def crear_clave():
    def seleccionar_metodo():
        metodo = tk.simpledialog.askstring("Seleccionar método", "¿Qué método de creación de claves desea usar?\n1. RSA\n2. Kyber")
        if metodo == '1':
            crear_RSA()
        elif metodo == '2':
            crear_kyber()
        else:
            messagebox.showerror("Error", "Opción no válida. Inténtalo de nuevo.")

    seleccionar_metodo()

def cargar_claves():
    global ruta_archivo            
    if ruta_archivo:
        global ruta_claves
        ruta_claves = ruta_archivo
        result = tk.simpledialog.askstring("Seleccionar método", "¿Este archivo está encriptado con (1) RSA, (2) Kyber o nada?\nSeleccione 1 (RSA), 2 (Kyber) o (3) nada")
        if result == '1':
            correcto = habilitar_claves(ruta_claves)
            if correcto == False:
                ruta_claves = ""
        elif result == '2':
            correcto = desencriptar_kyber(ruta_claves)
            if correcto == False:
                ruta_claves = ""
        else:
            messagebox.showinfo("Información", "No se seleccionó ningún archivo. Crearemos un archivo de claves nuevo...")
            ruta_claves = os.path.join("practica4", "claves.bin")
            if ruta_claves:
                with open(ruta_claves, 'wb') as f:
                    pass


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
    #Creamos el certificado físicamente en el directorio para el usuario
    ruta_certificado = os.path.join(directorio_base, f"certificate_{nombre}.json")
    with open(ruta_certificado, 'w') as cert_file:
        json.dump(certificate,cert_file, indent=4)

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

def validarUsuario(certificado, contraseña):
    global usuario
    global contrasena

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
                    
                        lista_user["signature"] == certificate["signature"]


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

def encriptarArchivosUsers(lista_usuarios_encriptan, lista_rutas_archivos, rutasalida):
    leerUsuariosApp()
    lista_claves_cifradas = {}
    ruta_salida_cortada = os.path.dirname(rutasalida)
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

def desencriptarArchivosUsers(lista_rutas_archivos, rutasalida):
    leerUsuariosApp()
    ruta_salida_cortada = os.path.dirname(rutasalida)
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

            for user in lista_claves_cifradas:
                for user2 in lista_usuarios:
                    if user == usuario == user2['user']:
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
                        print("Usuario validado para desencriptar")
                        
 
                
            #print(lista_claves_cifradas)
            #print(extension)
            #print(nombre_archivo)
            #print(iv)
            #print(datos_cifrados)





def salir_login():
    ventana.destroy()
    global usuario, contrasena
    usuario = ""
    contrasena = ""
    login()


def login():
    def registrar_usuario():
        def guardar_usuario():
            nuevo_usuario = entry_nuevo_usuario.get()
            nueva_contrasena = entry_nueva_contrasena.get()

            # Asegúrate de que el directorio base existe
            if not os.path.exists(directorio_base):
                os.makedirs(directorio_base)

            # Ruta del archivo de usuarios
            ruta_usuarios = os.path.join(directorio_base, "usuarios.txt")

            # Verificar si el usuario ya existe
            try:
                with open(ruta_usuarios, "r") as f:
                    usuarios = f.readlines()
                    for usuario_linea in usuarios:
                        if "," in usuario_linea:
                            usuario_guardado, _ = usuario_linea.strip().split(",")
                            if nuevo_usuario == usuario_guardado:
                                messagebox.showerror("Error", "El usuario ya existe")
                                return
            except FileNotFoundError:
                pass

            # Crear el directorio para el nuevo usuario
            user_directory = os.path.join(directorio_base, nuevo_usuario)
            if not os.path.exists(user_directory):
                os.makedirs(user_directory)

            # Generar claves RSA y guardarlas en la carpeta del usuario
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()

            ruta_privada = os.path.join(user_directory, "private_rsa.pem")
            ruta_publica = os.path.join(user_directory, "public_rsa.pem")

            with open(ruta_privada, "wb") as f:
                f.write(private_key)
            with open(ruta_publica, "wb") as f:
                f.write(public_key)

            # Guardar el usuario en el archivo de usuarios
            with open(ruta_usuarios, "a") as f:
                f.write(f"{nuevo_usuario},{nueva_contrasena}\n")

            messagebox.showinfo("Registro", f"Usuario registrado con éxito.\nClaves guardadas en: {user_directory}")
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

    def verificar_credenciales():
        global usuario
        usuario = entry_usuario.get()
        global contrasena
        contrasena = entry_contrasena.get()
        try:
            with open(os.path.join(directorio_base, "usuarios.txt"), "r") as f:
                usuarios = f.readlines()
                usuario_encontrado = False
                for usuario_linea in usuarios:
                    if "," in usuario_linea:
                        usuario_guardado, contrasena_guardada = usuario_linea.strip().split(",")
                        if usuario == usuario_guardado and contrasena == contrasena_guardada:
                            messagebox.showinfo("Login Exitoso", "Has iniciado sesión con éxito")
                            usuario_encontrado = True
                            login_ventana.destroy()
                            return
                if not usuario_encontrado:
                    messagebox.showerror("Error", "Credenciales incorrectas")   
        except FileNotFoundError:
            messagebox.showerror("Error", "Archivo de usuarios no encontrado")

    # Ventana de login
    crearClavesAplicacion()
    #registrarUsuarioApp("adrian","prueba2")
    #leerUsuariosApp()
    validarUsuario(os.path.join(directorio_base, f"certificate_adrian.json"), "prueba2")
    #lista = listarUsuariosEncriptar()
    #verificarUsuarioSeleccionado("adrian")
    lista_a_encriptar = ["david", "adrian"]
    lista_archivos = {os.path.join(directorio_base, "usuarios.txt"), os.path.join(directorio_base, "usuarios2.txt")}
    ruta_out = os.path.join(directorio_base, "usuarios.bin")
    lista_ruta_encriptados = {os.path.join(directorio_base, "usuarios.bin"), os.path.join(directorio_base, "usuarios2.bin")}
    ruta_out2 = os.path.join(directorio_base, "usuarios.bin")
    encriptarArchivosUsers(lista_a_encriptar, lista_archivos, ruta_out)
    desencriptarArchivosUsers(lista_ruta_encriptados, ruta_out2)


    login_ventana = tk.Tk()
    login_ventana.title("Login")
    login_ventana.geometry("600x300")

    label_usuario = tk.Label(login_ventana, text="Usuario:")
    label_usuario.pack(pady=5)
    entry_usuario = tk.Entry(login_ventana)
    entry_usuario.pack(pady=5)

    label_contrasena = tk.Label(login_ventana, text="Contraseña:")
    label_contrasena.pack(pady=5)
    entry_contrasena = tk.Entry(login_ventana, show="*")
    entry_contrasena.pack(pady=5)

    boton_login = tk.Button(login_ventana, text="Login", command=verificar_credenciales)
    boton_login.pack(pady=10)

    boton_registrar = tk.Button(login_ventana, text="Registrar", command=registrar_usuario)
    boton_registrar.pack(pady=10)

    login_ventana.mainloop()


    if not usuario or not contrasena:
        messagebox.showerror("Error", "No se ha proporcionado usuario o contraseña. El programa se cerrará.")
        sys.exit()

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

boton_cifrar = tk.Button(ventana, text="Archivo de claves", command=cargar_claves)
boton_cifrar.pack(expand=True)

boton_cifrar = tk.Button(ventana, text="Crear clave", command=crear_clave)
boton_cifrar.pack(expand=True)

boton_cifrar = tk.Button(ventana, text="Cifrar Archivo", command=cifrar_archivo)
boton_cifrar.pack(expand=True)

boton_descifrar = tk.Button(ventana, text="Descifrar Archivo", command=descifrar_archivo)
boton_descifrar.pack(expand=True)

boton_descifrar = tk.Button(ventana, text="Logout", command=salir_login)
boton_descifrar.pack(expand=True)

boton_salir = tk.Button(ventana, text="Salir de la aplicación", command=salir_app)
boton_salir.pack(expand=True)

# Iniciar el loop de la aplicación
ventana.mainloop()