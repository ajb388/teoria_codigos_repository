import os
import tkinter as tk
import customtkinter as ctk
from PIL import Image
import base64
import json
from hashlib import sha256
from kyber.kyber import Kyber512, Kyber768, Kyber1024
from Crypto.Hash import SHA256
from tkinter import filedialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from dilithium.dilithium import Dilithium2
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
    #seed = os.urandom(48)
    #public_prueba, private_prueba = Dilithium2.keygen(seed)
    #print(public_prueba)
    #print(private_prueba)
    
    private_app = b'\xe8N%\x8f\xb8\xbf\xe3\x11\xab\xc0\xd5\xcd\xa8\xac<\x806\xf2\x12M\x86\xa5\xc9\x1f\xb0d\xfd\x00E0\xb9\xab\x0fCyNL\x07@\xd0\x13\x08dH\xce\x19\'\xe0\xf9Y?\x84X\xdb\x17&\xb6\xf5]\xc4\xde\x91\x80\xfa\x924\xed}Y\xeb\x82\xdd\x1a*\xb6\xf0\x15\xf4\xddbP\x87CHZU\x1e\xb7\x1c\xf2\xeb\x94cJ1s\x0b#N\x18CiD\xb6\tB\xa0\x90\x0cEA\x89\x02r\x98\x08MD\x04E\t#H\x80\x08\x00#1b\x02\x192a\x04FR\x90l\x93\x84L\x8bD!\xc9\x92H\xdb\xa4Dc\x12p\xc0\xb8\x01\x83B"\x98 aP\xb2p\xd3\x14p\xd3\x16N\xd4\xa6)\x02\x17\x88\xa3&,\x12\xa0\x89\x19\xa9\x84\x90B\x90\x03\xb0qI\xb6-KFDB\xc2I"3)\x01\x06\x90\x04\xc1!\x1c%\x80\t\xb4l\xc0Ba\x0b\x07Lc$P\x8b\xa4\x88\xdaD)\x08\xc4\x80\x01\xc4\x89\x04\x13j$\x02\x8c\xa0\x90\x00"8\r\x114J$\x80H"&\x8c\x88\x00R\xc3\xa2M\x99\xb0$\x08\x94\x84\x1a\xb1id\x90`\x1c(\x84\x0b\xb8\x80\x10\xa1 \x089q\xc9\x02\x91T\x02$\x0b\xc0 \x90\x04A\xd4\x12\x05\x0b\x02r"!\x85\x14(\x8eD"\x12\xc1\xc6a\x031)\xd02R\x82\x04-\xe3\x94@@ \x90A\xa0\r\xc0&Q\xc4\xa2D$\xb4i\xe1\xa4A\xa1(\x0e\xc3\xc8 R\x02b\xe3\xc8%\x19\tF\x8a\xa4 \x8a\xc0\x11\x0b"q\xd8&)\x1b7\r\xa1\x10l\xc0\xc8\x81\xa0\x88a\x014&\xcb\xa2\x91\xe4\x10)\xd1\x12(\xe1\xc8P\xd36\x86\x12\x17\x02\x82@@\x0b\xa40\xc4\x14@\x00\xa7p\xc2\x02i\x02\xc0%\x1b@r\x9c\xc2E\x88\x841\x88@N#\xa0\x05\x04\xa0D\x8c\x04A \xb0 b \x82\n\xc0\x10L$ \t\xc6a\x12\x16"\xe3\xb2mQB\x8ea\xa6Eb\x88\x84c\x02.\x91\x02\x08\x18\x19h \xb6\x91\x84\x18La\x16\x00\x80(`D\x90L\x842\x08\nF$\xd4\x88I\x1c7\x00\x13F\x80J\x18M\x1a\x00H \x16\x88\xe1\xa6e\x18\x87e\n\t\x0eZ \x11\x04@\x05b0,\x1b \x89\x1bFF\x08FDC\xc2\x81\x1aFd\xe22(\xca\x00n\xd0D&\t \x89\x1c\x81\x04\x08Hb\xd9@a!\x92p\x80\x06\x84\x99(\x04\x13#H\xc1\xb6\x91\xe20\x84\xdb\x82a!)F\x04\xc4\x05\x14!e\xc1\x88\x04!\x16\x04\x91\x90E\x028.\x11\x060\x80Hr\x08%)\xe1F%\x8c($\x192\x02"\x99\x8c#)l\x94\x08\x06\x1b7ld\x10\t\x844\x01\x11\xc6qQ\x00p\\\x82(L\xa2,AD\x8e\n\xc4\x10b\x84DTD\x80\t\x10I$H\x80\x00I\x08\t!\x90\x1b\xa8\x04\xd2\x06\x0e\xd9\xa4\x80\x10\x90 \x0b\xa5\tK\x82E\x82\x06\x06\x18\x82Q\x93\x98Q\xda@\x00\xcbB\x90\x8a\xc6@Y\x00p\t\xb1\x91\xa0\x12\x8d\x00@\x8ab\xa4a\x1c0\x80!H-J\x94\x00\n\x18b\x03\x85\x00\n3\x12\xe0\x16AB\x00\x04\x91\x02"\x00He\x8a\xa0P\x89$`\xa02.\x99(\x0c\xa3\x04DH\x88i\x03\xc9L\x1b\xa8\x01A\x96(\x10\x00(D2db\x940\xa2\x08\x82\x89@E\x02\x15\x05"\xc4\x80\x123\x08\x04AI\xdb\xb6Q\x0c\x98DKB\x8e\t\xa9\x91\xdbFe\x0b\xb6\rT\x94D@\x18iS\xb2M\x92\xc8E\xdb\x90%\x9c\x00\x82GD2~\x08TTO7\x85\xb7\xd7QG\x17<W\xcc\x88 \xbc\xbd\xa0\x84\x14\xe5q\x85\x9a"JL\xac\xf0b\xc9\nJ\xa7\xfd.\xa5[\xeaA\xee[\xf6\xf5\x16\xcc\xdb\xa6\xca#\xbb\x97\xe4RV\x80Zh\xe6(\xbdjay\x97\xa3\x07\xfb\x85J\x8fA\xd1m*\xfbD\xce\xbd3\xf1\x0b#\r\xe3\xfd\x85\xb8\x03f\n\xd1\t\x9f\x10.O\x08\xa2uM&\xcc\x8e\x14_\xa67\x9f~+\xda\xfdE\x80\xa2\xdd?\x10\xd7pF\x8fc\xaa\x17\xef\x17\xa8\x98\xc7\x1b&\xb7H\xc7^\xb6\x15\xd5\xdcO\xd1hC)h\xd6\x1f\xd1Sm\x07D\x93\xa8R\'\xc5\x87\x11{\xdeb\xf3\xa7s~\xec\xa9\xaf*\xda\xe6g"\xbb\x0e\xb9]\xe1@\xdd\x83|\xab~my~\xf5"\xc9 \x0eF\xc9\xf3c\x92A\xccS\x194e\xad*\xd3\'\x19\x94\xf9+\xcd\x8f{\xa2\xc0\xbbs\xf6!\x1a\x970\x17\x0f\x05,%(\x19>\x83\xbf7m\xdai\xa7\xb1Jt\xc3\xa1\xfd\xe710xe\xf9\xea\x9fA\xcd\xa5\x02j\xaa\xc1M\xa3\x12\x0b\x90Jm(s\x1bY\x11\xbb#\xdd\x83 \xc74_\x15,m\xbaeO\x81T\xdc\x80D\x88El\xe0\xc1W\x15\xf0\x1c\xc6G\xc2\x04\xb7\xc2~\xec\x8c{\x1b\xc1\\\xd8\x7f\xc3\xadk\xac\x86\xe65\xd6I\xe8\x18~\x8fc\xf7$\x15pO\x94~{\x02\x95T\x9bA\xe4\x1b(\x06eY\xea\xa8u\xcfUA\x13\x0c\xda\r\xe0\x92\x07Y\xd6\xb8q\n\xe1\x1f*\x9e\xd0\xd7\xf0\x87uyjo\xdb\x1e\x8d\x10c\xcf7\xd8`\xaaOU\x92\xab6P\xcb\x1b]g\xe7Kh;&\xa1N\x8c\xd6J\xe8\xd2\x0b;\x8f\n\x8a\x87#|\xea\x82\xfd\xe3\xc1\xf5u\x00\xb7\xaa\x02.\xcf\xca\x9d8y\x8f\xa2R\x8c\x01\xda\x9e&#\xcf\x85\xcd\r\xb7j\xdb\x10\x8f\xd2\xaca\x121\xaf\xb3\xce\'\x9f\xd5\xd1\xd8\x9b\xeb\x96\xe4^\xab\x10FWv\xf2\xc4C\xde\xec\xc8\xc1\x87\\\xc4z\xf2wP]_\x0f\x00\xc1p\xab{-\xa7A\x0f\x7fl\xee\xd1S\xd7\xceF>\xe9)\x8e\x16\xfb\xe6\x8f\xa78\xe1\xe71x\xc2\x8f\x8ew$G\x95\x87\x81z#\xc7:s\xd3\x16\x84\xb4\x9d\xb9\x06\xaf\xa1\xb2/\xf4o\x8d\xac\x98\x9a\xefng\xfd\x00\x9b\xefe\x8d\x13\n\xd1)\x98\xc9\x11I\xb3\xcf.\x06\x8cb\xac\'\x9c\xf5l\xd9\x17-\n;\xe1\x89\xb90\xc5r\x1em\xf5\x98m\xa3\x13\xc8\x98\xdd\x1e\xfb\xaf\xe8%H\x1c\x87L\x93\xfd\\<s\x8fJ\xae\x95"\xaf\xc1\x9cRjI\x0f\x0e\xbe\xf4p\xfbx\x80*\x97<\x94\x85\x12G\x14uc"M\xf0/\x0f\xe5\xb2\xfe\xa8\tIF!L\x13<\xd7$\x1b\\\xb5\xb8\x9a\xaaA\xed9\xa3\xd2\xc0\x9c+U\xe2\xa1V\xb8Y\xcf\x85\xec\xec\xcf\xf7O\xd19\xac\x93X\xe2\xfcm~\x9f\xa5n\xf0\x8e|\xdb;\x80L\xabPV\xf1GSw\xcaL\x82fT\x9d]\xcf\x0cp\xed\x04g\x8c\x83\xd1\x04\x90;\xabMF\r\xc9\xed\xc3Tb\x13\xdf\x16\x01.\xb8\x82aC\xf7\x18<4X#\xces\xac%)W\x9ajf\xd5\x0c\x81Ms\xbc*\xe8D\x92\x03\x9912P}\xec\xe9\x86\xb5\xceWL\xf6\x98\xe7\xd1\xb9\x17\x90\x06n\xf2%*[~\xdc\x8e7\xbb*\xd8\xd3?;\x83\xc2T\x9al\t\xde\xd5\x01\xca\x84 vsF\xd1v>\x84\xa8\x90HP\xb2m\x1c\xe8\x8a@\xa7\xea\xc7Y*\xa9\x8b\x83\xbc\xec\xed\xc0\xc4wt\xcb\rS1\xa7+\xfe%1\x06\xdf\xffr\xb1f\xb5\xe6\xf6\x13\xb6\x88\xa9\xb3\x8dh\xd6|\xc5\x82\x06\xc1&u\xf6R\x8a\x8c`) \xa0"0\x1e9q\xfc]b\x81\x9fV\xcc\xd8\xea\xebD\x0cX\xae\x9f9\'1k\xcd\x9e\xf6\x83x\x88\x18\xec~\xbaD\x9c\xf8u\xb5\xceS3\x12Q\xfe\xcd\x07\xbc.Y\xb5FcL\x83%\xfe \x1a\x80c\xc0\xe0\xc2\xdc\xc8%,\xad\x8e\xa0 \x86\xf8\x0fkh\xad\xb0W\xe2\xd4\x10\xdd\x9dCt\xe0\t\xeb5M\x83\x1c\xb4I\xf4\x89\x86<w\xe7\xdd\xa3G\xb0\x02\xfb\xcd\x98\xbb\xb3uE\xb9H:\xe6\x12\x84\xbb\xc0\x1e\xec\xf8=\xf0\xa8!\'>\xfc\xb6\xc4l\xa6C+\x9e\xa1\xdf~\x05\xb0\xf4\xca\x16\xc3\xc2\xf2\x8d\xf5\xd6\xa7\xca\xc6`\xbeG&\xad\xf7jB\x0f(>\xc9\xc8\xbbx\xb6-\x96y\xe5\xb8\x7f?\xfe2\x10$\xdbi)\x84\xad)_<\t|\xae\xf6\xde\x8e\x93Y\x04+\xc0\x07\xea\xe9\x02\x84\x11j\xec\xc9\x0c\xb8\x06~\xf3@\x0e\xe6O&r\xb8\x8a\xa83T\xa1\x7f\xe4\x05SX\x8cG\x8c> \x1dOZ.\x04l\xb5^1\xb8t\xe6d\x93s\xd5\xd7}C\x98o6A\xd7\x08\x8c\xf7\xf2\xd6\xdf\x08d$\nP\x7f\xfb\xcd\xd9-\xfdq[\x11\xbbJ`\xb1C\x041&\x9b\x0e\xf8y`\xb0\x8e\x92\xefO&=\xb7\xbb\xfaS\xdc\xa3\xcbq\xae\x9dS\x90@^8\x1f\xf2B\xc4S3\x84z\xb0\xa6\xb3?A\x85\xbc\xc9h1aC\x14\x05\xc6\xa2\x9e\xff\x84\xaf4\x81\xc3\x9f\xdd\xd4O\'\x19\xa4\xca\xe7\xd85\x06\xeb\xb1\xfbW\x0f\xb2\x0c*\xe1dj\xca\x9b\xabw\xf9\x92\x19\x18f\x0e-\xa8\xa9F\xf0t\xd1\xe5\xe2\x19xF\x95f\x86\x9a\x10\x8c\x9e6\xc7\xb5\xc6\xd0\xac\x95q\xf3\x14\xbe/\x12\xd1-:\x9e\x83\xa0}\x92\x83\xdc\x88sfMO\xf5P\xfa\x92D\\0\x92\xcb\x11\x8a\x7f9\xcfT\xd9EN\x0bt\xaa\xc0\xe3x\xd2>\xcc\xb3\xd3|\xd1T\x19g\xfa(\x04#\xa7z\xeb\x0br\xfa\xf8\x1f<\xe0/?R\xcd\x14\xc3\x02\xea\xf7\xe9\xc4\xf1-\xef\x07\x8fd\xff\xd1P+\x07\n\x07*\x04\xe3V@\x0e\xa9\xbd8\xffI\xf7C$!\xb1F\x0c\xdc`D\x1ac\xe0\xb1e\x9b\xd4\xdc{\xae\x17\x83\xb5$f\xba\xb2\xa5PO{7\x94\xc7P\x80>\xa5\xd1\x86\xd5\rw\x05lQ\xa0\xcd\x11;\xfbUF)\r\x05\xf9\x85*\xf5[M\xe4\x9aL\xe9\xae\x0b\xd9[ \x12\x1e\xbe\xb1a\x8d.;\x86f\xca\xe2\xdai]^\xff\xf6\xa8\xf9`:\xe0IE\x99\x9c\x98vI\xbc\xed\xa0\x07\n\xbb\x83\xc8\x14\xdfv^\x13\x19\xacF\xc4[\xcf\x8d\xca\xb7!\xca\x1b.\xf0\xf6"\x9b\x8flpi\x1cS\x10\xff\xc8\xd1\x1e\x8c\x9c4\x1f\xac\x0b|*\xebv\xfd7\x92pV\x1a\x13\x06b\xa2\xd3,\xdan\x86"\x80=\x02[\xbf\xb7\x828\xa20\xedm\xa5\xa3Ms\xe2\x83\xcd\x8e\x0f\xd5\x1bb\xd4\tN\x96\xa7c+s\xb6yk\xa8\xf8\xf3Y1\xf0\xea\x0b\x89\xb4p\xae\x8b\x85\xfc8\xb0y\xe7/k\xa6\xd6\r\x9b\x9e\xc0\xeb\xd2\\k\xba\xf2\x0c\x82L,\xd3g\x9fv\xcb'
    public_app = b'\xe8N%\x8f\xb8\xbf\xe3\x11\xab\xc0\xd5\xcd\xa8\xac<\x806\xf2\x12M\x86\xa5\xc9\x1f\xb0d\xfd\x00E0\xb9\xab<\x0bY\x04\x9f\x81\xb0\xe0-j\x1a\x8c\xcf\x99Y\xd6=\xf5\x00\xdc#\x013\xab\xd63\xb6\x13\xc2\xb7\x0c\xe4P\xf2]\xb4\x8cv\xeb(\x88\x83\x96J\x99\x12b5Y\xdd\xfd\xce\x8d\x12G\xcet\x8fl\xc6\x13\xe8\x8a\xd7J\xb0wL\x0c\xb8\xdb;\xbd\xbd\x1fI\xd5\xfa2\xa6\x0cU\x8a\xcf\\\xb9T\xa9\xc8\xd3\xb6)\xbe\xab\n\x05.Y\xb7a)\x9e\xa6\xb1b\x87X\x7f\x9d\xa9R\xa3\x92v*\x95\xe5\xd4\x8a\xda\x18g\x1b\x91\xd0e\xdam\x14\xbaf\x02R@O/\x16\xc7\xee\x94zA)<\xd7\xcbV\xf6s\xca\x0b;,\xd7\\\xd6%\x07\x9bk\x13r\xc5SK\x89i%H\x05\xa8cV\xf9\xf4H\x03\x9f\xe4+\xb7\x97\x84\x0f\x12\x11\xc9l\xcc>\x8fs\xb9b\xa7\xd12\xd0\x90C\x16\x01\x84K\xc2\xa8\'|05\xc8/\x9aT\x0e\x92\xd5Q+ \xaf\xd1\x14\xc6\xf6\x98;\x9f\xaf\xe93\x1dx\xb6\xf8q_H\x1f\xbeK\xf8\xcb\xea\xe9\xb9\x8a{\xc8\xf5W"\xb1Q\t\xef\x0c\xb1W\x13k\xb2\xf4\x18=+(\x1e\x15\xf2\xcd\xbc_\xe1t\xd3Sk\xc4\xef!\x84E\xb1\x16\xa6\xf5\xf9\xde%\xada\x0c\xcd\x80\x08\xe3\xabE\x9d\xb5\xd0AX\xa4\xc2\xe6P\xe7A\x1d\x90\xbb\x9a\x056\x01M\x8b\xb2Iv~\xe7\x08\x08\xf4\xc9\xbb\xb8\xfb\x92\xa3]\x1a\xc5\x9f\xaa\x9c:\xff\x84AEL\x1c\x17\xee\xff\xe6\xbf\xb3\x12=\xa5{%\xc7ZT\xdf\x8f\xce\x13\xc8\xc9\x88\t\x15\x080\x7f\xfe\xea\xc3Q9k\xfc8ko\x01\xf9%H0:\x13\x1d\xc5\x861\xffAv\xe9Pt\xfcx\x06\x88\x88\x1a\xf3\xe6\xc0\xedw)j4\x80/\xf0\xd3\x05q6\x90\xb7\xe0\xf7\xab\xe2\xa6\xf0(\x9aqo\x8d\x1f\xd0\xf4\xa0\x17\x82\x86`7\xfa/rZs\xa3\x0c"\x97\x18O\x1f2\x0es\xc1\xcf!u\x1fSU\x91\xdf-\xf4\x90\x00@\xff\xd5\xdf\x17\xef\x0cb#\xa0\xb2\xf2\xbc\xe6=\xd4\xc7\'G\x83\xc2\x14\x1d\xca\x82\xc2K\xfc\x9b\x01?I\xf6\xde\xc2\xea$m\xb6\xa6,+;\xf6]\x8b\xf2\xa6\xeba\x1a\x10\xb7\x87A\xb4\xa7\xa0(,\xe9\xc1\xdbQx\xacB4\x18!\xa1]\xbf\xf7v\x8a\xf4m\x98\xe1\xc9aW\x0c\\\xae\xe1\x858\xd4\xbc\xb4\xa2\xf3\x10\xbd\x95an\xfb8\xbc\x1em\x87V3Y\x8b\x86\xef\x17\x80\x93\xf6BA\xed\x19\x92j\x91\x97\xb8:t"\xe0\xeb\x08\xf9\xc4z\xf0\xb6\xdb\x98qz(\xd4&\x05~\xfe\xfd\x83\xeaKFd\x91;C2\x8e\xc8\x1cz\xbc\xd2\xec\x96\xcda\x13#.\xdf\x87./;\x14g\xe3?\xfa\xab\x06^\x0b\xcd\xe9\x89t\xb3\x12\xebe\xaf\\m\xb5\xdc<T\xdd@\r\x94\xbbL\xf0\xf2\x10\xaeMZ\x06\xe1E\x8d\xcb)\xfd>(\xf9j\xb3a\x89\xc7\xbbm\xbfi$X\xff\xde!\xe1\xe3\xe7,WA\x9a\xeb\x1c\xfd\xfd\xb3\xdd}\xc3/\xb30\xb2b@L\xdf\x1f:\xa6wp\x08\x7fR\xafH\x8blS:~/3!i%C\x1d^\x97\x98\xd4\x0e\xa0\x82\xb51\xdaRt\xf5\xf7\x9c\xecD\xadm\xce\xbaG\xcd\x0c\xbc\xee\xb6"\xa6\r\xca\xd55\x16\tJ\xf0\x9eB\x10&!\xbe\x93\x95\xb6X\xedC\xb0\x02\x01O\xc0I\x02{o\xf5\xa5\xef\xb98(\xe2\xb4\x91\xb7\xe2fq\x9c\xaa7\xdeQ\x16\x03\xd5s\xb1\xd0]\x1d\x17w\x9bi\x9a*=\x01i\x1d\xfc\xac\x04h\x97\x84V\xc2\xb0\x04\x92\x86gg\xad\xcc}0\xf1\xeb\xdc *\x01\xd4\xbb\xfe\x17U:\x9aM\xfb\x7f\x84\xbf\xbc\xe9\xa5\xe8\x16\x149^\xec\xec\x17j\xd0iY\x17\xd6\xb9\xb04\x10\x9b+\xd9\x8b\x88\x1f\x03\x9b\x1b\xb4\xc4I]h\xee\xf8\xb6s\xa3\xe0\xd9\x94-\xf5v\\#\xa6X&\x16\x85$P!\x03x4)5\x1aoh\xc0\xdc\x91w\xd5\xaf\x86\xb2\xa4\xdb\xdb\xc7=\x08\'\xe5\x17tH\x85\x05\xb9\xc5\xba\xd2 C\xc5\xaf!t\xa0)\xfa\xd3\x8e}\xe3\xb7\xc7\xd72\x0e\xa24\xa9\xd9\xb1\xe8f\x17E0_\x9d\xdf\x17C\xeaW7Z\x7f\xc8\x150\xbb\xa4\xa6sC\x11\xb7\xabO\xf4\xef\x0e\xfa\x032\xdd>\xab\x80\x882\xc2\xff\xa9\x80\xa2\x17%\xbb\x9a<Ww\x96\xf6Y\x19\xa9\xc5t\xa8\x88z\xbd\xfb\xad\xc0\x96\x98\xdf\xd1\x0c#\xc7\x00FI\xfa\xdbIF\x81Q\xa9^z\x7f$\x82\xac\xa8\x1f\xf1G\xaayG\x9b\xbc\xc9|\x17K[\xcc\xc8\xdf\xd5\xbd\x10\x16l\x84V\xf2\xd8Wo\x84E\xaa\x00\xf1\xb8\xdf\xf59WR\xd6\xa5pl\xf2\x97\xf0/9 \xc4~oq\xe2\x80E\xdcS\xe76\xc0\x91\xeb\t\x12Aq\xbbL5Mu\xda\xd8\xf4\xf9\xaf\xa4\xa4\xcec\xf2\x80\r\xf5\x81{\xcc\xa6\xb2%\xae\xeb\xc9\xed\xfc2\x8aj@>\xfe\xce\xc8\x96\xb7\xe2>\xcc\xb5\x88\'\x8d>\xb5\xcd>\xa4t\xf4fyC\xb8w\xba\'\x1ffE\xf5!\xd9\x07\x13\x93\xa7qc\xd0\xfb}\x8c,VY5\x8b\x81pk\xd9(X\x92\x14\x06\xbfo\xd4\xe1\xf8F\xc3\x02\x17J>3F\xee>\\-\x04\n\x9c\x83\xde\x0c\x99zg\x99mp\x18\xe8\xb8/\xe7.\x9fL\x18\xcb\xe4\x0e\x99\xef\x03\xfe'
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
    #else:
        #private_app_bytes = private_app.export_key()

    salt = get_random_bytes(16)
    derived_key = PBKDF2(clave_aes_app, salt, dkLen=32)
    cipher = AES.new(derived_key, AES.MODE_CBC)
    padded_rsa_key = pad(private_app_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_rsa_key)
    private_app = salt + cipher.iv + ciphertext

def registrarUsuarioApp(nombre, contrasena, metodo):
    global private_app
    if metodo == 1:    
        key = Kyber512
        public_key, private_key = key.keygen()

        #encriptamos clave privada del user con su contraseña
        salt = get_random_bytes(16)
        derived_key = PBKDF2(contrasena, salt, dkLen=32)
        cipher = AES.new(derived_key, AES.MODE_CBC)
        padded_rsa_key = pad(private_key, AES.block_size)
        ciphertext = cipher.encrypt(padded_rsa_key)
        private_key = salt + cipher.iv + ciphertext

        hash_object = SHA256.new()
        public_key_base64 = base64.b64encode(public_key).decode('utf-8')
        public_key_base64 = base64.b64decode(public_key_base64)
        datos = nombre + " " + public_key_base64.hex()
        hash_object.update(datos.encode('utf-8'))
        hash_bytes = hash_object.digest()
        #este es el hash del nombre y la clave publica del usuario para la firma del certificado
        #firmamos el hash con la clave privada de la aplicación
        desencriptarPrivate_app()
        #private_app = RSA.import_key(private_app)
        #signature = pkcs1_15.new(private_app).sign(hash_object)
        signature = Dilithium2.sign(private_app, hash_bytes)
        encriptarPrivate_app()
        public_key_base64 = base64.b64encode(public_key).decode('utf-8')
        if isinstance(signature, tuple):
            signature_bytes = signature[0]
        else:
            signature_bytes = signature

        if not isinstance(signature_bytes, bytes):
            raise ValueError("Cagamos")
        signature_hex = signature_bytes.hex()
        #Creamos el certificado del usuario
        certificate = {
            "user": nombre,
            "public_key": public_key_base64,
            "signature": signature_hex
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
    elif metodo == 0:
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
        hash_bytes = hash_object.digest()
        #este es el hash del nombre y la clave publica del usuario para la firma del certificado
        #firmamos el hash con la clave privada de la aplicación
        desencriptarPrivate_app()
        signature = Dilithium2.sign(private_app, hash_bytes)
        encriptarPrivate_app()
        public_key_base64 = base64.b64encode(public_key).decode('utf-8')
        if isinstance(signature, tuple):
            signature_bytes = signature[0]
        else:
            signature_bytes = signature

        if not isinstance(signature_bytes, bytes):
            raise ValueError("Cagamos")
        signature_hex = signature_bytes.hex()
        #Creamos el certificado del usuario
        certificate = {
            "user": nombre,
            "public_key": public_key_base64,
            "signature": signature_hex
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
    else:
        return

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
            try:
                usuario = certificate["user"]
            except TypeError:
                return

            for lista_user in lista_usuarios:
                if lista_user["user"] == usuario:
                    try:
                        tipo_clavebase64 = lista_user["public_key"]
                        tipo_clave_key = base64.b64decode(tipo_clavebase64)
                        tipo_clave = RSA.import_key(tipo_clave_key)
                        if tipo_clave.has_private():
                            print("Clave privada")
                        else:
                            try:
                                public_key_user_base64 = certificate['public_key']
                                public_key_user = base64.b64decode(public_key_user_base64)
                                comprobante = certificate['user'] + " " + public_key_user.hex()
                                hash_comprobante = SHA256.new(comprobante.encode('utf-8'))
                                hash_comprobante_bytes = hash_comprobante.digest()
                                certif=bytes.fromhex(certificate['signature'])
                                Dilithium2.verify(public_app, hash_comprobante_bytes, certif)
                                    
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
                    except ValueError:
                        try:
                            public_key_user_base64 = certificate['public_key']
                            public_key_user = base64.b64decode(public_key_user_base64)
                            comprobante = certificate['user'] + " " + public_key_user.hex()
                            hash_comprobante = SHA256.new(comprobante.encode('utf-8'))
                            hash_comprobante_bytes = hash_comprobante.digest()
                            certif=bytes.fromhex(certificate['signature'])
                            Dilithium2.verify(public_app, hash_comprobante_bytes, certif)

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
                tipo_clavebase64 = user["public_key"]
                tipo_clave_key = base64.b64decode(tipo_clavebase64)
                tipo_clave = RSA.import_key(tipo_clave_key)
                if tipo_clave.has_private():
                    print("Clave privada")
                else:
                    try:
                        public_key_user_base64 = user['public_key']
                        public_key_user = base64.b64decode(public_key_user_base64)
                        comprobante = user['user'] + " " + public_key_user.hex()
                        hash_comprobante = SHA256.new(comprobante.encode('utf-8'))
                        hash_comprobante_bytes = hash_comprobante.digest()
                        certif=bytes.fromhex(user['signature'])
                        Dilithium2.verify(public_app, hash_comprobante_bytes, certif)

                        print("Usuario validado")
                        break
                    except (ValueError, TypeError):
                        print("Usuario no validado")
                        break
            except ValueError:
                try:
                    public_key_user_base64 = user['public_key']
                    public_key_user = base64.b64decode(public_key_user_base64)
                    comprobante = user['user'] + " " + public_key_user.hex()
                    hash_comprobante = SHA256.new(comprobante.encode('utf-8'))
                    hash_comprobante_bytes = hash_comprobante.digest()
                    certif=bytes.fromhex(user['signature'])
                    Dilithium2.verify(public_app, hash_comprobante_bytes, certif)

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
                    try:
                        tipo_clavebase64 = user2["public_key"]
                        tipo_clave_key = base64.b64decode(tipo_clavebase64)
                        tipo_clave = RSA.import_key(tipo_clave_key)
                        if tipo_clave.has_private():
                            print("Clave privada")
                        else:
                            public_key_base64 = user2['public_key']
                            public_key_bytes = base64.b64decode(public_key_base64)
                            public_key = RSA.import_key(public_key_bytes)
                            cipher = PKCS1_OAEP.new(public_key)
                            clave_user = cipher.encrypt(clave)
                            lista_claves_cifradas[user2['user']] = clave_user
                    except ValueError:
                        public_key_base64 = user2['public_key']
                        public_key_bytes = base64.b64decode(public_key_base64)
                        kyberobject = Kyber512
                        tamanio = 32
                        clave_user = []
                        for i in range(0, len(clave), tamanio):
                            bloque = clave[i:i+tamanio]
                            bloque = bloque.ljust(tamanio,b'\0')
                            clave_user.append(kyberobject._cpapke_enc(public_key_bytes, bloque, tamanio.to_bytes(32,byteorder='big')))

                        clave_user_encripted = b''.join(clave_user)
                        lista_claves_cifradas[user2['user']] = clave_user_encripted

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
        if not archivo.lower().endswith('.bin'):
            continue 
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

                        try:
                            tipo_clavebase64 = user2["public_key"]
                            tipo_clave_key = base64.b64decode(tipo_clavebase64)
                            tipo_clave = RSA.import_key(tipo_clave_key)
                            if tipo_clave.has_private():
                                print("Clave privada")
                            else:
                                private_key_rsa = RSA.import_key(private_key)
                            cipher_rsa = PKCS1_OAEP.new(private_key_rsa)
                            clave_descifrada = cipher_rsa.decrypt(clave)
                        except ValueError:
                            kyberobject = Kyber512
                            tamanio = 768
                            clave_user = []
                            for i in range(0,len(clave), tamanio):
                                bloque = clave[i:i+tamanio]
                                if isinstance(bloque,int):
                                    bloque = bloque.to_bytes((bloque.bit_length()+7)//8,byteorder='big')
                                bloquedes = kyberobject._cpapke_dec(private_key,bloque)
                                bloquedes = bloquedes.rstrip(b'\0')
                                clave_user.append(bloquedes)
                            
                            clave_descifrada = b''.join(clave_user)
                            clave_descifrada = clave_descifrada.rstrip(b'\0')

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

        seleccionar_usuarios_ventana = ctk.CTk()
        seleccionar_usuarios_ventana.title("Seleccionar Usuarios")
        ctk.set_appearance_mode("dark")        
        seleccionar_usuarios_ventana.scrollable_frame = ctk.CTkScrollableFrame(seleccionar_usuarios_ventana, label_text="Lista de usuarios")
        seleccionar_usuarios_ventana.scrollable_frame.grid(row=1, column=2, padx=(20, 0), pady=(20, 0), sticky="nsew")
        seleccionar_usuarios_ventana.scrollable_frame.grid_columnconfigure(0, weight=1)
        seleccionar_usuarios_ventana.scrollable_frame_switches = []
        
        for i in range(len(usuarios)):
            switch = ctk.CTkSwitch(seleccionar_usuarios_ventana.scrollable_frame, text=usuarios[i])
            switch.grid(row=i, column=0, padx=10, pady=(0, 20))
            seleccionar_usuarios_ventana.scrollable_frame_switches.append(switch)

        def guardar_seleccion():
            seleccionados.clear()
            for switch in seleccionar_usuarios_ventana.scrollable_frame_switches:
                if switch.get():
                    seleccionados.append(switch.cget("text"))
                    print(seleccionados)
            seleccionar_usuarios_ventana.destroy()
            encriptarArchivosUsers(seleccionados, ruta_archivo)

        boton_aceptar = ctk.CTkButton(seleccionar_usuarios_ventana, text="Aceptar", command=guardar_seleccion)
        boton_aceptar.grid(row=2, column=2, padx=10, pady=10)


        seleccionar_usuarios_ventana.mainloop()

    seleccionar_usuarios()

def login():
    def registrar_usuario():
        def guardar_usuario():
            nuevo_usuario = entry_nuevo_usuario.get()
            nueva_contrasena = entry_nueva_contrasena.get()

            if(len(nuevo_usuario) == 0 or len(nueva_contrasena) == 0):
                messagebox.showerror("Error", "Debe proporcionar un usuario y una contraseña.")
                return

            metodo = opcion_seleccionada.get()
            
            registrarUsuarioApp(nuevo_usuario, nueva_contrasena, metodo)

            
            registro_ventana.destroy()

        # Crear ventana para el registro
        registro_ventana = ctk.CTk()
        registro_ventana.title("Registrar Usuario")
        registro_ventana.geometry("400x300")
        ctk.set_appearance_mode("dark")


        label_nuevo_usuario = ctk.CTkLabel(registro_ventana, text="Nuevo Usuario:")
        label_nuevo_usuario.pack(pady=5)
        entry_nuevo_usuario = ctk.CTkEntry(registro_ventana)
        entry_nuevo_usuario.pack(pady=5)

        label_nueva_contrasena = ctk.CTkLabel(registro_ventana, text="Nueva Contraseña:")
        label_nueva_contrasena.pack(pady=5)
        entry_nueva_contrasena = ctk.CTkEntry(registro_ventana, show="*")
        entry_nueva_contrasena.pack(pady=5)

        label_metodo = ctk.CTkLabel(registro_ventana, text="Seleccione el tipo de cifrado:")
        label_metodo.pack(pady=5)

        opcion_seleccionada = ctk.IntVar(value=0)

        radiobutton_rsa = ctk.CTkRadioButton(registro_ventana, text="RSA", variable=opcion_seleccionada, value=0)
        radiobutton_rsa.pack(pady=5)

        radiobutton_kyber = ctk.CTkRadioButton(registro_ventana, text="Kyber", variable=opcion_seleccionada, value=1)
        radiobutton_kyber.pack(pady=5)

        boton_guardar = ctk.CTkButton(registro_ventana, text="Guardar", command=guardar_usuario)
        boton_guardar.pack(pady=15)

        registro_ventana.mainloop()

    def recoger_contrasena():
        contrasena = entry_contrasena.get()
        validarUsuario(contrasena)
        login_ventana.destroy()
    
    def seleccionar_certificado():
        global certificado
        certificado = filedialog.askopenfilename(
            title="Seleccionar certificado",
            filetypes=[("Archivos JSON", "*.json")]
        )

    login_ventana = ctk.CTk()
    login_ventana.title("Login")
    login_ventana.geometry("600x300")
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("green")

    boton_seleccionar_certificado = ctk.CTkButton(login_ventana, text="Seleccionar Certificado", command=seleccionar_certificado)
    boton_seleccionar_certificado.pack(pady=10)

    label_contrasena = ctk.CTkLabel(login_ventana, text="Contraseña:")
    label_contrasena.pack(pady=5)
    entry_contrasena = ctk.CTkEntry(login_ventana, show="*")
    entry_contrasena.pack(pady=5)

    boton_login = ctk.CTkButton(login_ventana, text="Login", command=recoger_contrasena)
    boton_login.pack(pady=10)

    boton_registrar = ctk.CTkButton(login_ventana, text="Registrar", command=registrar_usuario)
    boton_registrar.pack(pady=10)

    login_ventana.mainloop()


    if not usuario or not contrasena:
        messagebox.showerror("Error", "No se ha proporcionado usuario o contraseña. El programa se cerrará.")
        sys.exit()

crearClavesAplicacion()

login()



ventana = ctk.CTk()
ventana.title("Encriptación de PDFs")
ventana.geometry("800x600")

ctk.set_appearance_mode("dark")
# Crear el menú principal
menu_principal = tk.Menu(ventana)
ventana.config(menu=menu_principal)


# Crear un mensaje de bienvenida
mensaje_bienvenida = ctk.CTkLabel(
    ventana, 
    text=f"Bienvenido, {usuario.upper()}!!", 
    font=("Helvetica", 20, "bold"), 
    text_color="#00BFFF", 
    corner_radius=10, 
    fg_color="#2E2E2E", 
    bg_color="#1C1C1C", 
    padx=20, 
    pady=10
)
mensaje_bienvenida.pack(pady=20)

# Crear un frame para las instrucciones
frame_archivos_seleccionados = ctk.CTkFrame(ventana)
frame_archivos_seleccionados.pack(side=tk.RIGHT, padx=10, pady=10)


# Crear un label para mostrar la lista de archivos seleccionados
label_archivos_seleccionados = ctk.CTkLabel(frame_archivos_seleccionados, text="No hay archivos seleccionados todavía", justify=ctk.LEFT, font=("Helvetica", 11))
label_archivos_seleccionados.pack(pady=10)

def actualizar_label_archivos():
    if ruta_archivo:
        archivos_seleccionados = "\n".join(ruta_archivo)
        label_archivos_seleccionados.configure(text=f"Archivos seleccionados:\n{archivos_seleccionados}")
    else:
        label_archivos_seleccionados.configure(text="No hay archivos seleccionados todavía")

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
1. Seleccionar Archivos: Selecciona el archivo o archivos que deseas cifrar o descifrar.
2. Cifrar archivo: Permite seleccionar usuarios a los que encriptar estos archivos
3. Descifrar archivo: Descifra archivos si eres un usuario autorizado
4. Salir de la aplicación: Cierra la aplicación.
"""

label_instrucciones = ctk.CTkLabel(frame_archivos_seleccionados, text=instrucciones, justify=ctk.LEFT, font=("Helvetica", 11, "bold"))
label_instrucciones.pack(pady=30)

boton_seleccionar = ctk.CTkButton(ventana, text="Seleccionar Archivos", command=seleccionar_archivos)
boton_seleccionar.pack(pady=30)

boton_cifrar = ctk.CTkButton(ventana, text="Cifrar Archivo", command=cifrar_archivo)
boton_cifrar.pack(pady=30)

boton_descifrar = ctk.CTkButton(ventana, text="Descifrar Archivo", command=descifrar_archivo)
boton_descifrar.pack(pady=30)

boton_salir = ctk.CTkButton(ventana, text="Salir de la aplicación", command=salir_app)
boton_salir.pack(pady=30)

# Iniciar el loop de la aplicación
ventana.mainloop()