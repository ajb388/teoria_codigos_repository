import os
import tkinter as tk
import base64
from kyber.kyber import Kyber512, Kyber768, Kyber1024
from Crypto.Hash import SHA256
from tkinter import filedialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from tkinter import filedialog, messagebox

# Variables globales
ruta_archivo = ""

def generate_certificate(self):
# Método para generar certificados
    pass

    # Función para leer el archivo y devolver su contenido
def leer_archivo(ruta_archivo):
    with open(ruta_archivo, 'rb') as f:
        return f.read()

# Función para escribir datos en un archivo
def escribir_archivo(ruta_archivo, datos):
    with open(ruta_archivo, 'wb') as f:
        f.write(datos)

def cifrar_archivo(ruta_archivo, clave_tamaño, ruta_salida, ruta_claves):
    datos = leer_archivo(ruta_archivo)  # Leer el archivo a cifrar
    clave = generar_clave(clave_tamaño)
    print("Clave generada:", clave)
    # Crear un cifrador AES en modo CBC
    cipher = AES.new(clave, AES.MODE_CBC)
    iv = cipher.iv  # Inicializar el vector de inicialización (IV)

    # Añadir padding (relleno) a los datos para que sean múltiplos del tamaño de bloque (16 bytes)
    datos_padded = pad(datos, AES.block_size)

    # Cifrar los datos
    ciphertext = cipher.encrypt(datos_padded)

    nombre_archivo, extension = os.path.splitext(os.path.basename(ruta_archivo))

    # Guardar el IV y el texto cifrado en el archivo de salida
    with open(ruta_salida, 'wb') as f:
        f.write(iv)           # Guardar el IV (16 bytes)
        f.write(ciphertext)    # Guardar el texto cifrado
    guardar_clave(nombre_archivo, clave, extension, ruta_claves)
    print(f"Archivo cifrado guardado en {ruta_salida}")       

def descifrar_archivo(ruta_archivo, ruta_claves):
    lista_claves = leer_claves(ruta_claves)
    with open(ruta_archivo, 'rb') as f:
        iv = f.read(16)        # Leer el IV (16 bytes)
        ciphertext = f.read()  # Leer el texto cifrado restante

    nombre_archivo, extension = os.path.splitext(os.path.basename(ruta_archivo))
    
    if nombre_archivo in lista_claves:
        clave = lista_claves[nombre_archivo][0]
        extension = lista_claves[nombre_archivo][1]
        print(f"La clave para '{nombre_archivo}' es : {clave}")

    ruta_salida = filedialog.asksaveasfilename(defaultextension=extension,
                                            initialfile=nombre_archivo,
                                            filetypes=[("Todos los archivos", "*.*")])
    
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

def generar_clave(clave_tamaño):
    if clave_tamaño == '1':
        clave = get_random_bytes(32)
    elif clave_tamaño == '2':
        clave = get_random_bytes(24)
    elif clave_tamaño == '3':
        clave = get_random_bytes(16)
    else:
        print("Opción no válida. Creando clave por defecto de 32 bytes")
        clave = get_random_bytes(32)
    return clave # AES-256 usa una clave de 256 bits (32 bytes)    

def guardar_clave(nombre, clave, extension, ruta_claves):
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

def crear_kyber(ruta_archivo_cifrado, tamanio):
    #Dependiendo de la opción elegida, se creará un kyber de un tamaño de clave o de otro
    if tamanio == '1':
        key = Kyber512
    elif tamanio == '2':
        key = Kyber768
    elif tamanio == '3':
        key = Kyber1024
    else:
        key = Kyber512
        print("Establecido tamaño por defecto de 512")
    #Guardamos las claves generadas publica y privada tal y como lo devuelve la funcion keygen()
    public_key, private_key = key.keygen()
    #Recortamos la dirección final para poder colocar en ese directorio las rutas de los futuros archivos .pem
    ruta_cortada = os.path.dirname(ruta_archivo_cifrado)
    ruta_privada = os.path.normpath(os.path.join(ruta_cortada, "private_kyber.pem"))
    ruta_publica = os.path.normpath(os.path.join(ruta_cortada, "public_kyber.pem"))
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
        print("¿Desea crear un nuevo par de claves pública y privada, o desea utilizar una clave pública propia?")
        print("1. Crear nuevas")
        print("2. Utilizar mi clave")
        print("3. Volver")
        opcion = input("Selecciona una opción: ")
        if opcion == '1':
            tamanio = input("Seleccione el tamaño de clave Kyber: (1) 512, (2) 768 o (3) 1024:")

            ruta_archivo_cifrado = filedialog.asksaveasfilename(defaultextension=".pem",
                                                        initialfile="public",
                                                        filetypes=[("Archivos pem", "*.pem"),("Todos los archivos", "*.*")])
            crear_kyber(ruta_archivo_cifrado, tamanio) #Creamos las claves pública y privada en el mismo directorio que el archivo claves.bin

        elif opcion == '2':
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
            else:
                print("No ha seleccionado ningún archivo")
        elif opcion == '3':
            break
        else:
            print("Opción no válida. Inténtalo de nuevo.")

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
                    
                #Dependiendo del tamaño de la clave se deduce con qué tamaño de clave kyber estamos trabajando, y se le asigna el tamaño de bloque
                if len(private_key) == 1632:
                    kyberobject = Kyber512
                    tamanio = 768
                elif len(private_key) == 2400:
                    kyberobject = Kyber768
                    tamanio = 1088
                elif len(private_key) == 3168:
                    kyberobject = Kyber1024
                    tamanio = 1568
                    
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

def crear_RSA(ruta_archivo_cifrado, clave_tamaño):
    if clave_tamaño == "1":
        print("Creando clave RSA con 2048 bits")
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
    elif clave_tamaño == "2":
        print("Creando clave RSA con 4096 bits")
        key = RSA.generate(4096)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
    else:
        print("Selección por defecto de creación de clave RSA de 2048")
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

    ruta_cortada = os.path.dirname(ruta_archivo_cifrado)
    ruta_privada = os.path.normpath(os.path.join(ruta_cortada, "private_rsa.pem"))
    ruta_publica = os.path.normpath(os.path.join(ruta_cortada, "public_rsa.pem"))
    
    with open(ruta_privada, "wb") as f:
        f.write(private_key)
    with open(ruta_publica, "wb") as f:
        f.write(public_key)

def habilitar_claves(ruta_archivo_cifrado):
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
                print("Este archivo no corresponde con una clave privada o quizás el archivo de claves no lo requiera, vuelva a intentarlo")

def encriptar_claves():

    while True:
        print("¿Desea crear un nuevo par de claves pública y privada, o desea utilizar una clave pública propia?")
        print("1. Crear nuevas")
        print("2. Utilizar mi clave")
        print("3. Volver")
        opcion = input("Selecciona una opción: ")
        if opcion == '1':
            tamanio = input("Seleccione el tamaño de clave RSA: (1) 2048 o (2) 4096:")

            ruta_archivo_cifrado = filedialog.asksaveasfilename(defaultextension=".bin",
                                                        initialfile="public_rsa",
                                                        filetypes=[("Archivos PEM", "*.pem"),("Todos los archivos", "*.*")])
            crear_RSA(ruta_archivo_cifrado, tamanio) #Creamos las claves pública y privada en el mismo directorio que el archivo claves.bin

        elif opcion == '2':
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
                    filetypes=[("Todos los archivos", "*.pem")] #Seleccionamos el archivo clave publica
                )
            if ruta_archivo:
                try:
                    with open(ruta_archivo, "rb") as f:
                        public_key = RSA.import_key(f.read()) #Leemos su contenido y lo importamos como clave RSA
                    if public_key.has_private():
                        print("Esta clave publica no es valida o puede no ser una clave publica, intentelo de nuevo")
                    else:
                        cipher_rsa = PKCS1_OAEP.new(public_key)
            
                        with open(ruta_archivo_cifrado, "rb") as f:
                            datos = f.read()
                        
                        encrypted_data = cipher_rsa.encrypt(datos)
            
                        with open(ruta_archivo_cifrado, "wb") as f:
                            f.write(encrypted_data)
                        break
                except ValueError:
                    print("Esta clave está corrupta, intentelo de nuevo")
            else:
                print("No ha seleccionado ningún archivo")
        elif opcion == '3':
            break
        else:
            print("Opción no válida. Inténtalo de nuevo.")

def salir_app():
    ventana.quit()

def seleccionar_archivos():
    # Abre un diálogo para seleccionar uno o varios archivos
    ruta_archivo = filedialog.askopenfilename(
                    title="Seleccionar archivo",
                    filetypes=[("Todos los archivos", ".*")]
    )
    
    # Si se seleccionan archivos, muestra sus nombres
    if ruta_archivo:
        mensaje = "\n".join(ruta_archivo)
        messagebox.showinfo("Archivos Seleccionados", f"Has seleccionado:\n{mensaje}")
    else:
        messagebox.showinfo("No se seleccionaron archivos", "No se ha seleccionado ningún archivo.")

ventana = tk.Tk()
ventana.title("Encriptación de PDFs")
ventana.geometry("600x400")

# Crear el menú principal
menu_principal = tk.Menu(ventana)
ventana.config(menu=menu_principal)

# Crear un submenú para "Archivo"
menu_archivo = tk.Menu(menu_principal, tearoff=0)
menu_archivo.add_command(label="Cifrar", command=cifrar_archivo)   # Vincula a abrir_archivo
menu_archivo.add_command(label="Descifrar", command=descifrar_archivo)  # Vincula a guardar_archivo
menu_archivo.add_separator()  # Línea separadora
menu_archivo.add_command(label="Salir", command=salir_app)    # Vincula a salir_app

boton_seleccionar = tk.Button(ventana, text="Seleccionar Archivos", command=seleccionar_archivos)
boton_seleccionar.pack(expand=True)

# Añadir el submenú "Archivo" al menú principal
menu_principal.add_cascade(label="Archivo", menu=menu_archivo)

# Iniciar el loop de la aplicación
ventana.mainloop()