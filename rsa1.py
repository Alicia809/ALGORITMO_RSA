import tkinter as tk  # Importar la biblioteca Tkinter para la interfaz gráfica
from tkinter import filedialog  # Importar filedialog de Tkinter para abrir el diálogo de selección de archivos
from cryptography.hazmat.backends import default_backend  # Importar el backend de cryptography
from cryptography.hazmat.primitives.asymmetric import rsa  # Importar RSA de cryptography para la generación de claves
from cryptography.hazmat.primitives import serialization  # Importar serialization de cryptography para serializar las claves
from cryptography.hazmat.primitives import hashes  # Importar hashes de cryptography para los algoritmos de hash
from cryptography.hazmat.primitives.asymmetric import padding  # Importar padding de cryptography para el relleno

# Función para generar claves RSA
def generar_claves():
    # Generar una clave privada RSA con un exponente público de 65537 y un tamaño de clave de 2048 bits
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Obtener la clave pública correspondiente a partir de la clave privada generada
    public_key = private_key.public_key()
    return private_key, public_key  # Devolver la clave privada y la clave pública

# Función para cifrar un mensaje utilizando la clave pública RSA
def cifrar_mensaje(public_key, mensaje):
    if isinstance(mensaje, str):  # Verificar si el mensaje es una cadena de texto
        mensaje = mensaje.encode()  # Convertir el mensaje a bytes si es una cadena de texto
    
    # Determinar el tamaño máximo de bloque para cifrar según el tamaño de la clave pública
    max_size = public_key.key_size // 8 - 2 * hashes.SHA256.digest_size - 2
    
    # Dividir el mensaje en bloques y cifrar cada bloque utilizando el algoritmo de relleno OAEP
    cifrado = b""
    for i in range(0, len(mensaje), max_size):
        bloque = mensaje[i:i + max_size]
        cifrado += public_key.encrypt(
            bloque,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    return cifrado  # Devolver el mensaje cifrado

# Función para descifrar un mensaje cifrado utilizando la clave privada RSA
def descifrar_mensaje(private_key, cifrado):
    # Desencriptar cada bloque del mensaje cifrado utilizando la clave privada y el algoritmo de relleno OAEP
    descifrado = b""
    max_size = private_key.key_size // 8
    for i in range(0, len(cifrado), max_size):
        bloque = cifrado[i:i + max_size]
        descifrado += private_key.decrypt(
            bloque,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    return descifrado  # Devolver el mensaje descifrado

# Función para cifrar el contenido de un archivo utilizando la clave pública RSA
def cifrar_archivo(public_key, nombre_archivo):
    with open(nombre_archivo, 'rb') as archivo:
        contenido = archivo.read()  # Leer el contenido del archivo
    cifrado = cifrar_mensaje(public_key, contenido)  # Cifrar el contenido del archivo
    return cifrado  # Devolver el contenido cifrado

# Función para mostrar los resultados en la interfaz gráfica
def mostrar_resultados():
    mensaje = entrada_mensaje.get()  # Obtener el mensaje ingresado por el usuario desde la entrada de texto
    private_key, public_key = generar_claves()  # Generar un par de claves pública y privada RSA
    cifrado = cifrar_mensaje(public_key, mensaje)  # Cifrar el mensaje utilizando la clave pública
    mensaje_descifrado = descifrar_mensaje(private_key, cifrado)  # Descifrar el mensaje cifrado utilizando la clave privada
    resultado_cifrado.delete(1.0, tk.END)  # Borrar el contenido anterior del widget de texto de cifrado
    resultado_cifrado.insert(tk.END, cifrado)  # Mostrar el mensaje cifrado en el widget de texto de cifrado
    resultado_descifrado.delete(1.0, tk.END)  # Borrar el contenido anterior del widget de texto de descifrado
    resultado_descifrado.insert(tk.END, mensaje_descifrado)  # Mostrar el mensaje descifrado en el widget de texto de descifrado

# Función para seleccionar un archivo y cifrar su contenido
def seleccionar_archivo():
    archivo = filedialog.askopenfilename(filetypes=[("Archivos de texto", "*.txt")])  # Abrir el diálogo de selección de archivos
    if archivo:  # Verificar si se seleccionó un archivo
        private_key, public_key = generar_claves()  # Generar un par de claves pública y privada RSA
        cifrado = cifrar_archivo(public_key, archivo)  # Cifrar el contenido del archivo
        resultado_cifrado.delete(1.0, tk.END)  # Borrar el contenido anterior del widget de texto de cifrado
        resultado_cifrado.insert(tk.END, cifrado)  # Mostrar el contenido cifrado en el widget de texto de cifrado
        
        # Descifrar el contenido del archivo utilizando la clave privada
        contenido_descifrado = descifrar_mensaje(private_key, cifrado)
        
        # Mostrar el contenido descifrado en el widget de texto de descifrado
        resultado_descifrado.delete(1.0, tk.END)  # Borrar el contenido anterior del widget de texto de descifrado
        resultado_descifrado.insert(tk.END, contenido_descifrado.decode())  # Mostrar el contenido descifrado en el widget de texto de descifrado

# Función para limpiar todos los campos de entrada y salida
def limpiar_todo():
    entrada_mensaje.delete(0, tk.END)  # Borrar el contenido del widget de entrada de texto
    resultado_cifrado.delete(1.0, tk.END)  # Borrar el contenido del widget de texto de cifrado
    resultado_descifrado.delete(1.0, tk.END)  # Borrar el contenido del widget de texto de descifrado

# Crear la ventana principal de la aplicación
ventana = tk.Tk()
ventana.title("RSA Ejemplo")  # Establecer el título de la ventana
ventana.geometry("400x400")  # Establecer las dimensiones de la ventana

# Etiqueta y entrada de texto para ingresar el mensaje a cifrar
tk.Label(ventana, text="Mensaje a cifrar:").pack()
entrada_mensaje = tk.Entry(ventana)
entrada_mensaje.pack()

# Botón para cifrar el mensaje ingresado
boton_cifrar = tk.Button(ventana, text="Cifrar Mensaje", command=mostrar_resultados)
boton_cifrar.pack()

# Botón para seleccionar un archivo y cifrar su contenido
boton_seleccionar_archivo = tk.Button(ventana, text="Seleccionar Archivo", command=seleccionar_archivo)
boton_seleccionar_archivo.pack()

# Etiqueta y widget de texto para mostrar el mensaje cifrado
resultado_cifrado_label = tk.Label(ventana, text="Mensaje cifrado:")
resultado_cifrado_label.pack()
resultado_cifrado = tk.Text(ventana, height=5, width=50)
resultado_cifrado.pack()

# Etiqueta y widget de texto para mostrar el mensaje descifrado
resultado_descifrado_label = tk.Label(ventana, text="Mensaje descifrado:")
resultado_descifrado_label.pack()
resultado_descifrado = tk.Text(ventana, height=5, width=50)
resultado_descifrado.pack()

# Botón para limpiar todos los campos
boton_limpiar = tk.Button(ventana, text="Limpiar Todo", command=limpiar_todo)
boton_limpiar.pack()

# Iniciar el bucle principal de la aplicación
ventana.mainloop()

