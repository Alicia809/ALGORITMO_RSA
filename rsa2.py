from Crypto.PublicKey import RSA  # Importar la clase RSA de la biblioteca Crypto
from Crypto.Cipher import AES, PKCS1_OAEP  # Importar AES y PKCS1_OAEP de la biblioteca Crypto
import os  # Importar el módulo os para generación de números aleatorios y manipulación de archivos

# Función para generar un par de claves RSA
def generate_RSA_key_pair():
    key = RSA.generate(2048)  # Generar una clave RSA de 2048 bits
    private_key = key.export_key()  # Exportar la clave privada
    public_key = key.publickey().export_key()  # Exportar la clave pública
    return private_key, public_key  # Devolver la clave privada y la clave pública

# Función para cifrar un archivo
def encrypt_file(file_path, public_key):
    aes_key = os.urandom(16)  # Generar una clave AES aleatoria de 16 bytes
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))  # Inicializar el cifrador RSA con la clave pública
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)  # Cifrar la clave AES con RSA
    with open(file_path, 'rb') as f:  # Abrir el archivo en modo lectura binaria
        data = f.read()  # Leer el contenido del archivo
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)  # Inicializar el cifrador AES con la clave AES
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)  # Cifrar el contenido del archivo con AES
    with open(file_path + '.enc', 'wb') as f:  # Abrir un nuevo archivo en modo escritura binaria
        [f.write(x) for x in (encrypted_aes_key, cipher_aes.nonce, tag, ciphertext)]  # Escribir los datos cifrados en el archivo

# Función para descifrar un archivo y guardarlo
def decrypt_file_and_save(file_path, private_key, output_path):
    with open(file_path, 'rb') as f:  # Abrir el archivo cifrado en modo lectura binaria
        encrypted_aes_key, nonce, tag, ciphertext = [f.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]  # Leer los datos cifrados del archivo
    cipher_rsa = PKCS1_OAEP.new(private_key)  # Inicializar el cifrador RSA con la clave privada
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)  # Descifrar la clave AES con RSA
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)  # Inicializar el cifrador AES con la clave AES y el nonce
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)  # Descifrar el contenido del archivo con AES
    with open(output_path, 'wb') as f:  # Abrir un nuevo archivo en modo escritura binaria
        f.write(data)  # Escribir el contenido descifrado en el archivo

# Ejemplo de uso:
private_key, public_key = generate_RSA_key_pair()  # Generar un par de claves RSA
encrypt_file('documento.txt', public_key)  # Cifrar un archivo llamado "RSA.pdf" con la clave pública
decrypt_file_and_save('documento.txt.enc', RSA.import_key(private_key), 'documento2.txt')  # Descifrar el archivo cifrado y guardarlo como "RSA2.pdf"

#En la linea 37 y 38 podemos modificar para utilizar el algoritmo RSA
#con documentos .pdf, .docx, .txt 