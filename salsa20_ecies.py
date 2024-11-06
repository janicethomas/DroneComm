import numpy as np
from Crypto.Cipher import Salsa20
from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt
import numpy as np
import matplotlib.pyplot as plt
from PIL import Image
import io
from math import log2, sqrt
import time
import psutil
from memory_profiler import memory_usage

def measure_memory_usage(func, *args):
    mem_usage = memory_usage((func, args))
    return max(mem_usage) - min(mem_usage)

def npcr(original, encrypted):
    # Compute NPCR
    diff = original != encrypted
    return np.sum(diff) / original.size * 100  # as a percentage

def uaci(original, encrypted):
    # Compute UACI
    diff_intensity = np.abs(original - encrypted)
    return np.mean(diff_intensity / 255) * 100  # as a percentage


def correlation_coefficient(image):
    max_index = len(image)
    sample_size = 1000
    indices = np.random.randint(0, max_index, sample_size)
    x_vals = image[indices]         # Current pixel values
    y_vals = image[indices + 1]     # Adjacent pixel values
    return np.corrcoef(x_vals, y_vals)[0, 1]


def information_entropy(image):
    # Flatten the image to a 1D array
    hist, _ = np.histogram(image.flatten(), bins=256, range=(0, 256))
    hist = hist / np.sum(hist)  # Normalize histogram

    entropy = -np.sum([p * log2(p) for p in hist if p > 0])
    return entropy


def mse(original, encrypted):
    return np.mean((original - encrypted) ** 2)

def psnr(original, encrypted):
    mse_value = mse(original, encrypted)
    if mse_value == 0:
        return float('inf')
    max_pixel = 255.0
    return 20 * np.log10(max_pixel / sqrt(mse_value))


def evaluate_image_metrics(original_image_path, encrypted_bin):
    original = image_to_numpy_array(original_image_path)
    original = original.ravel()
    encrypted = np.frombuffer(encrypted_bin, dtype=np.uint8)
    # encrypted = np.pad(encrypted, (0, original.size-encrypted.size))
    original = original[:encrypted.size]

    metrics = {}
    metrics['NPCR'] = npcr(original, encrypted)
    metrics['UACI'] = uaci(original, encrypted)
    metrics['Correlation Coefficient'] = correlation_coefficient(encrypted)
    metrics['Information Entropy'] = information_entropy(encrypted)
    metrics['MSE'] = mse(original, encrypted)
    metrics['PSNR'] = psnr(original, encrypted)
    for key in metrics.keys():
        print(key, ":",metrics[key])

def image_to_numpy_array(image_path):
    image = Image.open(image_path)
    image_array = np.array(image)
    return image_array

def image_to_bytes(image_path):
    with open(image_path, 'rb') as image_file:
        return image_file.read()

def bytes_to_image(image_bytes, output_path):
    image = Image.open(io.BytesIO(image_bytes))
    image.save(output_path)

def generate_keys():
    privKey = generate_eth_key()
    privKeyHex = privKey.to_hex()
    pubKeyHex = privKey.public_key.to_hex()
    print("Encryption public key:", pubKeyHex)
    print("Decryption private key:", privKeyHex)
    return pubKeyHex, privKeyHex

def salsa20_encrypt(image_path, key):
    image_bytes = image_to_bytes(image_path)
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes long for Salsa20")
    cipher = Salsa20.new(key=key)
    encrypted_image = cipher.nonce + cipher.encrypt(image_bytes)
    return encrypted_image

def salsa20_decrypt(encrypted_image, key):
    encrypted_data = encrypted_image
    msg_nonce = encrypted_data[:8]
    ciphertext = encrypted_data[8:]
    cipher = Salsa20.new(key=key, nonce=msg_nonce)
    decrypted_image_bytes = cipher.decrypt(ciphertext)
    return decrypted_image_bytes

def ecies_encrypt(pubKeyHex, plaintext):
    encrypted = encrypt(pubKeyHex, plaintext)
    # print("Encrypted:", binascii.hexlify(encrypted))
    return encrypted

def ecies_decrypt(privKeyHex, encrypted):
    decrypted = decrypt(privKeyHex, encrypted)
    # print("Decrypted:", decrypted)
    return decrypted

def visualize_encrypted_data(encrypted_data, title):
    data_array = np.frombuffer(encrypted_data, dtype=np.uint8)
    size = int(np.ceil(np.sqrt(data_array.size)))
    data_array = np.resize(data_array, (size, size))
    plt.imshow(data_array, cmap='gray')
    plt.axis('off')
    plt.title(title)
    plt.show()

def image_to_rgbarr(image_path):
    image_data = image_to_bytes(image_path)
    image = Image.open(io.BytesIO(image_data))
    image = image.convert("RGB")
    rgb_array = np.array(image)
    return rgb_array

def rawbin_to_rgbarr(image_data):
    data_array = np.frombuffer(image_data, dtype=np.uint8)
    size = int(np.ceil(np.sqrt(data_array.size/3)))
    data_array = np.resize(data_array, (size, size, 3))
    return data_array

def plot_rgb_histogram(rgb_array, title):
    r, g, b = rgb_array[:, :, 0].flatten(), rgb_array[:, :, 1].flatten(), rgb_array[:, :, 2].flatten()
    plt.figure(figsize=(10, 4))
    plt.hist(r, bins=256, color='red', alpha=0.6, label="Red Channel")
    plt.hist(g, bins=256, color='green', alpha=0.6, label="Green Channel")
    plt.hist(b, bins=256, color='blue', alpha=0.6, label="Blue Channel")
    plt.xlabel("Pixel Intensity")
    plt.ylabel("Frequency")
    plt.legend()
    plt.title(f"RGB Histogram for {title} image")
    plt.show()

def save_encrypted_data_as_image(encrypted_data, output_path, size=(256, 256)):
    data_array = np.frombuffer(encrypted_data, dtype=np.uint8)
    print(data_array.shape)
    # total_size = size[0] * size[1]
    # if data_array.size < total_size:
    #     data_array = np.pad(data_array, (0, total_size - data_array.size), mode='wrap')
    # elif data_array.size > total_size:
    #     data_array = data_array[:total_size]
    # image_array = data_array.reshape(size)
    
    # image = Image.fromarray(data_array)
    # image.save(output_path, format='JPEG')
    # print(f"Encrypted data saved as image at {output_path}")

salsa_key = b'*Thirty-two byte (256 bits) key*'
input_image_path = "img1.jpg"

process = psutil.Process()
start_cpu_enc = process.cpu_percent(interval=None)
enc_start_time = time.time()

# Step 1: Encrypt using Salsa20
encrypted_salsa_data = salsa20_encrypt(input_image_path, salsa_key)
print("Salsa20 Encryption Successful - Encrypted Data:")
visualize_encrypted_data(encrypted_salsa_data, "Salsa20 Encrypted Image")

# Step 2: Encrypt the Salsa20-encrypted data using ECIES framework
pubKeyHex, privKeyHex = generate_keys()
encrypted_ecies = ecies_encrypt(pubKeyHex, encrypted_salsa_data)

enc_end_time = time.time()
end_cpu_enc = process.cpu_percent(interval=None)

print("ECIES framework Encryption Successful - Encrypted Data:")
visualize_encrypted_data(encrypted_ecies, "ECIES Framework Encrypted Image")
# save_encrypted_data_as_image(encrypted_ecies, "img1_enc.jpg")

start_cpu_dec = process.cpu_percent(interval=None)
dec_start_time = time.time()

# Step 3: Decrypt the AES-encrypted data first
decrypted_ecc_data = ecies_decrypt(privKeyHex, encrypted_ecies)
print("ECIES framework Decryption Successful")

# Step 4: Decrypt the Salsa20-encrypted data second
decrypted_salsa_data = salsa20_decrypt(decrypted_ecc_data, salsa_key)
print("Salsa20 Decryption Successful")

dec_end_time = time.time()
end_cpu_dec = process.cpu_percent(interval=None)

# Step 5: Save the final decrypted image to a file
# output_decrypted_image_path = "C:\\Users\\SUDIKSHA\\Pictures\\.ipynb_checkpoints\\dec.jpg"
output_decrypted_image_path = "img1_dec.jpg"
bytes_to_image(decrypted_salsa_data, output_decrypted_image_path)
print(f"Decrypted image saved as: {output_decrypted_image_path}")

decrypted_image = Image.open(output_decrypted_image_path)
decrypted_image.show(title="Decrypted Image")

# Step 6: Evaluate

print()
enc_time = enc_end_time - enc_start_time
dec_time = dec_end_time - dec_start_time
# enc_memory = measure_memory_usage(salsa20_encrypt, input_image_path, salsa_key) + measure_memory_usage(ecies_encrypt, pubKeyHex, encrypted_salsa_data)
print("Encryption time: ",enc_time, "secs")
print("Decryption time: ", dec_time, "secs")
print("Encryption Throughput: ", len(encrypted_ecies)/enc_time, "bytes/sec")
print("Decryption Throughput: ", len(decrypted_salsa_data)/dec_time, "bytes/sec")
print(f"Encryption CPU Usage: {end_cpu_enc - start_cpu_enc} %")
print(f"Decryption CPU Usage: {end_cpu_dec - start_cpu_dec} %")
# print(f"Encryption Memory Usage: {enc_memory} MiB")
print()
print("Salsa20 + ECIES: ")
evaluate_image_metrics(input_image_path, encrypted_ecies)
print()
print("Salsa20:")
evaluate_image_metrics(input_image_path, encrypted_salsa_data)
rgb_arr = image_to_rgbarr(input_image_path)
plot_rgb_histogram(rgb_arr, "Original")
rgb_arr = rawbin_to_rgbarr(encrypted_ecies)
plot_rgb_histogram(rgb_arr, "Encrypted")

