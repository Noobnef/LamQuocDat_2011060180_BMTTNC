from flask import Flask, request, jsonify
from cipher.caesar import CaesarCipher
from cipher.vigenere import VigenereCipher
from cipher.railfence import RailFenceCipher
from cipher.playfair import PlayFairCipher
from cipher.transposition import TranspositionCipher

app = Flask(__name__)

caesar_cipher = CaesarCipher()
vigenere_cipher = VigenereCipher()
railfence_cipher = RailFenceCipher()
playfair_cipher = PlayFairCipher()
transposition_cipher = TranspositionCipher()

# Function để kiểm tra dữ liệu đầu vào
def validate_request(data, required_fields):
    """Kiểm tra request JSON có đủ field cần thiết hay không"""
    if not data:
        return jsonify({'error': 'Request body is empty'}), 400
    
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({'error': f'Missing fields: {", ".join(missing_fields)}'}), 400
    
    return None


# Caesar Cipher
@app.route("/api/caesar/encrypt", methods=['POST'])
def caesar_encrypt():
    data = request.json
    validation = validate_request(data, ['plain_text', 'key'])
    if validation:
        return validation

    plain_text = data['plain_text']
    key = int(data['key'])
    encrypted_text = caesar_cipher.encrypt_text(plain_text, key)
    return jsonify({'encrypted_message': encrypted_text})

@app.route("/api/caesar/decrypt", methods=['POST'])
def caesar_decrypt():
    data = request.json
    validation = validate_request(data, ['cipher_text', 'key'])
    if validation:
        return validation

    cipher_text = data['cipher_text']
    key = int(data['key'])
    decrypted_text = caesar_cipher.decrypt_text(cipher_text, key)
    return jsonify({'decrypted_message': decrypted_text})

# Vigenere Cipher
@app.route('/api/vigenere/encrypt', methods=['POST'])
def vigenere_encrypt():
    data = request.json
    validation = validate_request(data, ['plain_text', 'key'])
    if validation:
        return validation

    plain_text = data['plain_text']
    key = data['key']
    encrypted_text = vigenere_cipher.vigenere_encrypt(plain_text, key)
    return jsonify({'encrypted_text': encrypted_text})

@app.route('/api/vigenere/decrypt', methods=['POST'])
def vigenere_decrypt():
    data = request.json
    validation = validate_request(data, ['cipher_text', 'key'])
    if validation:
        return validation

    cipher_text = data['cipher_text']
    key = data['key']
    decrypted_text = vigenere_cipher.vigenere_decrypt(cipher_text, key)
    return jsonify({'decrypted_text': decrypted_text})

# Rail Fence Cipher
@app.route('/api/railfence/encrypt', methods=['POST'])
def railfence_encrypt():
    data = request.json
    validation = validate_request(data, ['plain_text', 'key'])
    if validation:
        return validation

    plain_text = data['plain_text']
    key = int(data['key'])
    encrypted_text = railfence_cipher.rail_fence_encrypt(plain_text, key)
    return jsonify({'encrypted_text': encrypted_text})

@app.route('/api/railfence/decrypt', methods=['POST'])
def railfence_decrypt():
    data = request.json
    validation = validate_request(data, ['cipher_text', 'key'])
    if validation:
        return validation

    cipher_text = data['cipher_text']
    key = int(data['key'])
    decrypted_text = railfence_cipher.rail_fence_decrypt(cipher_text, key)
    return jsonify({'decrypted_text': decrypted_text})

# Playfair Cipher
@app.route('/api/playfair/encrypt', methods=['POST'])
def playfair_encrypt():
    data = request.json
    validation = validate_request(data, ['plain_text', 'key'])
    if validation:
        return validation

    plain_text = data['plain_text']
    key = data['key']
    playfair_matrix = playfair_cipher.create_playfair_matrix(key)
    encrypted_text = playfair_cipher.playfair_encrypt(plain_text, playfair_matrix)
    return jsonify({'encrypted_text': encrypted_text})

@app.route('/api/playfair/decrypt', methods=['POST'])
def playfair_decrypt():
    data = request.json
    validation = validate_request(data, ['cipher_text', 'key'])
    if validation:
        return validation

    cipher_text = data['cipher_text']
    key = data['key']
    playfair_matrix = playfair_cipher.create_playfair_matrix(key)
    decrypted_text = playfair_cipher.playfair_decrypt(cipher_text, playfair_matrix)
    return jsonify({'decrypted_text': decrypted_text})

# Transposition Cipher
@app.route('/api/transposition/encrypt', methods=['POST'])
def transposition_encrypt():
    data = request.json
    validation = validate_request(data, ['plain_text', 'key'])
    if validation:
        return validation

    plain_text = data['plain_text']
    key = int(data['key'])
    encrypted_text = transposition_cipher.encrypt(plain_text, key)
    return jsonify({'encrypted_text': encrypted_text})

@app.route('/api/transposition/decrypt', methods=['POST'])
def transposition_decrypt():
    data = request.json
    validation = validate_request(data, ['cipher_text', 'key'])
    if validation:
        return validation

    cipher_text = data['cipher_text']
    key = int(data['key'])
    decrypted_text = transposition_cipher.decrypt(cipher_text, key)
    return jsonify({'decrypted_text': decrypted_text})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
