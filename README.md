# Stego + Encrypt Tool

A secure, GUI-based application that encrypts text and embeds it inside an image using LSB steganography. You can also extract and decrypt hidden messages from stego-images using the same tool.

---

## Demo

| Original Image |   Image with Hidden Message  |
| :------------: | :--------------------------: |
|   `image.png`  |       `image_stego.png`      |
|  *Clean Image* | *Contains encrypted payload* |

---

## Repository Structure

* **`main.py`** — Tkinter GUI application
* **`requirements.txt`** — Python dependencies
* **`image.png`** — Sample carrier image
* **`image_stego.png`** — Sample stego-image output

---

## Features

### Strong Encryption

* Uses **Fernet (AES-128)**
* Key derived using **PBKDF2HMAC (SHA-256, 200,000 iterations)**
* Random **16-byte salt** per encryption

### LSB Steganography

* Hides encrypted binary data inside pixel LSBs
* Completely invisible to the naked eye

### Automatic Payload Handling

Packet format:

```
[16-byte Salt] + [4-byte Payload Length] + [Encrypted Data]
```

### Lossless Output

* Saves as **PNG** to avoid compression artifacts

---

## Installation

```bash
git clone https://github.com/Himas18/Image_steganography_encryption_tool
cd Image_steganography_encryption_tool
pip install -r requirements.txt
```

---

## Running the Application

```bash
python main.py
```

---

## Usage Guide

### Hide a Message (Encrypt + Embed)

1. Click **Open Image…** and load a PNG source image
2. Enter your **secret message**
3. Enter a **password** (required for encryption)
4. Click **Hide into Image**
5. The output file is saved as `*_stego.png`

---

### Reveal a Message (Extract + Decrypt)

1. Open the application
2. Load the **stego-image** (if not already open)
3. Enter the **same password** used for encryption
4. Click **Reveal Message**
5. The decrypted message appears in the output box

---

## Technical Overview

* Generates a **16-byte salt** for every encryption
* Derives key using:

```
PBKDF2HMAC(algorithm=SHA256, iterations=200000)
```

* Embeds bits sequentially into **R, G, B** channels
* Only the **LSB** of each channel is modified

---

## Important Notes

* **Do not convert the output PNG to JPG/JPEG** — JPEG compression alters pixel values and destroys the embedded data.
* Works best with **high-resolution PNG** images.

---

## License

MIT License
