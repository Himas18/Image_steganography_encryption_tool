import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
import secrets, base64, struct
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

# --- Crypto helpers ---
def derive_fernet_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    pwd = password.encode()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=iterations, backend=default_backend())
    raw = kdf.derive(pwd)
    return base64.urlsafe_b64encode(raw)

def encrypt_message(message: str, password: str) -> bytes:
    salt = secrets.token_bytes(16)
    key = derive_fernet_key(password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(message.encode())
    length = len(encrypted)
    header = salt + struct.pack(">I", length)
    return header + encrypted

def decrypt_message(payload: bytes, password: str) -> str:
    if len(payload) < 20:
        raise ValueError("Payload too short")
    salt = payload[:16]
    length = struct.unpack(">I", payload[16:20])[0]
    encrypted = payload[20:20+length]
    key = derive_fernet_key(password, salt)
    f = Fernet(key)
    plain = f.decrypt(encrypted)
    return plain.decode()

# --- Stego helpers ---
def _pixels_from_image(img: Image.Image):
    # Convert to RGB and return list of tuples
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    data = list(img.getdata())
    has_alpha = (img.mode == "RGBA")
    return data, has_alpha, img.mode, img.size

def embed_payload_in_image(in_path: str, out_path: str, payload: bytes):
    img = Image.open(in_path)
    data, has_alpha, mode, (w, h) = _pixels_from_image(img)
    capacity = len(data) * 3 
    total_bits = len(payload) * 8
    if total_bits > capacity:
        raise ValueError(f"Payload too large for image capacity ({total_bits} > {capacity})")

    bits = ''.join(f"{byte:08b}" for byte in payload)
    bit_idx = 0
    new_pixels = []
    for px in data:
        r, g, b = px[0], px[1], px[2]
        r = (r & ~1) | (int(bits[bit_idx]) if bit_idx < total_bits else (r & 1)); bit_idx += 1 if bit_idx < total_bits else 0
        g = (g & ~1) | (int(bits[bit_idx]) if bit_idx < total_bits else (g & 1)); bit_idx += 1 if bit_idx < total_bits else 0
        b = (b & ~1) | (int(bits[bit_idx]) if bit_idx < total_bits else (b & 1)); bit_idx += 1 if bit_idx < total_bits else 0
        if has_alpha:
            a = px[3]
            new_pixels.append((r, g, b, a))
        else:
            new_pixels.append((r, g, b))
    # Building image and saving it as PNG to avoid compression losses
    out_img = Image.new("RGBA" if has_alpha else "RGB", (w, h))
    out_img.putdata(new_pixels)
    out_img.save(out_path, format="PNG")

def extract_payload_from_image(in_path: str) -> bytes:
    img = Image.open(in_path)
    data, has_alpha, mode, (w, h) = _pixels_from_image(img)
    bits = []
    for px in data:
        bits.append(str(px[0] & 1))
        bits.append(str(px[1] & 1))
        bits.append(str(px[2] & 1))
    bitstring = ''.join(bits)
    if len(bitstring) < 160:
        raise ValueError("Image too small / no payload")
    header_bits = bitstring[:160]
    header_bytes = bytes(int(header_bits[i:i+8], 2) for i in range(0, 160, 8))
    salt = header_bytes[:16]
    length = struct.unpack(">I", header_bytes[16:20])[0]
    total_bits_needed = (16 + 4 + length) * 8
    if len(bitstring) < total_bits_needed:
        raise ValueError("Image does not contain full payload or is corrupted")
    payload_bits = bitstring[:total_bits_needed]
    payload_bytes = bytes(int(payload_bits[i:i+8], 2) for i in range(0, total_bits_needed, 8))
    return payload_bytes

class StegGUI:
    def __init__(self, root):
        self.root = root
        root.title("Stego+Encrypt Tool")
        root.geometry("820x520")
        self.in_path = None
        self.out_path = None

        left = tk.Frame(root)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=8)

        self.canvas = tk.Label(left, text="No image", width=48, height=20, relief=tk.SUNKEN, anchor=tk.CENTER)
        self.canvas.pack(padx=4, pady=4)

        btn_frame = tk.Frame(left)
        btn_frame.pack(pady=6)
        tk.Button(btn_frame, text="Open Image...", command=self.open_image).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text="Save As...", command=self.save_as).pack(side=tk.LEFT, padx=4)

    
        right = tk.Frame(root)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=8, pady=8)


        tk.Label(right, text="Hide (encrypt & embed)").pack(anchor="w")
        tk.Label(right, text="Message:").pack(anchor="w")
        self.msg_text = scrolledtext.ScrolledText(right, height=6)
        self.msg_text.pack(fill=tk.X, padx=2)

        tk.Label(right, text="Password (for encryption):").pack(anchor="w", pady=(6,0))
        self.pw_entry = tk.Entry(right, show="*")
        self.pw_entry.pack(fill=tk.X, padx=2)

        tk.Button(right, text="Hide into Image", command=self.hide_into_image, bg="#4caf50", fg="white").pack(pady=8)

        tk.Label(right, text="").pack() 
     
        tk.Label(right, text="Reveal (extract & decrypt)").pack(anchor="w", pady=(10,0))
        tk.Label(right, text="Password (for decryption):").pack(anchor="w")
        self.pw_entry2 = tk.Entry(right, show="*")
        self.pw_entry2.pack(fill=tk.X, padx=2)

        tk.Button(right, text="Reveal Message", command=self.reveal_from_image, bg="#2196f3", fg="white").pack(pady=8)

        tk.Label(right, text="Extracted message:").pack(anchor="w", pady=(8,0))
        self.out_text = scrolledtext.ScrolledText(right, height=8)
        self.out_text.pack(fill=tk.BOTH, expand=True, padx=2)


        self.status = tk.Label(root, text="Ready", bd=1, relief=tk.SUNKEN, anchor="w")
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    def open_image(self):
        p = filedialog.askopenfilename(filetypes=[("Image files","*.png;*.jpg;*.jpeg;*.bmp;*.tiff"), ("All files","*.*")])
        if not p:
            return
        self.in_path = p
        img = Image.open(p)
        img.thumbnail((380, 380))
        self.tkimg = ImageTk.PhotoImage(img)
        self.canvas.config(image=self.tkimg, text="")
        self.status.config(text=f"Opened {p}")

    def save_as(self):
        p = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG","*.png")])
        if p:
            self.out_path = p
            self.status.config(text=f"Will save to {p}")

    def hide_into_image(self):
        if not self.in_path:
            messagebox.showwarning("No image", "Open an image first")
            return
        msg = self.msg_text.get("1.0", tk.END).rstrip("\n")
        if not msg:
            messagebox.showwarning("No message", "Enter a message to hide")
            return
        password = self.pw_entry.get()
        if not password:
            messagebox.showwarning("No password", "Enter a password")
            return
        outp = self.out_path or (self.in_path.rsplit(".",1)[0] + "_stego.png")
        try:
            payload = encrypt_message(msg, password)
            embed_payload_in_image(self.in_path, outp, payload)
            messagebox.showinfo("Done", f"Hidden message saved to:\n{outp}")
            self.status.config(text=f"Hidden message saved to {outp}")
            self.out_path = outp
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status.config(text=f"Error: {e}")

    def reveal_from_image(self):
        img_path = self.in_path or filedialog.askopenfilename(filetypes=[("PNG","*.png;*.jpg;*.jpeg;*.bmp;*.tiff")])
        if not img_path:
            return
        password = self.pw_entry2.get()
        if not password:
            messagebox.showwarning("No password", "Enter password for decryption")
            return
        try:
            payload = extract_payload_from_image(img_path)
            plain = decrypt_message(payload, password)
            self.out_text.delete("1.0", tk.END)
            self.out_text.insert(tk.END, plain)
            messagebox.showinfo("Success", "Message extracted and decrypted")
            self.status.config(text=f"Message revealed from {img_path}")
        except Exception as e:
            messagebox.showerror("Failed", f"Failed to reveal/decrypt: {e}")
            self.status.config(text=f"Failed: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = StegGUI(root)
    root.mainloop()
