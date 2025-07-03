import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk
import os
import json
import struct
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import threading
import datetime
import traceback

# --- Utility Functions for Encryption/Decryption ---
# (این بخش‌ها تغییری نکرده‌اند)
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # AES-256 requires 32 bytes
        salt=salt,
        iterations=400000, # More iterations increase security but slow down
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_path: str, key: bytes) -> bytes:
    cipher_suite = Fernet(key)
    with open(file_path, "rb") as f:
        file_data = f.read()
    encrypted_data = cipher_suite.encrypt(file_data)
    return encrypted_data

def decrypt_data(encrypted_data: bytes, key: bytes) -> bytes:
    cipher_suite = Fernet(key)
    decrypted_data = cipher_suite.decrypt(encrypted_data)
    return decrypted_data

# --- VCM Packer Class ---
class VCMPacker(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.master.title("VCM Packer 2018")
        self.pack(fill="both", expand=True)
        self.create_widgets()

        self.encryption_key = None
        self.salt = os.urandom(16)

    def create_widgets(self):
        # --- Packer Section ---
        packer_frame = tk.LabelFrame(self, text="VCM Packer", padx=10, pady=10)
        packer_frame.pack(padx=10, pady=10, fill="x")

        tk.Label(packer_frame, text="Folder path for save:").grid(row=0, column=0, sticky="w", pady=5)
        self.folder_path_entry = tk.Entry(packer_frame, width=50)
        self.folder_path_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(packer_frame, text="Select folder", command=self.select_folder).grid(row=0, column=2, padx=5, pady=5)

        tk.Label(packer_frame, text="File name:").grid(row=1, column=0, sticky="w", pady=5)
        self.output_vcm_entry = tk.Entry(packer_frame, width=50)
        self.output_vcm_entry.insert(0, "output.vcm")
        self.output_vcm_entry.grid(row=1, column=1, padx=5, pady=5)

        self.pack_progress = ttk.Progressbar(packer_frame, orient="horizontal", length=300, mode="determinate")
        self.pack_progress.grid(row=3, column=0, columnspan=3, pady=10)
        self.pack_progress["value"] = 0

        tk.Button(packer_frame, text="Start", command=self.start_pack_operation, bg="green", fg="white").grid(row=2, column=1, pady=10)

        # --- Unpacker Section ---
        unpacker_frame = tk.LabelFrame(self, text="VCM Unpacker", padx=10, pady=10)
        unpacker_frame.pack(padx=10, pady=10, fill="x")

        tk.Label(unpacker_frame, text="VCM file location for extract:").grid(row=0, column=0, sticky="w", pady=5)
        self.vcm_path_entry = tk.Entry(unpacker_frame, width=50)
        self.vcm_path_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Button(unpacker_frame, text="Select VCM file", command=self.select_vcm_file).grid(row=0, column=2, padx=5, pady=5)

        tk.Label(unpacker_frame, text="Destination folder path for extraction:").grid(row=1, column=0, sticky="w", pady=5)
        self.extract_path_entry = tk.Entry(unpacker_frame, width=50)
        self.extract_path_entry.grid(row=1, column=1, padx=5, pady=5)
        tk.Button(unpacker_frame, text="Select destination folder", command=self.select_extract_folder).grid(row=1, column=2, padx=5, pady=5)

        self.unpack_progress = ttk.Progressbar(unpacker_frame, orient="horizontal", length=300, mode="determinate")
        self.unpack_progress.grid(row=3, column=0, columnspan=3, pady=10)
        self.unpack_progress["value"] = 0

        tk.Button(unpacker_frame, text="Start", command=self.start_unpack_operation, bg="blue", fg="white").grid(row=2, column=1, pady=10)

    def select_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.folder_path_entry.delete(0, tk.END)
            self.folder_path_entry.insert(0, folder_selected)

    def select_vcm_file(self):
        file_selected = filedialog.askopenfilename(defaultextension=".vcm", filetypes=[("VCM files", "*.vcm")])
        if file_selected:
            self.vcm_path_entry.delete(0, tk.END)
            self.vcm_path_entry.insert(0, file_selected)

    def select_extract_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.extract_path_entry.delete(0, tk.END)
            self.extract_path_entry.insert(0, folder_selected)

    def start_pack_operation(self):
        source_folder = self.folder_path_entry.get()
        output_vcm_file = self.output_vcm_entry.get()

        if not source_folder or not os.path.isdir(source_folder):
            messagebox.showerror("ERROR", "Please select a valid folder for packaging.")
            return
        if not output_vcm_file:
            messagebox.showerror("ERROR", "Please enter the file name. The file name should not be separated and fill in the blanks with - or _ symbols. Also, do not use the @ and # symbols.")
            return

        password = simpledialog.askstring("ENCRYPTION", "Enter a strong password for your VCM file:", show='*')
        if not password:
            messagebox.showwarning("WARNING", "Packaging will not be done without a password.")
            self.pack_progress["value"] = 0
            return
        
        threading.Thread(target=self.pack_folder, args=(password,)).start()

    def pack_folder(self, password):
        source_folder = self.folder_path_entry.get()
        output_vcm_file = self.output_vcm_entry.get()

        try:
            self.encryption_key = derive_key(password, self.salt)
            file_metadata = []
            total_files = 0
            for root, _, files in os.walk(source_folder):
                total_files += len(files)

            self.pack_progress["maximum"] = total_files
            processed_files = 0

            for root, _, files in os.walk(source_folder):
                for file_name in files:
                    full_file_path = os.path.join(root, file_name)
                    relative_path = os.path.relpath(full_file_path, source_folder)

                    try:
                        encrypted_data = encrypt_file(full_file_path, self.encryption_key)
                        file_metadata.append({
                            'path': relative_path,
                            'data': base64.b64encode(encrypted_data).decode('utf-8')
                        })
                    except Exception as e:
                        self.log_error("Packaging Error", f"Error encrypting file: {relative_path}", str(e))

                    processed_files += 1
                    self.pack_progress["value"] = processed_files
                    self.update_idletasks()

            metadata_json = json.dumps(file_metadata).encode('utf-8')

            with open(output_vcm_file, "wb") as f:
                f.write(b"VCMF")
                f.write(struct.pack("<I", len(self.salt)))
                f.write(self.salt)
                f.write(struct.pack("<I", len(metadata_json)))
                f.write(metadata_json)

            self.master.after(0, lambda: messagebox.showinfo("DONE", f"Folder '{source_folder}' successfully saved to '{output_vcm_file}' ."))
            # --- خط اصلاح شده ---
            self.master.after(0, lambda: self.pack_progress.__setitem__("value", total_files)) # Correct way to set progress to 100%

        except Exception as e:
            self.log_error("Packaging Error", "An unexpected error occurred during packaging.", str(e))
            self.master.after(0, lambda: messagebox.showerror("ERROR", f"An error occurred while packaging: {e}"))
            # --- خط اصلاح شده ---
            self.master.after(0, lambda: self.pack_progress.__setitem__("value", 0)) # Correct way to reset progress bar

    def start_unpack_operation(self):
        vcm_file_path = self.vcm_path_entry.get()
        extract_destination = self.extract_path_entry.get()

        if not vcm_file_path or not os.path.isfile(vcm_file_path):
            messagebox.showerror("ERROR", "Please select a valid vcm file.")
            return
        if not extract_destination:
            messagebox.showerror("ERROR", "Please select a destination folder for extraction.")
            return

        password = simpledialog.askstring("ENCRYPTION", "Enter password:", show='*')
        if not password:
            messagebox.showwarning("WARNING", "Password required.")
            self.unpack_progress["value"] = 0
            return
        
        threading.Thread(target=self.unpack_vcm, args=(password,)).start()

    def unpack_vcm(self, password):
        vcm_file_path = self.vcm_path_entry.get()
        extract_destination = self.extract_path_entry.get()

        try:
            with open(vcm_file_path, "rb") as f:
                magic_bytes = f.read(4)
                if magic_bytes != b"VCMF":
                    raise ValueError("The vcm file is invalid. (Wrong Magic Bytes)")

                salt_len = struct.unpack("<I", f.read(4))[0]
                salt = f.read(salt_len)

                metadata_len = struct.unpack("<I", f.read(4))[0]
                metadata_json = f.read(metadata_len).decode('utf-8')

                file_metadata = json.loads(metadata_json)

            self.encryption_key = derive_key(password, salt)

            total_files = len(file_metadata)
            self.unpack_progress["maximum"] = total_files
            processed_files = 0

            for item in file_metadata:
                relative_path = item['path']
                encrypted_data_b64 = item['data']
                encrypted_data = base64.b64decode(encrypted_data_b64)

                try:
                    decrypted_data = decrypt_data(encrypted_data, self.encryption_key)
                    full_output_path = os.path.join(extract_destination, relative_path)
                    os.makedirs(os.path.dirname(full_output_path), exist_ok=True)

                    with open(full_output_path, "wb") as out_f:
                        out_f.write(decrypted_data)

                except Exception as e:
                    self.log_error("Unpacking Error", f"Error decrypting file: {relative_path}", str(e))

                processed_files += 1
                self.unpack_progress["value"] = processed_files
                self.update_idletasks()

            self.master.after(0, lambda: messagebox.showinfo("DONE", f" '{vcm_file_path}' successfully extracted to '{extract_destination}' ."))
            # --- خط اصلاح شده ---
            self.master.after(0, lambda: self.unpack_progress.__setitem__("value", total_files)) # Correct way to set progress to 100%

        except Exception as e:
            self.log_error("Unpacking Error", "An unexpected error occurred during extraction.", str(e))
            self.master.after(0, lambda: messagebox.showerror("ERROR", f"An error occurred during extraction: {e}"))
            # --- خط اصلاح شده ---
            self.master.after(0, lambda: self.unpack_progress.__setitem__("value", 0)) # Correct way to reset progress bar

    # (متد log_error تغییری نکرده است و می‌تواند همانند قبل باشد)
    def log_error(self, error_type, description, details=""):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        full_traceback = traceback.format_exc()
        if "NoneType: None" in full_traceback or "Traceback (most recent call last):\n  None\n" in full_traceback:
            full_traceback = "No specific Python traceback available at this point."

        error_info = {
            "timestamp": timestamp,
            "type": error_type,
            "description": description,
            "details": details,
            "traceback": full_traceback
        }

        # Ensure we append properly to an existing HTML file, or create a new valid one.
        # This logic ensures proper HTML structure.
        file_path = "error_log.html"
        log_entry_html = f"""
        <div class="error-entry">
            <h2>Error Type: {error_info['type']}</h2>
            <p><strong>Timestamp:</strong> {error_info['timestamp']}</p>
            <p><strong>Description:</strong> {error_info['description']}</p>
            <h3>Details:</h3>
            <pre>{error_info['details']}</pre>
            <h3>Traceback:</h3>
            <pre>{error_info['traceback']}</pre>
        </div>
        <hr>
        """
        
        try:
            if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
                # Create a new file with full HTML structure if it doesn't exist or is empty
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VCM Packer Error Log</title>
    <style>
        body { font-family: sans-serif; margin: 20px; }
        .error-entry { border: 1px solid #ffcc00; padding: 15px; margin-bottom: 20px; background-color: #fffacd; }
        h2 { color: #cc0000; }
        pre { background-color: #eee; padding: 10px; border-radius: 5px; overflow-x: auto; }
        hr { border: 0; height: 1px; background: #333; background-image: linear-gradient(to right, #ccc, #333, #ccc); margin: 30px 0; }
    </style>
</head>
<body>
    <h1>VCM Packer Error Log</h1>
""")
                    f.write(log_entry_html)
                    f.write("</body>\n</html>\n")
            else:
                # Append just the new log entry before the closing </body> tag
                # Read content, remove </body></html>, add new content, then add them back
                with open(file_path, "r+", encoding="utf-8") as f:
                    content = f.read()
                    # Find last occurrence of </body> and insert before it
                    insert_point = content.rfind("</body>")
                    if insert_point != -1:
                        f.seek(insert_point)
                        f.truncate() # Remove content from insert_point to end
                        f.write(log_entry_html)
                        f.write("</body>\n</html>\n")
                    else:
                        # Fallback if structure is unexpected, just append (less ideal)
                        f.write(log_entry_html)

        except Exception as file_e:
            print(f"Error writing to error_log.html: {file_e}")


# --- Main App Execution ---
if __name__ == "__main__":
    root = tk.Tk()
    app = VCMPacker(master=root)
    root.mainloop()

