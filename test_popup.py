import tkinter as tk
from tkinter import messagebox
root = tk.Tk()
root.title('RANSOMWARE TEST')
root.geometry('1024x768')
root.configure(bg='black')
root.attributes('-topmost', True)
tk.Label(root, text='CRITICAL SYSTEM ALERT', font=('Impact', 48), fg='red', bg='black').pack(pady=50)
tk.Label(root, text='Team DON''T WANNA CRY', font=('Arial', 28), fg='orange', bg='black').pack(pady=20)
tk.Label(root, text='Your files have been encrypted!', font=('Arial', 18), fg='#00ff41', bg='black').pack(pady=20)
tk.Label(root, text='72:00:00', font=('Arial', 72), fg='red', bg='black').pack(pady=30)
tk.Button(root, text='UNLOCK SYSTEM', font=('Arial', 20), bg='white', fg='red', command=root.destroy).pack(pady=40)
root.mainloop()
