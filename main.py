import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog as fd
import rsa
import os


class CodeFrame:
    def __init__(self, parent_frame, name, func):
        self.main_frame = tk.Frame(master=parent_frame, bd=2)
        self.input_scrollbar = tk.Scrollbar(self.main_frame)
        self.output_scrollbar = tk.Scrollbar(self.main_frame)
        self.input_label = tk.Label(self.main_frame, text='Decode Input', justify=tk.CENTER, bd=2)
        self.input_text = tk.Text(self.main_frame, bd=2, height=5, width=32, yscrollcommand=self.input_scrollbar.set)
        self.output_label = tk.Label(self.main_frame, text='Decode Output', justify=tk.CENTER, bd=2)
        self.btn = tk.Button(self.main_frame, text=name, command=func, bd=2, bg='#ffff00')
        self.output_text = tk.Text(self.main_frame, bd=2, height=5, width=32, yscrollcommand=self.output_scrollbar.set)
        self.input_scrollbar.config(command=self.input_text.yview)
        self.output_scrollbar.config(command=self.output_text.yview)

        self.input_label.grid(column=0, columnspan=4, row=0, sticky="WESN")
        self.input_text.grid(column=0, columnspan=3, row=1, sticky="WESN")
        self.input_scrollbar.grid(column=3, row=1, sticky="WESN")
        self.output_label.grid(column=0, columnspan=3, row=2, sticky="WESN")
        self.btn.grid(column=3, row=2, sticky="WESN")
        self.output_text.grid(column=0, columnspan=3, row=3, sticky="WESN")
        self.output_scrollbar.grid(column=3, row=3, sticky="WESN")


class KeyFrame:
    def add_key(self):
        file_name = fd.askopenfilename()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, file_name)

    def __init__(self, parent_frame, name):
        self.main_frame = tk.Frame(master=parent_frame, bd=2)
        self.key_label = tk.Label(self.main_frame, text=name, justify=tk.CENTER, bd=2)
        self.key_entry = tk.Entry(self.main_frame, justify=tk.RIGHT, bd=2)
        self.key_btn = tk.Button(self.main_frame, text='View', command=self.add_key, bg='#ffff00', bd=2)

        self.key_label.grid(column=0, row=0, sticky="WESN")
        self.key_entry.grid(column=0, row=1, sticky="WESN")
        self.key_btn.grid(column=1, row=1, sticky="WESN")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.encoded_text_tmp = ''
        self.init_keys()
        self.configure(background='#ffe4c4')
        self.title('To DO list')
        self.iconbitmap('coder.ico')
        self.wm_iconbitmap('coder.ico')
        self.grid_columnconfigure(1, weight=1)

        # Frames
        self.pub_frame = KeyFrame(self, 'Public')
        self.priv_frame = KeyFrame(self, 'Private')
        self.encode_frame = CodeFrame(self, 'Encode', func=self.__encode)
        self.decode_frame = CodeFrame(self, 'Decode', func=self.__decode)

        # location
        self.pub_frame.main_frame.grid(column=0, row=0, sticky="WESN")
        self.priv_frame.main_frame.grid(column=1, row=0, sticky="WESN")
        self.encode_frame.main_frame.grid(column=0, row=2, sticky="WESN")
        self.decode_frame.main_frame.grid(column=1, row=2, sticky="WESN")

    def __encode(self):
        filename = self.pub_frame.key_entry.get()
        if len(filename) == 0:
            messagebox.showinfo('Encode error', 'File is not found')
            return
        with open(filename, "rb") as file:
            public = file.read()
        pubkey = rsa.PublicKey.load_pkcs1(public)
        self.encode_frame.output_text.delete('1.0', tk.END)
        message = self.encode_frame.input_text.get('1.0', 'end-1c').encode('utf-8')
        message = rsa.encrypt(message, pubkey)
        self.encoded_text_tmp = message
        self.encode_frame.output_text.insert(tk.END, message)

    def __decode(self):
        filename = self.priv_frame.key_entry.get()
        if len(filename) == 0:
            messagebox.showinfo('Encode error', 'File is not found')
            return
        with open(filename, "rb") as file:
            private = file.read()
        privkey = rsa.PrivateKey.load_pkcs1(private)
        self.decode_frame.output_text.delete('1.0', tk.END)
        message = self.encoded_text_tmp
        message = rsa.decrypt(message, privkey)
        self.decode_frame.output_text.insert(tk.END, message)

    @staticmethod
    def init_keys():
        (pub, priv) = rsa.newkeys(256)
        with open("pub.pem", "wb") as file:
            file.write(pub.save_pkcs1())
        with open("priv.pem", "wb") as file:
            file.write(priv.save_pkcs1())


if __name__ == '__main__':
    my_app = App()
    my_app.mainloop()
