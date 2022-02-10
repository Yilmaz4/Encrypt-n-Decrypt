"""
MIT License

Copyright 2017-2022 Yilmaz Alpaslan

Permission is hereby granted, free ofy person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be included in all copies
or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

version = "0.2.1"

from tkinter import *
from tkinter import _flatten, _join, _stringify, _splitdict
TkLabel = Label
from tkinter import messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
from tkinter.commondialog import Dialog
from tkinter.ttk import *

from typing import Any, Union, Optional, Literal
from urllib.request import urlopen
from markdown import markdown
from tkinterweb import HtmlFrame
from requests import get, head
from webbrowser import open as openweb
from string import ascii_letters, digits
from getpass import getuser
from ctypes import windll
from zipfile import ZipFile
from datetime import datetime
from random import randint, choice
from hurry.filesize import size, alternative
from time import sleep

from Crypto.Cipher import AES, PKCS1_OAEP, DES3
from Crypto.Util import Counter
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

import base64, os, logging, pyperclip, binascii

class Crypto:
    def __init__(self, master: Tk):
        self.master = master

    @staticmethod
    def generateKey(length: int = 32) -> str:
        key = str()
        for i in range(int(length)):
            random = randint(1,32)
            if random < 25:
                key += str(choice(ascii_letters))
            elif random >= 25 and random < 30:
                key += str(choice(digits))
            elif random >= 30:
                key += str(choice("!'^+%&/()=?_<>#${[]}\|__--$__--"))
        return key
    
    def updateStatus(self, status: str):
        self.master.statusBar.configure(text=f"Status: {status}")
        self.master.update()

    def encrypt(self):
        if not bool(self.master.dataSourceVar.get()):
            data = self.master.textEntryVar.get()
        else:
            self.updateStatus("Reading the file...")
            path = self.master.fileEntry.get()
            try:
                with open(path, mode="rb") as file:
                    data = file.read()
            except PermissionError:
                messagebox.showerror("Permission denied", "Access to the file you've specified has been denied. Try running the program as administrator and make sure read & write access for the file is permitted.")
                self.master.logger.error("Read permission for the file specified has been denied, encryption was interrupted.")
                self.updateStatus("Ready")
                return
        if not bool(self.master.algorithmSelect.index(self.master.algorithmSelect.select())):
            if not bool(self.master.keySourceSelection.get()):
                self.updateStatus("Generating the key...")
                if not bool(self.master.generateAlgorithmSelection.get()):
                    key = self.generateKey(int(self.master.generateRandomAESVar.get() / 8))
                else:
                    key = self.generateKey(int(self.master.generateRandomDESVar.get() / 8))
            else:
                key = self.master.keyEntryVar.get()
            if type(key) is str:
                key = bytes(key, "utf-8")

            self.updateStatus("Creating the cipher...")
            try:
                if (not bool(self.master.generateAlgorithmSelection.get()) and not bool(self.master.keySourceSelection.get())) or (not bool(self.master.entryAlgorithmSelection.get()) and bool(self.master.keySourceSelection.get())):
                    iv = get_random_bytes(AES.block_size)
                    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
                else:
                    iv = get_random_bytes(DES3.block_size)
                    cipher = DES3.new(key, mode=DES3.MODE_OFB, iv=iv)
            except ValueError as details:
                if not len(key) in [16, 24, 32 if "AES" in str(details) else False]:
                    messagebox.showerror("Invalid key length", "The length of the encryption key you've entered is invalid! It can be either 16, 24 or 32 characters long.")
                    self.master.logger.error("Key with invalid length specified.")
                    self.updateStatus("Ready")
                    return
                else:
                    messagebox.showerror("Invalid key", "The key you've entered is invalid for encryption. Please enter another key or consider generating one instead.")
                    self.master.logger.error("Invalid key specified.")
                    self.updateStatus("Ready")
                    return

            self.updateStatus("Encrypting...")
            try:
                self.master.lastResult = iv + cipher.encrypt(data.encode("utf-8") if type(data) is str else data)
            except MemoryError:
                messagebox.showerror("Not enough memory", "Your computer has run out of memory while encrypting the file. Try closing other applications or restart your computer.")
                self.master.logger.error("Device has run out of memory while encrypting, encryption was interrupted.")
                self.updateStatus("Ready")
                return
            del data
            self.updateStatus("Encoding the result...")
            try:
                self.master.lastResult = base64.urlsafe_b64encode(self.master.lastResult).decode("utf-8")
            except MemoryError:
                messagebox.showerror("Not enough memory", "Your computer has run out of memory while encoding the result. Try closing other applications or restart your computer.")
                self.master.logger.error("Device has run out of memory while encoding, encryption was interrupted.")
                self.updateStatus("Ready")
                return
            self.master.lastKey = key

            if bool(self.master.dataSourceVar.get()) and bool(self.master.writeFileContentVar.get()):
                self.updateStatus("Writing to the file...")
                try:
                    with open(path, mode="wb") as file:
                        file.write(bytes(self.master.lastResult, "utf-8"))
                except PermissionError:
                    messagebox.showerror("Permission denied", "Access to the file you've specified has been denied. Try running the program as administrator and make sure write access for the file is permitted.")
                    self.master.logger.error("Write permission for the file specified has been denied, encrypted was interrupted.")
                    self.updateStatus("Ready")
                    return
                except OSError as details:
                    if "No space" in str(details):
                        messagebox.showerror("No space left", "There is no space left on your device. Free up some space and try again.")
                        self.master.logger.error("No space left on device, encryption was interrupted.")
                        self.updateStatus("Ready")
                        return

            self.updateStatus("Displaying the result...")
            self.master.outputText.configure(state=NORMAL)
            if not len(self.master.lastResult) > 15000:
                self.master.outputText.configure(foreground="black", wrap=None)
                self.master.outputText.replace(self.master.lastResult)
            else:
                self.master.outputText.configure(foreground="gray", wrap=WORD)
                self.master.outputText.replace("The encrypted text is not being displayed because it is longer than 15.000 characters.")
            self.master.outputText.configure(state=DISABLED)

            self.master.AESKeyText.configure(state=NORMAL)
            self.master.AESKeyText.replace(key.decode("utf-8"))
            self.master.AESKeyText.configure(state=DISABLED)

            self.updateStatus("Ready")
            if not bool(self.master.keySourceSelection.get()):
                self.master.logger.info(f"{'Entered text' if not bool(self.master.dataSourceVar.get()) else 'Specified file'} has been successfully encrypted using {'AES' if not bool(self.master.generateAlgorithmSelection.get()) else '3DES'}-{len(key) * 8} algorithm.")
            else:
                self.master.logger.info(f"{'Entered text' if not bool(self.master.dataSourceVar.get()) else 'Specified file'} has been successfully encrypted using {'AES' if not bool(self.master.entryAlgorithmSelection.get()) else '3DES'}-{len(key) * 8} algorithm.")
        else:
            self.updateStatus("Generating the key...")
            key = RSA.generate(1024)

            self.updateStatus("Exporting the public key...")
            publicKey = key.publickey()
            self.updateStatus("Exporting the private key..")
            privateKey = key.exportKey()

            msg = bytes('Herkese merhaba arkadaşlar.', "utf-8")
            encryptor = PKCS1_OAEP.new(publicKey)
            encrypted = encryptor.encrypt(msg)
            print("Encrypted:", base64.urlsafe_b64encode(encrypted).decode())

            decryptor = PKCS1_OAEP.new(RSA.import_key(privateKey))
            decrypted = decryptor.decrypt(encrypted)
            print('Decrypted:', decrypted.decode())

    def decrypt(self):
        if not bool(self.master.decryptSourceVar.get()):
            self.updateStatus("Decoding encrypted data...")
            data = base64.urlsafe_b64decode(self.master.textDecryptVar.get().encode("utf-8"))
        else:
            self.updateStatus("Reading the file...")
            try:
                with open(self.master.fileDecryptEntry.get(), mode="r+b") as file:
                    data = file.read()
            except PermissionError:
                messagebox.showerror("Permission denied", "Access to the file you've specified has been denied. Try running the program as administrator and make sure read & write access for the file is permitted.")
                self.master.logger.error("Read permission for the file specified has been denied, decryption was interrupted.")
                self.updateStatus("Ready")
                return
            self.updateStatus("Decoding the file data...")
            try:
                decodedData = base64.urlsafe_b64decode(data)
            except:
                messagebox.showerror("Unencrypted file", f"This file seems to be not encrypted using AES nor DES symmetric key encryption algorithm.")
                self.master.logger.error("Unencrypted file specified.")
                self.updateStatus("Ready")
                return
            else:
                if data == base64.urlsafe_b64encode(decodedData):
                    data = decodedData
                    del decodedData
                else:
                    messagebox.showerror("Unencrypted file", f"This file seems to be not encrypted using AES nor DES symmetric key encryption algorithm.")
                    self.master.logger.error("Unencrypted file specified.")
                    self.updateStatus("Ready")
                    return
        iv = data[:16 if not bool(self.master.decryptAlgorithmVar.get()) else 8]
        key = self.master.decryptKeyVar.get()[:-1 if self.master.decryptKeyVar.get().endswith("\n") else None].encode("utf-8")

        self.updateStatus("Defining cipher...")
        try:
            if not bool(self.master.decryptAlgorithmVar.get()):
                cipher = AES.new(key, AES.MODE_CFB, iv=iv)
            else:
                cipher = DES3.new(key, DES3.MODE_OFB, iv=iv)
        except ValueError as details:
            if not len(key) in [16, 24, 32 if "AES" in str(details) else False]:
                messagebox.showerror("Invalid key length", "The length of the encryption key you've entered is invalid! It can be either 16, 24 or 32 characters long.")
                self.master.logger.error("Key with invalid length specified for decryption.")
                self.updateStatus("Ready")
                return
            else:
                messagebox.showerror("Invalid key", "The key you've entered is invalid.")
                self.master.logger.error("Invalid key specified for decryption.")
                self.updateStatus("Ready")
                return
        self.updateStatus("Decrypting...")
        try:
            result = cipher.decrypt(data.replace(iv, b""))
        except UnicodeDecodeError:
            messagebox.showerror("Invalid key", "The encryption key you've entered seems to be not the right key. Make sure you've entered the correct key.")
            self.master.logger.error("Wrong key entered for decryption.")
            self.updateStatus("Ready")
            return

        self.updateStatus("Writing to the file...")
        if bool(self.master.decryptSourceVar.get()):
            try:
                with open(self.master.fileDecryptEntry.get(), mode="wb") as file:
                    file.write(result)
            except PermissionError:
                messagebox.showerror("Permission denied", "Access to the file you've specified has been denied. Try running the program as administrator and make sure write access for the file is permitted.")
                self.master.logger.error("Write permission for the file specified has been denied, decryption was interrupted.")
                self.updateStatus("Ready")
                return

        self.updateStatus("Displaying the result...")
        try:
            result = result.decode("utf-8")
        except UnicodeDecodeError:
            self.master.decryptOutputText.configure(foreground="gray")
            self.master.decryptOutputText.replace("Decrypted data is not being displayed because it's in an unknown encoding.")
        else:
            if not len(result) > 15000:
                self.master.decryptOutputText.configure(foreground="black")
                self.master.decryptOutputText.replace(result)
            else:
                self.master.decryptOutputText.configure(foreground="gray")
                self.master.decryptOutputText.replace("Decrypted data is not being displayed because it's longer than 15.000 characters.")
        self.updateStatus("Ready")

class loggingHandler(logging.Handler):
    def __init__(self, widget: Text):
        super().__init__()
        self.widget = widget

    def emit(self, record):
        message = self.format(record)
        def append():
            self.widget.configure(state=NORMAL)
            self.widget.insert(END, message + '\n')
            self.widget.configure(state=DISABLED)

            self.widget.yview(END)

        self.widget.after(0, append)
    
    def format(self, record: logging.LogRecord) -> str:
        return str(datetime.now().strftime(r'%Y-%m-%d %H:%M:%S') + " [" + record.levelname + "] " + record.getMessage())

class ScrolledText(Text):
    def __init__(self, master=None, *args, **kwargs):
        try:
            self._textvariable = kwargs.pop("textvariable")
        except KeyError:
            self._textvariable = None
        self.frame = Frame(master)
        self.vbar = Scrollbar(self.frame)
        self.vbar.pack(side=RIGHT, fill=Y)
        kwargs.update({'yscrollcommand': self.vbar.set})
        super().__init__(self.frame, **kwargs)
        self.pack(side=LEFT, fill=BOTH, expand=True)
        self.vbar['command'] = self.yview
        text_meths = vars(Text).keys()
        methods = vars(Pack).keys() | vars(Grid).keys() | vars(Place).keys()
        methods = methods.difference(text_meths)

        for m in methods:
            if m[0] != '_' and m != 'config' and m != 'configure':
                setattr(self, m, getattr(self.frame, m))

        if self._textvariable is not None:
            self.insert("1.0", self._textvariable.get())
        with open("textvariable.tcl", mode="r", encoding="utf-8") as tclfile:
            self.tk.eval(tclfile.read())
        self.tk.eval('''
            rename {widget} _{widget}
            interp alias {{}} ::{widget} {{}} widget_proxy {widget} _{widget}
        '''.format(widget=str(Text.__str__(self))))
        self.bind("<<Change>>", self._on_widget_change)

        if self._textvariable is not None:
            self._textvariable.trace("wu", self._on_var_change)

    def replace(self, chars: str):
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete("1.0", END)
        self.insert("1.0", chars)
        self.configure(state=old_val)

    def _on_var_change(self, *args):
        text_current = self.get("1.0", "end-1c")
        var_current = self._textvariable.get()
        if text_current != var_current:
            self.delete("1.0", "end")
            self.insert("1.0", var_current)

    def _on_widget_change(self, event=None):
        if self._textvariable is not None:
            self._textvariable.set(self.get("1.0", "end-1c"))

    def __str__(self):
        return str(self.frame)

class Text(Text):
    def __init__(self, parent, *args, **kwargs):
        try:
            self._textvariable = kwargs.pop("textvariable")
        except KeyError:
            self._textvariable = None
        super().__init__(parent, *args, **kwargs)
        if self._textvariable is not None:
            self.insert("1.0", self._textvariable.get())
        with open("textvariable.tcl", mode="r", encoding="utf-8") as tclfile:
            self.tk.eval(tclfile.read())
        self.tk.eval('''
            rename {widget} _{widget}
            interp alias {{}} ::{widget} {{}} widget_proxy {widget} _{widget}
        '''.format(widget=str(self)))
        self.bind("<<Change>>", self._on_widget_change)

        if self._textvariable is not None:
            self._textvariable.trace("wu", self._on_var_change)

    def replace(self, chars: str):
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete("1.0", END)
        self.insert("1.0", chars)
        self.configure(state=old_val)

    def _on_var_change(self, *args):
        text_current = self.get("1.0", "end-1c")
        var_current = self._textvariable.get()
        if text_current != var_current:
            self.delete("1.0", "end")
            self.insert("1.0", var_current)

    def _on_widget_change(self, event=None):
        if self._textvariable is not None:
            self._textvariable.set(self.get("1.0", "end-1c"))

class Entry(Entry):
    def replace(self, string: str):
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete(0, END)
        self.insert(0, string)
        self.configure(state=old_val)

"""class Notebook(Notebook):
    def __init__(self, master=None, **kw):
        self.tab_order = {}
        self.current_tab = 0
        super().__init__(master, **kw)

        self.bind("<<NotebookTabChanged>>", self.on_tab_change)
    
    @staticmethod
    def _format_optvalue(value, script=False):
        if script:
            # if caller passes a Tcl script to tk.call, all the values need to
            # be grouped into words (arguments to a command in Tcl dialect)
            value = _stringify(value)
        elif isinstance(value, (list, tuple)):
            value = _join(value)
        return value

    @classmethod
    def _format_optdict(cls, optdict, script=False, ignore=None):
        opts = []
        for opt, value in optdict.items():
            if not ignore or opt not in ignore:
                opts.append("-%s" % opt)
                if value is not None:
                    opts.append(cls._format_optvalue(value, script))
        return _flatten(opts)

    def on_tab_change(self, event = None):
        self.tab_order[self.current_tab].place_forget()
        self.tab_order[self.index(self.select())].place(x=self.winfo_rootx() + 1, y=self.winfo_rooty() + 23)

    def add(self, child, **kw):
        if child.master == self:
            new_child = Frame(self.master)
            for widget in child.winfo_children():
                new_widget_type = eval(str(widget)[str(widget).find("tkinter") + len("tkinter") + 1:].split(" ")[0])
                new_widget = new_widget_type(new_child, )
        if self.tab_order == {}:
            self.tab_order[0] = child
            child.place(x=self.winfo_rootx() + 1, y=self.winfo_rooty() + 23)
        else:
            self.tab_order[int(max(self.tab_order.keys(), key=int)) + 1] = child

        self.tk.call(self._w, "add", Frame(self), *(self._format_optdict(kw)))"""

class Interface(Tk):
    def __init__(self):
        global version
        super().__init__()
        self.withdraw()

        self.height = 580
        self.width = 800
        self.version = version
        del version

        self.title(f"Encrypt-n-Decrypt v{self.version}")
        self.geometry(f"{self.width}x{self.height}")
        self.resizable(width=False, height=False)
        self.minsize(width = self.width, height = self.height)
        self.maxsize(width = self.width, height = self.height)
        try:
            self.iconbitmap("icon.ico")
        except TclError:
            pass
        
        self.mainNotebook = Notebook(self, width=380, height=340)
        self.encryptionFrame = Frame(self.mainNotebook)
        self.decryptionFrame = Frame(self.mainNotebook)
        self.loggingFrame = Frame(self.mainNotebook)
        self.helpFrame = Frame(self.mainNotebook)

        self.mainNotebook.add(self.encryptionFrame, text="Encryption")
        self.mainNotebook.add(self.decryptionFrame, text="Decryption")
        self.mainNotebook.add(self.loggingFrame, text="Logs")
        self.mainNotebook.add(self.helpFrame, text="Help & About")

        self.mainNotebook.pack(fill=BOTH, expand=1, pady=4, padx=4, side=TOP)
        self.loggingWidget = ScrolledText(self.loggingFrame, height=22, width=107, font=("Consolas", 9), state=DISABLED, takefocus=0)

        loghandler = loggingHandler(widget = self.loggingWidget)
        logging.basicConfig(
            format = '%(asctime)s [%(levelname)s] %(message)s',
            level = logging.DEBUG,
            datefmt = r'%Y-%m-%d %H:%M:%S',
            handlers = [loghandler]
        )
        self.logger = logging.getLogger()
        self.logger.propagate = False

        self.crypto = Crypto(self)

        self.__initialize_vars()
        self.__initialize_menu()
        self.__initialize_widgets()
        self.__initialize_bindings()

        self.deiconify()

    @property
    def logging_level(self) -> int:
        return self.logger.level

    @logging_level.setter
    def logging_level(self, level: Optional[Literal[0, 10, 20, 30, 40, 50]] = None) -> None:
        if not not level:
            self.logger.setLevel(level=level)
            self.logger.disabled = False
        else:
            self.logger.setLevel(level=logging.CRITICAL + 1)
            self.logger.disabled = True

    def __initialize_widgets(self):
        # ┌──────────────────┐
        # │ Encryption Frame │
        # └──────────────────┘

        # Plain text & file entries frame
        def changeDataSource():
            if bool(self.dataSourceVar.get()):
                self.writeFileContentCheck.configure(state=NORMAL)
                self.textEntry.configure(state=DISABLED)
                self.textEntryHideCharCheck.configure(state=DISABLED)
                self.textClearButton.configure(state=DISABLED)
                self.textPasteButton.configure(state=DISABLED)

                self.fileEntry.configure(state=NORMAL)
                self.fileBrowseButton.configure(state=NORMAL)
                if self.fileEntryVar.get() != "":
                    self.fileClearButton.configure(state=NORMAL)
                    self.encryptButton.configure(state=NORMAL)
                else:
                    self.fileClearButton.configure(state=DISABLED)
                    self.encryptButton.configure(state=DISABLED)
            else:
                self.writeFileContentCheck.configure(state=DISABLED)
                self.textEntry.configure(state=NORMAL)
                if self.textEntryVar.get() != "":
                    self.textClearButton.configure(state=NORMAL)
                else:
                    self.textClearButton.configure(state=DISABLED)
                self.textEntryHideCharCheck.configure(state=NORMAL)
                self.textPasteButton.configure(state=NORMAL)

                self.fileEntry.configure(state=DISABLED)
                self.fileBrowseButton.configure(state=DISABLED)
                self.fileClearButton.configure(state=DISABLED)
                self.encryptButton.configure(state=NORMAL)
                if bool(self.keySourceSelection.get()):
                    limitKeyEntry()
            if not bool(self.dataSourceVar.get()):
                not self.fileValidityLabel["foreground"] in ["gray", "grey"] and not "[Blank]" in self.fileValidityLabel["text"]
                if not self.fileValidityLabel["foreground"] in ["gray", "grey"] and not "[Blank]" in self.fileValidityLabel["text"]:
                    self.fileValidityStatusColor = self.fileValidityLabel["foreground"]
                self.fileValidityLabel.configure(foreground="gray")
            else:
                try:
                    self.fileValidityLabel.configure(foreground=self.fileValidityStatusColor)
                except AttributeError:
                    self.fileValidityLabel.configure(foreground="gray")

        def fileEntryBrowse():
            files = [("All files","*.*")]
            filePath = filedialog.askopenfilename(title = "Open a file to encrypt", filetypes=files)
            self.fileEntry.delete(0, END)
            self.fileEntry.insert(0, filePath)

        def toggleHideChar():
            self.textEntry.configure(show="●" if bool(self.textEntryHideCharVar.get()) else "")

        def textEntryCallback(*args, **kwargs):
            self.textClearButton.configure(state=DISABLED if self.textEntryVar.get() == "" else NORMAL)
        
        def fileEntryCallback(*args, **kwargs):
            self.fileClearButton.configure(state=DISABLED if self.fileEntryVar.get() == "" else NORMAL)
            self.encryptButton.configure(state=DISABLED if self.fileEntryVar.get() == "" else NORMAL)
            if self.fileEntry.get() != "":
                if os.path.isfile(self.fileEntry.get()):
                    if os.access(self.fileEntry.get(), os.R_OK) and os.access(self.fileEntry.get(), os.W_OK):
                        self.fileValidityLabel.configure(text="Validity: Encryptable", foreground="green")
                    elif os.access(self.fileEntry.get(), os.R_OK) and not os.access(self.fileEntry.get(), os.W_OK):
                        self.fileValidityLabel.configure(text="Validity: Encryptable but not writable", foreground="orange")
                    else:
                        self.fileValidityLabel.configure(text="Validity: Read access was denied", foreground="red")
                else:
                    self.fileValidityLabel.configure(text="Validity: Not a file", foreground="red")
            else:
                self.fileValidityLabel.configure(text="Validity: [Blank]", foreground="gray")

        self.textEntryCheck = Radiobutton(self.encryptionFrame, text="Plain text:", value=0, variable=self.dataSourceVar, command=changeDataSource, takefocus=0)
        self.textEntry = Entry(self.encryptionFrame, width=48, font=("Consolas", 9), state=NORMAL, takefocus=0, textvariable=self.textEntryVar)
        self.textPasteButton = Button(self.encryptionFrame, text="Paste", width=14, state=NORMAL, command=lambda: (self.textEntry.delete(0, END), self.textEntry.insert(0, str(self.clipboard_get()))), takefocus=0)
        self.textClearButton = Button(self.encryptionFrame, text="Clear", width=14, command=lambda: self.textEntry.delete(0, END), takefocus=0, state=DISABLED)
        self.textEntryHideCharCheck = Checkbutton(self.encryptionFrame, text="Hide characters", variable=self.textEntryHideCharVar, onvalue=1, offvalue=0, command=toggleHideChar, takefocus=0)

        self.fileEntryCheck = Radiobutton(self.encryptionFrame, text="File:", value=1, variable=self.dataSourceVar, command=changeDataSource, takefocus=0)
        self.fileValidityLabel = Label(self.encryptionFrame, text="Validity: [Blank]", foreground="gray")
        self.fileEntry = Entry(self.encryptionFrame, width=48, font=("Consolas", 9), state=DISABLED, takefocus=0, textvariable=self.fileEntryVar)
        self.fileBrowseButton = Button(self.encryptionFrame, text="Browse...", width=14, state=DISABLED, command=fileEntryBrowse, takefocus=0)
        self.fileClearButton = Button(self.encryptionFrame, text="Clear", width=14, state=DISABLED, command=lambda: self.fileEntry.delete(0, END), takefocus=0)

        self.textEntryVar.trace("w", textEntryCallback)
        self.fileEntryVar.trace("w", fileEntryCallback)

        self.textEntryCheck.place(x=8, y=2)
        self.textEntry.place(x=24, y=22)
        self.textPasteButton.place(x=23, y=49)
        self.textClearButton.place(x=124, y=49)
        self.textEntryHideCharCheck.place(x=261, y=50)

        self.fileEntryCheck.place(x=8, y=76)
        self.fileValidityLabel.place(x=51, y=77)
        self.fileEntry.place(x=24, y=96)
        self.fileBrowseButton.place(x=23, y=123)
        self.fileClearButton.place(x=124, y=123)

        # Algorithm selection frame
        def changeEnterKeySectionState(state = DISABLED):
            self.keyEntry.configure(state=state)
            self.keyEntryHideCharCheck.configure(state=state)
            self.keyClearButton.configure(state=state)
            self.keyPasteButton.configure(state=state)
            self.keyBrowseButton.configure(state=state)
            self.keyEnteredAlgDES.configure(state=state)
            self.keyEnteredAlgAES.configure(state=state)

        def changeGenerateKeySectionState(state = NORMAL):
            self.AESAlgorithmCheck.configure(state=state)
            self.DESAlgorithmCheck.configure(state=state)

        def changeAESState(state = NORMAL):
            self.AES128Check.configure(state=state)
            self.AES192Check.configure(state=state)
            self.AES256Check.configure(state=state)
        
        def changeDESState(state = DISABLED):
            self.DES128Check.configure(state=state)
            self.DES192Check.configure(state=state)

        def changeAlgorithmSelection():
            changeAESState(state = DISABLED if bool(self.generateAlgorithmSelection.get()) else NORMAL)
            changeDESState(state = NORMAL if bool(self.generateAlgorithmSelection.get()) else DISABLED)

        def changeSourceSelection():
            changeGenerateKeySectionState(state = DISABLED if bool(self.keySourceSelection.get()) else NORMAL)
            changeAESState(state = DISABLED if bool(self.keySourceSelection.get()) else DISABLED if bool(self.generateAlgorithmSelection.get()) else NORMAL)
            changeDESState(state = DISABLED if bool(self.keySourceSelection.get()) else NORMAL if bool(self.generateAlgorithmSelection.get()) else DISABLED)
            changeEnterKeySectionState(state = NORMAL if bool(self.keySourceSelection.get()) else DISABLED)

            if bool(self.keySourceSelection.get()) and not len(self.keyEntry.get()) in [16, 24, 32]:
                self.encryptButton.configure(state=DISABLED)

            if not bool(self.keySourceSelection.get()):
                if not self.keyValidityStatusLabel["foreground"] != "gray" and not "[Blank]" in self.keyValidityStatusLabel["text"]:
                    self.keyValidityStatusColor = self.keyValidityStatusLabel["foreground"]
                self.keyValidityStatusLabel.configure(foreground="gray")
            else:
                try:
                    self.keyValidityStatusLabel.configure(foreground=self.keyValidityStatusColor)
                except AttributeError:
                    self.keyValidityStatusLabel.configure(foreground="gray")

        def getKey(path: str) -> Optional[str]:
            with open(path, encoding = 'utf-8', mode="r") as file:
                global index
                index = file.read()
            index = str(index)
            where = -1
            for i in range(0, len(index)):
                where += 1
                key_to_try = index[where:where+32]
                try:
                    iv = base64.urlsafe_b64decode(index.replace(key_to_try, ""))[:16]
                    aes = AES.new(bytes(key_to_try, "utf-8"), AES.MODE_CFB, iv=iv)
                except:
                    continue
                else:
                    try:
                        output_key = aes.decrypt(base64.urlsafe_b64decode(index.replace(key_to_try, "")).replace(iv, b""))
                        output_key = output_key.decode("utf-8")
                    except:
                        continue
                    else:
                        try:
                            if len(output_key) == 16 or len(output_key) == 24 or len(output_key) == 32:
                                return output_key
                        except:
                            continue
            with open(path, encoding = 'utf-8', mode="r") as file:
                if len(file.read()) == 16 or len(file.read()) == 24 or len(file.read()) == 32:
                    return str(file.read())
                else:
                    return None

        def getKeyFromFile():
            path = filedialog.askopenfilename(title="Select key file", filetypes=[("Encrypt'n'Decrypt key file","*.key"),("Text document","*.txt"),("All files","*.*")])
            if path == "":
                return
            if os.path.splitext(path)[1] != ".txt":
                key = getKey(path)
                if not key:
                    messagebox.showwarning("ERR_INVALID_KEY_FILE","The specified file does not contain any valid key for encryption.")
                    return
            else:
                with open(path, encoding="utf-8", mode="r") as file:
                    key = file.read()
            self.keyEntry.delete(0, END)
            self.keyEntry.insert(0, key)

        def limitKeyEntry(*args, **kwargs):
            global value
            if len(self.keyEntryVar.get()) > 32:
                self.keyEntryVar.set(self.keyEntryVar.get()[:32])
            value = self.keyEntryVar.get()
            if len(value) == 0 or ''.join(str(self.keyEntryVar.get()).split()) == "":
                self.keyValidityStatusLabel.configure(foreground="gray", text="Validity: [Blank]")
                self.encryptButton.configure(state=DISABLED)
            else:
                if not bool(self.keySourceSelection.get()):
                    cond = bool(self.generateAlgorithmSelection.get())
                else:
                    cond = bool(self.entryAlgorithmSelection.get())
                iv = get_random_bytes(AES.block_size if not cond else DES3.block_size)
                try:
                    if not cond:
                        AES.new(bytes(value, 'utf-8'), mode=AES.MODE_OFB, iv=iv)
                    else:
                        DES3.new(bytes(value, 'utf-8'), mode=DES3.MODE_OFB, iv=iv)
                except:
                    if not len(value) in [16, 24, 32]:
                        self.keyValidityStatusLabel.configure(foreground="red", text=f"Validity: Invalid Key")
                    else:
                        self.keyValidityStatusLabel.configure(foreground="red", text=f"Validity: Invalid {'AES' if not cond else '3DES'}-{len(value) * 8} Key")
                    if "3DES-256" in self.keyValidityStatusLabel["text"]:
                        self.keyValidityStatusLabel.configure(text="Validity: Invalid Key")
                    self.encryptButton.configure(state=DISABLED)
                else:
                    self.keyValidityStatusLabel.configure(foreground="green", text=f"Validity: Valid {'AES' if not cond else '3DES'}-{len(value) * 8} Key")
                    self.encryptButton.configure(state=NORMAL)

        self.algorithmSelect = Notebook(self.encryptionFrame, width=355, height=290, takefocus=0)
        self.symmetricEncryption = Frame(self.algorithmSelect, takefocus=0)
        self.asymmetricEncryption = Frame(self.algorithmSelect, takefocus=0)

        self.algorithmSelect.add(self.symmetricEncryption, text="Symmetric Key Encryption")
        self.algorithmSelect.add(self.asymmetricEncryption, text="Asymmetric Key Encryption")

        self.generateRandomKeyCheck = Radiobutton(self.symmetricEncryption, text="Generate a random key", value=0, variable=self.keySourceSelection, command=changeSourceSelection, takefocus=0)

        self.AESAlgorithmCheck = Radiobutton(self.symmetricEncryption, text="AES (Advanced Encryption Standard)", value=0, variable=self.generateAlgorithmSelection, command=changeAlgorithmSelection, takefocus=0)
        self.AES128Check = Radiobutton(self.symmetricEncryption, text="AES-128 Key", value=128, variable=self.generateRandomAESVar, takefocus=0)
        self.AES192Check = Radiobutton(self.symmetricEncryption, text="AES-192 Key", value=192, variable=self.generateRandomAESVar, takefocus=0)
        self.AES256Check = Radiobutton(self.symmetricEncryption, text="AES-256 Key", value=256, variable=self.generateRandomAESVar, takefocus=0)

        self.DESAlgorithmCheck = Radiobutton(self.symmetricEncryption, text="3DES (Triple Data Encryption Standard)", value=1, variable=self.generateAlgorithmSelection, command=changeAlgorithmSelection, takefocus=0)
        self.DES128Check = Radiobutton(self.symmetricEncryption, text="3DES-128 Key", value=128, state=DISABLED, variable=self.generateRandomDESVar, takefocus=0)
        self.DES192Check = Radiobutton(self.symmetricEncryption, text="3DES-192 Key", value=192, state=DISABLED, variable=self.generateRandomDESVar, takefocus=0)
        
        self.selectKeyCheck = Radiobutton(self.symmetricEncryption, text="Use this key:", value=1, variable=self.keySourceSelection, command=changeSourceSelection, takefocus=0)
        
        self.keyEntry = Entry(self.symmetricEncryption, width=46, font=("Consolas",9), state=DISABLED, textvariable=self.keyEntryVar, takefocus=0)
        self.keyValidityStatusLabel = Label(self.symmetricEncryption, text="Validity: [Blank]", foreground="gray", takefocus=0)
        self.keyEntryHideCharCheck = Checkbutton(self.symmetricEncryption, text="Hide characters", onvalue=1, offvalue=0, variable=self.keyEntryHideCharVar, state=DISABLED, takefocus=0)
        self.keyBrowseButton = Button(self.symmetricEncryption, text="Browse key file...", width=21, state=DISABLED, command=getKeyFromFile, takefocus=0)
        self.keyPasteButton = Button(self.symmetricEncryption, text="Paste", width=13, state=DISABLED, command=lambda: (self.keyEntry.delete(0, END), self.keyEntry.insert(0, self.clipboard_get())), takefocus=0)
        self.keyClearButton = Button(self.symmetricEncryption, text="Clear", width=13, state=DISABLED, command=lambda: self.keyEntry.delete(0, END), takefocus=0)
        self.keyEnteredAlgAES = Radiobutton(self.symmetricEncryption, text="AES (Advanced Encryption Standard)", value=0, variable=self.entryAlgorithmSelection, command=limitKeyEntry, state=DISABLED, takefocus=0)
        self.keyEnteredAlgDES = Radiobutton(self.symmetricEncryption, text="3DES (Triple Data Encryption Standard)", value=1, variable=self.entryAlgorithmSelection, command=limitKeyEntry, state=DISABLED, takefocus=0)
        
        self.keyEntryVar.trace("w", limitKeyEntry)
        self.algorithmSelect.place(x=10, y=155)
        self.generateRandomKeyCheck.place(x=5, y=5)
        self.AESAlgorithmCheck.place(x=16, y=25)
        self.AES128Check.place(x=27, y=44)
        self.AES192Check.place(x=27, y=63)
        self.AES256Check.place(x=27, y=82)
        self.DESAlgorithmCheck.place(x=16, y=101)
        self.DES128Check.place(x=27, y=120)
        self.DES192Check.place(x=27, y=139)
        self.keyEntry.place(x=18, y=181)
        self.keyValidityStatusLabel.place(x=92, y=159)
        self.keyClearButton.place(x=114, y=207)
        self.keyPasteButton.place(x=17, y=207)
        self.keyBrowseButton.place(x=211, y=207)
        self.keyEntryHideCharCheck.place(x=244, y=158)
        self.selectKeyCheck.place(x=5, y=158)
        self.keyEnteredAlgAES.place(x=16, y=235)
        self.keyEnteredAlgDES.place(x=16, y=254)

        # Output section & encrypt 
        def saveOutput():
            files = [("Text document","*.txt"),("All files","*.*")]
            path = filedialog.asksaveasfilename(title="Save encrypted data", initialfile="Encrypted Data.txt", filetypes=files, defaultextension="*.txt")
            if path == "":
                return
            with open(path, encoding="utf-8", mode="w") as file:
                file.write(self.outputVar.get())

        def saveKey(path, key):
            key_to_use = self.crypto.generateKey(32)

            data = bytes(key, "utf-8")
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(bytes(key_to_use, "utf-8"), AES.MODE_CFB, iv=iv)
            rawResult = iv + cipher.encrypt(data)

            result = base64.urlsafe_b64encode(rawResult).decode()
            iv = rawResult[:16]
            aes = AES.new(bytes(key_to_use, "utf-8"), AES.MODE_CFB, iv=iv)
            plaintext = aes.decrypt(rawResult.replace(iv, b""))

            if plaintext.decode("utf-8") == key:
                first_part = randint(0, len(result))
                encrypted_key = result[:first_part] + key_to_use + result[first_part:]
                try:
                    os.remove(path)
                except:
                    pass
                finally:
                    with open(path, encoding = 'utf-8', mode="w") as file:
                        file.write(str(encrypted_key))

        def saveAESKey():
            files = [("Encrypt'n'Decrypt key file","*.key"),("Text document","*.txt"),("All files","*.*")]
            path = filedialog.asksaveasfilename(title="Save encryption key", initialfile="Encryption Key.key", filetypes=files, defaultextension="*.key")
            if path == "":
                return
            if os.path.splitext(path)[1] == ".key":
                saveKey(path, self.AESKeyVar.get())
            else:
                with open(path, encoding="utf-8", mode="w") as file:
                    file.write(self.AESKeyVar.get())

        def saveRSAPublic():
            files = [("Text document","*.txt"),("All files","*.*")]
            path = filedialog.asksaveasfilename(title="Save public key", initialfile="Public Key.txt", filetypes=files, defaultextension="*.txt")
            if path == "":
                return
            with open(path, encoding="utf-8", mode="w") as file:
                file.write(self.RSAPublicVar.get())

        def saveRSAPrivate():
            files = [("Text document","*.txt"),("All files","*.*")]
            path = filedialog.asksaveasfilename(title="Save private key", initialfile="Private Key.txt", filetypes=files, defaultextension="*.txt")
            if path == "":
                return
            with open(path, encoding="utf-8", mode="w") as file:
                file.write(self.RSAPrivateVar.get())

        def outputTextCallback(*args, **kwargs):
            if self.outputVar.get() == "":
                self.outputText.configure(bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1)
                self.clearOutputButton.configure(state=DISABLED)
                self.copyOutputButton.configure(state=DISABLED)
                self.saveOutputButton.configure(state=DISABLED)
            else:
                self.outputText.configure(bg="white", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1)
                self.clearOutputButton.configure(state=NORMAL)
                self.copyOutputButton.configure(state=NORMAL)
                self.saveOutputButton.configure(state=NORMAL)

        def AESKeyTextCallback(*args, **kwargs):
            if self.AESKeyVar.get() == "":
                self.AESKeyText.configure(bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1)
                self.clearAESKeyButton.configure(state=DISABLED)
                self.copyAESKeyButton.configure(state=DISABLED)
                self.saveAESKeyButton.configure(state=DISABLED)
            else:
                self.AESKeyText.configure(bg="white", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1)
                self.clearAESKeyButton.configure(state=NORMAL)
                self.copyAESKeyButton.configure(state=NORMAL)
                self.saveAESKeyButton.configure(state=NORMAL)

        self.encryptButton = Button(self.encryptionFrame, text="Encrypt", width=22, command=self.crypto.encrypt, takefocus=0)
        self.writeFileContentCheck = Checkbutton(self.encryptionFrame, text="Write encrypted data to the file", variable=self.writeFileContentVar, state=DISABLED, takefocus=0)

        self.outputFrame = LabelFrame(self.encryptionFrame, text="Output", height=502, width=403, takefocus=0)

        self.outputText = ScrolledText(self.outputFrame, height = 6, width = 52, state=DISABLED, font = ("Consolas", 9), bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, textvariable=self.outputVar)
        self.AESKeyText = Text(self.outputFrame, width=54, height=1, state=DISABLED, font=("Consolas",9), bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, textvariable=self.AESKeyVar)
        self.RSAPublicText = ScrolledText(self.outputFrame, height = 6, width = 52, state=DISABLED, font = ("Consolas", 9), bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1)
        self.RSAPrivateText = ScrolledText(self.outputFrame, height = 6, width = 52, state=DISABLED, font = ("Consolas", 9), bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1)
        self.AESKeyLabel = Label(self.outputFrame, text="AES/3DES Key:", takefocus=0)
        self.RSAPublicLabel = Label(self.outputFrame, text="RSA Public Key:", takefocus=0)
        self.RSAPrivateLabel = Label(self.outputFrame, text="RSA Private Key:", takefocus=0)

        self.outputVar.trace("w", outputTextCallback)
        self.AESKeyVar.trace("w", AESKeyTextCallback)

        self.copyOutputButton = Button(self.outputFrame, text = "Copy", width=10, command=lambda: self.clipboard_set(self.lastResult), state=DISABLED, takefocus=0)
        self.clearOutputButton = Button(self.outputFrame, text = "Clear", width=10, command=lambda: (self.outputText.configure(state=NORMAL), self.outputText.delete("1.0", END), self.outputText.configure(state=DISABLED)), state=DISABLED, takefocus=0)
        self.saveOutputButton = Button(self.outputFrame, width=15, text="Save as...", command=saveOutput, state=DISABLED, takefocus=0)
        self.copyAESKeyButton = Button(self.outputFrame, width = 10, text="Copy", command=lambda: self.clipboard_set(self.AESKeyText.get("1.0", END)), state=DISABLED, takefocus=0)
        self.clearAESKeyButton = Button(self.outputFrame, width = 10, text="Clear", command=lambda: (self.AESKeyText.configure(state=NORMAL), self.AESKeyText.delete("1.0", END), self.AESKeyText.configure(state=DISABLED)), state=DISABLED, takefocus=0)
        self.saveAESKeyButton = Button(self.outputFrame, width=15, text="Save as...", command=saveAESKey, state=DISABLED, takefocus=0)
        self.copyRSAPublicButton = Button(self.outputFrame, width = 10, text="Copy", command=lambda: self.clipboard_set(self.RSAPublicText.get("1.0", END)), state=DISABLED, takefocus=0)
        self.clearRSAPublicButton = Button(self.outputFrame, width = 10, text="Clear", command=lambda: (self.RSAPublicText.configure(state=NORMAL), self.RSAPublicText.delete("1.0", END), self.RSAPublicText.configure(state=DISABLED)), state=DISABLED, takefocus=0)
        self.saveRSAPublicButton = Button(self.outputFrame, width=15, text="Save as...", command=saveRSAPublic, state=DISABLED, takefocus=0)
        self.copyRSAPrivateButton = Button(self.outputFrame, width = 10, text="Copy", command=lambda: self.clipboard_set(self.RSAPrivateText.get("1.0", END)), state=DISABLED, takefocus=0)
        self.clearRSAPrivateButton = Button(self.outputFrame, width = 10, text="Clear", command=lambda: (self.RSAPrivateText.configure(state=NORMAL), self.RSAPrivateText.delete("1.0", END), self.RSAPrivateText.configure(state=DISABLED)), state=DISABLED, takefocus=0)
        self.saveRSAPrivateButton = Button(self.outputFrame, width=15, text="Save as...", command=saveRSAPrivate, state=DISABLED, takefocus=0)

        self.statusBar = TkLabel(self, text="Status: Ready", bd=1, relief=SUNKEN, anchor=W)

        self.encryptButton.place(x=9, y=480)
        self.writeFileContentCheck.place(x=160, y=482)
        self.outputText.place(x=9, y=5)

        self.AESKeyText.place(x=9, y=145)
        self.RSAPublicText.place(x=9, y=215)
        self.RSAPrivateText.place(x=9, y=355)
        self.AESKeyLabel.place(x=8, y=125)
        self.RSAPublicLabel.place(x=8, y=194)
        self.RSAPrivateLabel.place(x=8, y=334)

        self.copyOutputButton.place(x=8, y=100)
        self.clearOutputButton.place(x=85, y=100)
        self.saveOutputButton.place(x=162, y=100)
        self.copyAESKeyButton.place(x=8, y=170)
        self.clearAESKeyButton.place(x=85, y=170)
        self.saveAESKeyButton.place(x=162, y=170)
        self.copyRSAPublicButton.place(x=8, y=309)
        self.clearRSAPublicButton.place(x=85, y=309)
        self.saveRSAPublicButton.place(x=162, y=309)
        self.copyRSAPrivateButton.place(x=8, y=449)
        self.clearRSAPrivateButton.place(x=85, y=449)
        self.saveRSAPrivateButton.place(x=162, y=449)

        self.statusBar.pack(side=BOTTOM, fill=X)

        self.outputFrame.place(x=377, y=4)

        # ┌──────────────────┐
        # │ Decryption Frame │
        # └──────────────────┘
        def changeDecryptSource():
            if not bool(self.decryptSourceVar.get()):
                self.textDecryptEntry.configure(state=NORMAL, bg="white", foreground="black", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1)
                self.textDecryptPasteButton.configure(state=NORMAL)
                self.textDecryptClearButton.configure(state=NORMAL)
                self.fileDecryptEntry.configure(state=DISABLED)
                self.fileDecryptBrowseButton.configure(state=DISABLED)
                self.fileDecryptClearButton.configure(state=DISABLED)
                if not ''.join(str(self.textDecryptEntry.get("1.0", END)).split()) == "":
                    try:
                        if base64.urlsafe_b64encode(base64.urlsafe_b64decode(self.textDecryptEntry.get("1.0", END).encode("utf-8"))) == self.textDecryptEntry.get("1.0", END).rstrip().encode("utf-8"):
                            self.textDecryptValidityLabel.configure(text="Validity: Valid base64 encoded data", foreground="green")
                            self.decryptButton.configure(state=NORMAL)
                        else:
                            self.textDecryptValidityLabel.configure(text="Validity: Invalid base64 encoded data", foreground="red")
                            self.decryptButton.configure(state=DISABLED)
                    except:
                        self.textDecryptValidityLabel.configure(text="Validity: Invalid base64 encoded data", foreground="red")
                        self.decryptButton.configure(state=DISABLED)
                else:
                    self.textDecryptValidityLabel.configure(text="Validity: [Blank]", foreground="gray")
                    self.decryptButton.configure(state=DISABLED)
            else:
                self.textDecryptEntry.configure(state=DISABLED, bg="#F0F0F0", foreground="gray", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1)
                self.textDecryptPasteButton.configure(state=DISABLED)
                self.textDecryptClearButton.configure(state=DISABLED)
                self.fileDecryptEntry.configure(state=NORMAL)
                self.fileDecryptBrowseButton.configure(state=NORMAL)
                self.fileDecryptClearButton.configure(state=NORMAL)
                if os.path.isfile(self.fileDecryptEntry.get()):
                    self.decryptButton.configure(state=NORMAL)
                else:
                    self.decryptButton.configure(state=DISABLED)

        def textDecryptCallback(*args, **kwargs):
            if not ''.join(str(self.textDecryptEntry.get("1.0", END)).split()) == "":
                try:
                    if base64.urlsafe_b64encode(base64.urlsafe_b64decode(self.textDecryptEntry.get("1.0", END).encode("utf-8"))) == self.textDecryptEntry.get("1.0", END).rstrip().encode("utf-8"):
                        self.textDecryptValidityLabel.configure(text="Validity: Valid base64 encoded data", foreground="green")
                        self.decryptButton.configure(state=NORMAL)
                        decryptLimitKeyEntry()
                    else:
                        self.textDecryptValidityLabel.configure(text="Validity: Invalid base64 encoded data", foreground="red")
                        self.decryptButton.configure(state=DISABLED)
                except binascii.Error:
                    self.textDecryptValidityLabel.configure(text="Validity: Invalid base64 encoded data", foreground="red")
                    self.decryptButton.configure(state=DISABLED)
            else:
                self.textDecryptValidityLabel.configure(text="Validity: [Blank]", foreground="gray")
                self.decryptButton.configure(state=DISABLED)

        def fileDecryptCallback(*args, **kwargs):
            if not ''.join(str(self.fileDecryptEntry.get()).split()) == "":
                if os.path.isfile(self.fileDecryptEntry.get()):
                    self.decryptButton.configure(state=NORMAL)
                    decryptLimitKeyEntry()
                else:
                    self.decryptButton.configure(state=DISABLED)
            else:
                self.decryptButton.configure(state=DISABLED)

        def decryptLimitKeyEntry(*args, **kwargs):
            global value
            if len(self.decryptKeyVar.get()) > 32:
                self.decryptKeyVar.set(self.decryptKeyVar.get()[:32])
            value = self.decryptKeyVar.get()
            if ''.join(str(self.decryptKeyVar.get()).split()) == "":
                self.decryptKeyClearButton.configure(state=DISABLED)
            else:
                self.decryptKeyClearButton.configure(state=NORMAL)
            if len(value) == 0:
                self.decryptButton.configure(state=DISABLED)
            else:
                cond = bool(self.decryptAlgorithmVar.get())
                iv = get_random_bytes(AES.block_size if not cond else DES3.block_size)
                try:
                    if not cond:
                        AES.new(bytes(value, 'utf-8'), mode=AES.MODE_OFB, iv=iv)
                    else:
                        DES3.new(bytes(value, 'utf-8'), mode=DES3.MODE_OFB, iv=iv)
                except:
                    self.decryptButton.configure(state=DISABLED)
                else:
                    if not ''.join(str(self.fileDecryptEntry.get()).split()) == "" and os.path.isfile(self.fileDecryptEntry.get()):
                        self.decryptButton.configure(state=NORMAL)
                    else:
                        self.decryptButton.configure(state=DISABLED)
        
        def decryptBrowseFile():
            files = [("All files","*.*")]
            filePath = filedialog.askopenfilename(title = "Open a file to decrypt", filetypes=files)
            self.fileDecryptEntry.delete(0, END)
            self.fileDecryptEntry.insert(0, filePath)

        def decryptOutputCallback(*args, **kwargs):
            if not ''.join(str(self.decryptOutputVar.get()).split()) == "":
                self.decryptClearButton.configure(state=NORMAL)
                self.decryptCopyButton.configure(state=NORMAL)
                self.decryptSaveButton.configure(state=NORMAL)
            else:
                self.decryptClearButton.configure(state=DISABLED)
                self.decryptCopyButton.configure(state=DISABLED)
                self.decryptSaveButton.configure(state=DISABLED)

        self.textDecryptRadio = Radiobutton(self.decryptionFrame, text = "Encrypted text:", value=0, variable=self.decryptSourceVar, command=changeDecryptSource, takefocus=0)
        self.textDecryptValidityLabel = Label(self.decryptionFrame, text="Validity: [Blank]", foreground="gray")
        self.textDecryptEntry = ScrolledText(self.decryptionFrame, width=105, height=5, font=("Consolas", 9), textvariable=self.textDecryptVar, bg="white", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1)
        self.textDecryptPasteButton = Button(self.decryptionFrame, width=15, text="Paste", command=lambda: self.textDecryptEntry.replace(self.clipboard_get()), takefocus=0)
        self.textDecryptClearButton = Button(self.decryptionFrame, width=15, text="Clear", command=lambda: self.textDecryptEntry.delete("1.0", END), takefocus=0, state=DISABLED)

        self.fileDecryptRadio = Radiobutton(self.decryptionFrame, text = "Encrypted file:", value=1, variable=self.decryptSourceVar, command=changeDecryptSource, takefocus=0)
        self.fileDecryptEntry = Entry(self.decryptionFrame, width=107, font=("Consolas", 9), textvariable=self.fileDecryptVar, state=DISABLED, takefocus=0)
        self.fileDecryptBrowseButton = Button(self.decryptionFrame, width=15, text="Browse...", state=DISABLED, command=decryptBrowseFile, takefocus=0)
        self.fileDecryptClearButton = Button(self.decryptionFrame, width=15, text="Clear", state=DISABLED, command=lambda: self.fileDecryptEntry.delete(0, END), takefocus=0)

        self.textDecryptVar.trace("w", textDecryptCallback)
        self.fileDecryptVar.trace("w", fileDecryptCallback)

        self.decryptNotebook = Notebook(self.decryptionFrame, height=160, width=765, takefocus=0)
        self.symmetricDecryption = Frame(self.decryptNotebook, takefocus=0)
        self.asymmetricEncryption = Frame(self.decryptNotebook, takefocus=0)
        self.decryptNotebook.add(self.symmetricDecryption, text="Symmetric Key Decryption")
        self.decryptNotebook.add(self.asymmetricEncryption, text="Asymmetric Key Decryption")
        self.decryptAlgorithmFrame = LabelFrame(self.symmetricDecryption, text="Select algorithm", height=63, width=749, takefocus=0)
        self.decryptAESCheck = Radiobutton(self.decryptAlgorithmFrame, text="AES (Advanced Encryption Standard)", value=0, variable=self.decryptAlgorithmVar, takefocus=0)
        self.decryptDESCheck = Radiobutton(self.decryptAlgorithmFrame, text="3DES (Triple Data Encryption Standard)", value=1, variable=self.decryptAlgorithmVar, takefocus=0)
        self.decryptKeyFrame = LabelFrame(self.symmetricDecryption, text="Enter encryption key", height=84, width=749, takefocus=0)
        self.decryptKeyValidity = Label(self.symmetricDecryption, text="Validity: [Blank]", foreground="gray")
        self.decryptKeyEntry = Entry(self.decryptKeyFrame, width=103, font=("Consolas", 9), textvariable=self.decryptKeyVar, takefocus=0)
        self.decryptKeyBrowseButton = Button(self.decryptKeyFrame, width=21, text="Browse key file...", takefocus=0)
        self.decryptKeyPasteButton = Button(self.decryptKeyFrame, width=15, text="Paste", takefocus=0, command=lambda: self.decryptKeyEntry.replace(self.clipboard_get()))
        self.decryptKeyClearButton = Button(self.decryptKeyFrame, width=15, text="Clear", takefocus=0, command=lambda: self.decryptKeyEntry.delete(0, END), state=DISABLED)

        self.decryptKeyVar.trace("w", decryptLimitKeyEntry)

        self.decryptButton = Button(self.decryptionFrame, width=22, text="Decrypt", command=self.crypto.decrypt, takefocus=0, state=DISABLED)
        self.decryptOutputFrame = LabelFrame(self.decryptionFrame, text="Decrypted text", height=84, width=766, takefocus=0)
        self.decryptOutputText = Text(self.decryptOutputFrame, width=105, height=1, font=("Consolas", 9), state=DISABLED, bg="#F0F0F0", relief=FLAT, highlightbackground="#cccccc", highlightthickness=1, takefocus=0, textvariable=self.decryptOutputVar)
        self.decryptCopyButton = Button(self.decryptOutputFrame, text="Copy", width=17, takefocus=0, state=DISABLED)
        self.decryptClearButton = Button(self.decryptOutputFrame, text="Clear", width=17, takefocus=0, state=DISABLED)
        self.decryptSaveButton = Button(self.decryptOutputFrame, text="Save as...", width=20, takefocus=0, state=DISABLED)

        self.decryptOutputVar.trace("w", decryptOutputCallback)

        self.textDecryptRadio.place(x=8, y=2)
        self.textDecryptValidityLabel.place(x=108, y=3)
        self.textDecryptEntry.place(x=24, y=24)
        self.textDecryptPasteButton.place(x=23, y=107)
        self.textDecryptClearButton.place(x=130, y=107)
        self.fileDecryptRadio.place(x=8, y=132)
        self.fileDecryptEntry.place(x=24, y=153)
        self.fileDecryptBrowseButton.place(x=23, y=182)
        self.fileDecryptClearButton.place(x=130, y=182)
        self.decryptNotebook.place(x=10, y=215)
        self.decryptAlgorithmFrame.place(x=8, y=2)
        self.decryptAESCheck.place(x=5, y=0)
        self.decryptDESCheck.place(x=5, y=19)
        self.decryptKeyFrame.place(x=8, y=68)
        self.decryptKeyEntry.place(x=9, y=3)
        self.decryptKeyBrowseButton.place(x=601, y=30)
        self.decryptKeyPasteButton.place(x=8, y=30)
        self.decryptKeyClearButton.place(x=115, y=30)
        self.decryptButton.place(x=9, y=406)
        self.decryptOutputFrame.place(x=10, y=435)
        self.decryptOutputText.place(x=10, y=3)
        self.decryptCopyButton.place(x=9, y=30)
        self.decryptClearButton.place(x=128, y=30)
        self.decryptSaveButton.place(x=622, y=30)

        # ┌───────────────┐
        # │ Logging Frame │
        # └───────────────┘
        self.loggingClearButton = Button(self.loggingFrame, text="Clear", width=15, takefocus=0, state=DISABLED)
        self.loggingSaveAsButton = Button(self.loggingFrame, text="Save as...", width=15, takefocus=0)
        self.loggingSaveButton = Button(self.loggingFrame, text="Save to 'Encrypt-n-Decrypt.log'", width=28, takefocus=0)

        self.loggingWidget.place(x=10, y=10)
        self.loggingClearButton.place(x=9, y=330)
        self.loggingSaveAsButton.place(x=494, y=330)
        self.loggingSaveButton.place(x=601, y=330)

        # ┌────────────┐
        # │ Help Frame │
        # └────────────┘

    def __initialize_vars(self):
        self.showTextChar = IntVar(value=0)
        self.showTooltip = IntVar(value=1)
        self.showInfoBox = IntVar(value=1)
        self.showWarnBox = IntVar(value=1)
        self.showErrorBox = IntVar(value=1)
        self.windowAlpha = IntVar(value=1)

        self.generateRandomAESVar = IntVar(value=256)
        self.generateRandomDESVar = IntVar(value=192)
        self.keySourceSelection = IntVar(value=0)
        self.generateAlgorithmSelection = IntVar(value=0)
        self.entryAlgorithmSelection = IntVar(value=0)
        self.keyEntryVar = StringVar()
        self.keyEntryHideCharVar = IntVar()

        self.dataSourceVar = IntVar(value=0)
        self.textEntryVar = StringVar()
        self.fileEntryVar = StringVar()
        self.textEntryHideCharVar = IntVar(value=0)
        self.writeFileContentVar = IntVar(value=1)
        self.outputVar = StringVar()
        self.AESKeyVar = StringVar()
        self.RSAPublicVar = StringVar()
        self.RSAPrivateVar = StringVar()

        self.decryptSourceVar = IntVar(value=0)
        self.decryptAlgorithmVar = IntVar(value=0)
        self.textDecryptVar = StringVar()
        self.fileDecryptVar = StringVar()
        self.decryptKeyVar = StringVar()
        self.decryptOutputVar = StringVar()

    def __initialize_menu(self):
        self.menuBar = Menu(self)
        self.config(menu = self.menuBar)

        self.fileMenu = Menu(self.menuBar, tearoff=0)
        self.viewMenu = Menu(self.menuBar, tearoff=0)
        self.helpMenu = Menu(self.menuBar, tearoff=0)

        self.titleMenu = Menu(self.viewMenu, tearoff=0)
        self.opacityMenu = Menu(self.viewMenu, tearoff=0)
        self.langMenu = Menu(self.viewMenu, tearoff=0)

        self.speedMenu = Menu(self.titleMenu, tearoff=0)

        def changeAlpha(alpha: int = 100):
            self.attributes("-alpha", alpha/100)

        # Menu-bar
        self.fileMenu.add_command(label = "Encryption", command=lambda: self.mainNotebook.select(0), accelerator="Ctrl+E", underline=0)
        self.fileMenu.add_command(label = "Decryption", command=lambda: self.mainNotebook.select(1), accelerator="Ctrl+D", underline=0)
        self.fileMenu.add_command(label = "Logs", command=lambda: self.mainNotebook.select(2), accelerator="Ctrl+L", underline=0)
        self.fileMenu.add_command(label = "Help & About", command=lambda: self.mainNotebook.select(3), accelerator="F1", underline=0)
        self.fileMenu.add_separator()
        self.fileMenu.add_command(label = "Check for updates", accelerator="Ctrl+Alt+U", command=lambda: self.Updates(self), underline=10)
        self.fileMenu.add_separator()
        self.fileMenu.add_command(label = "Exit", accelerator="Alt+F4", command=lambda: self.destroy())
        # View menu
        self.viewMenu.add_checkbutton(label = "Show tooltips on hover", accelerator="Ctrl+Alt+T", onvalue=1, offvalue=0, variable=self.showTooltip, underline=5)
        self.viewMenu.add_separator()
        self.viewMenu.add_checkbutton(label = "Show info message dialogs", accelerator="Ctrl+Alt+I", onvalue=1, offvalue=0, variable=self.showInfoBox, underline=5)
        self.viewMenu.add_checkbutton(label = "Show warning message dialogs", accelerator="Ctrl+Alt+W", onvalue=1, offvalue=0, variable=self.showWarnBox, underline=5)
        self.viewMenu.add_checkbutton(label = "Show error message dialogs", accelerator="Ctrl+Alt+E", onvalue=1, offvalue=0, variable=self.showErrorBox, underline=5)
        self.viewMenu.add_separator()
        # Title bar sub-menu
        self.titleMenu.add_checkbutton(label = "Show program name in titlebar")
        self.titleMenu.add_checkbutton(label = "Show program version in titlebar")
        self.titleMenu.add_checkbutton(label = "Show program build number in titlebar")
        self.titleMenu.add_checkbutton(label = "Show time in titlebar")
        self.titleMenu.add_checkbutton(label = "Show date in titlebar")
        self.titleMenu.add_separator()
        
        UpdateValue = IntVar()
        UpdateValue.set(200)
        self.speedMenu.add_radiobutton(label = "Fast", value=50, variable=UpdateValue)
        self.speedMenu.add_radiobutton(label = "Moderate", value=200, variable=UpdateValue)
        self.speedMenu.add_radiobutton(label = "Slow", value=800, variable=UpdateValue)
        self.speedMenu.add_radiobutton(label = "Paused", value=0, variable=UpdateValue)
        self.speedMenu.add_separator()
        self.speedMenu.add_command(label = "Update now")
        self.titleMenu.add_cascade(menu=self.speedMenu, label = "Titlebar update rate")
        self.viewMenu.add_cascade(menu=self.titleMenu, label = "Window titlebar configuration")
        self.viewMenu.add_separator()
        # Transparency sub-menu
        self.opacityMenu.add_radiobutton(label = "%20", value=20, variable=self.windowAlpha, command=lambda:changeAlpha(20), accelerator="Ctrl+Alt+2")
        self.opacityMenu.add_radiobutton(label = "%40", value=40, variable=self.windowAlpha, command=lambda:changeAlpha(40), accelerator="Ctrl+Alt+4")
        self.opacityMenu.add_radiobutton(label = "%60", value=60, variable=self.windowAlpha, command=lambda:changeAlpha(60), accelerator="Ctrl+Alt+6")
        self.opacityMenu.add_radiobutton(label = "%80", value=80, variable=self.windowAlpha, command=lambda:changeAlpha(80), accelerator="Ctrl+Alt+8")
        self.opacityMenu.add_radiobutton(label = "%90", value=90, variable=self.windowAlpha, command=lambda:changeAlpha(90), accelerator="Ctrl+Alt+9")
        self.opacityMenu.add_radiobutton(label = "Opaque", value=100, variable=self.windowAlpha, command=lambda:changeAlpha(100), accelerator="Ctrl+Alt+1")
        self.opacityMenu.add_separator()
        self.opacityMenu.add_command(label = "Reset opacity", command=lambda:changeAlpha(100), accelerator="Ctrl+Alt+O", underline=6)
        # End transparency sub-menu
        self.viewMenu.add_cascade(menu=self.opacityMenu, label = "Window opacity configuration")
        self.viewMenu.add_separator()
        # Language sub-menu
        self.langMenu.add_radiobutton(label = "English [Coming Soon]")
        self.langMenu.add_radiobutton(label = "Türkçe [Yakında Geliyor]", state=DISABLED)
        self.langMenu.add_radiobutton(label = "Deutsche [Kommt Bald]", state=DISABLED)
        self.langMenu.add_radiobutton(label = "中国人 [即将推出]", state=DISABLED)
        self.langMenu.add_separator()
        self.langMenu.add_command(label = "Reset language to default", accelerator="Ctrl+Alt+L")
        # End language sub-menu
        self.viewMenu.add_cascade(menu=self.langMenu, label ="Language")
        # End view menu
        self.menuBar.add_cascade(label = "Main", menu=self.fileMenu)
        self.menuBar.add_cascade(label = "Preferences", menu=self.viewMenu)
        self.menuBar.add_command(label = "Help", command=self.helpMenu)

    def __initialize_bindings(self):
        def encrypt(*args, **kwargs):
            self.crypto.encrypt()
        def give_focus(*args, **kwargs):
            self.after(50, self.textEntry.focus_set())
        def changeTab(*args, **kwargs):
            if self.mainNotebook.index(self.mainNotebook.select()) == 3:
                if not hasattr(self, f"_{self.__class__.__name__}__tabChangeCount"):
                    request = get("https://raw.githubusercontent.com/Yilmaz4/Encrypt-n-Decrypt/main/README.md").text
                    self.HTML = markdown(request)
                self.readmePage = HtmlFrame(self, messages_enabled=False, vertical_scrollbar=True)
                self.readmePage.load_html(self.HTML)
                self.readmePage.set_zoom(0.8)
                self.readmePage.grid_propagate(0)
                self.readmePage.enable_images(0)
                self.__tabChangeCount = True
                self.readmePage.place(x=5, y=27, height=548, width=790)
            else:
                if hasattr(self, "readmePage"):
                    self.readmePage.place_forget()
                    self.readmePage.destroy()

        self.bind("<Return>", encrypt)
        self.bind("<Tab>", give_focus)
        self.mainNotebook.bind("<<NotebookTabChanged>>", changeTab)

    def clipboard_get(self) -> Optional[str]:
        clipboard = pyperclip.paste()
        if not clipboard:
            return ""
        elif len(clipboard) > 15000:
            if messagebox.askyesno("Super long text", "The text you're trying to paste is too long (longer than 15.000 characters) which can cause the program to freeze. Are you sure?"):
                return clipboard
            else:
                return ""
        else:
            return clipboard

    def clipboard_set(self, text: str = None):
        pyperclip.copy(text)

    class Updates(Toplevel):
        def __init__(self, master: Tk):
            self.master = master
            releases = get("https://api.github.com/repos/Yilmaz4/Encrypt-n-Decrypt/releases").json()

            latest = None
            for release in releases:
                if not release["draft"] and not release["prerelease"]:
                    latest = release
                    break

            success = False
            for i in range(len(latest["tag_name"].split("."))):
                if latest["tag_name"].split(".")[i] > self.master.version.split(".")[i]:
                    success = True
                    break
                else:
                    continue

            if not success:
                messagebox.showinfo("No updates available", "No updates avaliable yet. Please check back later.")
                self.master.logger.info("Updates checked. No updates available.")
                super().__init__(self.master)
                self.withdraw()
                self.destroy()
                return

            asset_0 = urlopen(latest["assets"][0]["browser_download_url"]).info()
            asset_1 = urlopen(latest["assets"][1]["browser_download_url"]).info()
            asset_0_size, asset_0_date = size(int(asset_0["Content-Length"]), system=alternative), asset_0["Last-Modified"]
            asset_1_size, asset_1_date = size(int(asset_1["Content-Length"]), system=alternative), asset_0["Last-Modified"]
            super().__init__(master)
            self.grab_set()
            self.width = 669
            self.height = 558

            self.title("Eɲcrƴpʈ'n'Decrƴpʈ Updater")
            self.geometry(f"{self.width}x{self.height}")
            self.resizable(height=False, width=False)
            self.attributes("-fullscreen", False)
            self.maxsize(self.width, self.height)
            self.minsize(self.width, self.height)
            try:
                self.iconbitmap("icon.ico")
            except TclError:
                pass

            HTML = markdown(latest["body"])
            frame = HtmlFrame(self, height=558, width=300, messages_enabled=False, vertical_scrollbar=True)
            frame.load_html(HTML)
            frame.set_zoom(0.8)
            frame.grid_propagate(0)
            frame.enable_images(0)
            frame.place(x=0, y=0)
            UpdateAvailableLabel = Label(self, text="An update is available!", font=('Segoe UI', 22), foreground="#189200", takefocus=0)
            LatestVersionLabel = Label(self, text="Latest version: Encrypt-n-Decrypt {}".format(latest["tag_name"]), font=('Segoe UI', 9, 'bold'), takefocus=0)
            YourVersionLabel = Label(self, text="Current version: Encrypt-n-Decrypt v{}".format(master.version), font=('Segoe UI', 9), takefocus=0)
            DownloadLabel = Label(self, text="Download page for more information and asset files:", takefocus=0)
            DownloadLinks = LabelFrame(self, text="Download links", height=248, width=349, takefocus=0)
            DownloadLinkLabel = Label(DownloadLinks, text=latest["assets"][0]["name"], takefocus=0)
            DownloadLinkLabel2 = Label(DownloadLinks, text=latest["assets"][1]["name"], takefocus=0)
            Separator1 = Separator(self, orient='horizontal', takefocus=0)
            Separator2 = Separator(DownloadLinks, orient='horizontal', takefocus=0)
            Separator3 = Separator(DownloadLinks, orient='horizontal', takefocus=0)
            DownloadPage = Entry(self, width=57, takefocus=0)
            DownloadPage.insert(0, latest["html_url"])
            DownloadPage.configure(state=DISABLED)
            DownloadLink = Entry(DownloadLinks, width=54, takefocus=0)
            DownloadLink.insert(0, latest["assets"][0]["browser_download_url"])
            DownloadLink.configure(state=DISABLED)
            DownloadLink2 = Entry(DownloadLinks, width=54, takefocus=0)
            DownloadLink2.insert(0, latest["assets"][1]["browser_download_url"])
            DownloadLink2.configure(state=DISABLED)
            CopyDownloadPage = Button(self, text="Copy", width=10, command=lambda: self.master.clipboard_set(DownloadPage.get()), takefocus=0)
            OpenDownloadLink = Button(self, text="Open in browser", width=17, command=lambda: openweb(str(latest["html_url"])), takefocus=0)
            CopyDownloadLink = Button(DownloadLinks, text="Copy", width=10, takefocus=0, command=lambda: self.master.clipboard_set(DownloadLink.get()))
            DownloadTheLinkBrowser = Button(DownloadLinks, text="Download from browser", width=25, command=lambda: openweb(latest["assets"][0]["browser_download_url"]), takefocus=0)
            DownloadTheLinkBuiltin = Button(DownloadLinks, text="Download", width=13, command=lambda: None, takefocus=0)
            CopyDownloadLink2 = Button(DownloadLinks, text="Copy", width=10, takefocus=0, command=lambda: self.master.clipboard_set(DownloadLink2.get()))
            DownloadTheLinkBrowser2 = Button(DownloadLinks, text="Download from browser", width=25, command=lambda: openweb(latest["assets"][1]["browser_download_url"]), takefocus=0)
            DownloadTheLinkBuiltin2 = Button(DownloadLinks, text="Download", width=13, command=lambda: None, takefocus=0)
            AssetSize = Label(DownloadLinks, text=asset_0_size, foreground="#474747", takefocus=0)
            AssetSize2 = Label(DownloadLinks, text=asset_1_size, foreground="#474747", takefocus=0)
            Date = Label(DownloadLinks, text=asset_0_date, foreground="gray", takefocus=0)
            Date2 = Label(DownloadLinks, text=asset_1_date, foreground="gray", takefocus=0)
            downloadProgress = IntVar()
            downloadProgress.set(0)
            ProgressBar = Progressbar(DownloadLinks, length=329, mode='determinate', orient=HORIZONTAL, variable=downloadProgress, maximum=asset_0["Content-Length"], takefocus=0)
            ProgressLabel = Label(DownloadLinks, text="Download progress:", takefocus=0)
            
            ProgressBar.place(x=7, y=195)
            ProgressLabel.place(x=5, y=173)
            LatestVersionLabel.place(x=309, y=43)
            YourVersionLabel.place(x=309, y=63)
            UpdateAvailableLabel.place(x=310, y=2)
            Separator1.place(x=312, y=86, width=346)
            Separator2.place(x=7, y=81, width=329)
            Separator3.place(x=7, y=167, width=329)
            DownloadLabel.place(x=309, y=89)
            DownloadLinkLabel.place(x=6, y=0)
            AssetSize.place(x=175, y=0)
            Date.place(x=237, y=0)
            Date2.place(x=237, y=86)
            DownloadLinkLabel2.place(x=6, y=86)
            AssetSize2.place(x=175, y=86)
            CopyDownloadPage.place(x=310, y=138)
            OpenDownloadLink.place(x=385, y=138)
            DownloadPage.place(x=311, y=111)
            DownloadLink.place(x=7, y=22)
            DownloadLink2.place(x=7, y=108)
            DownloadTheLinkBuiltin.place(x=83, y=49)
            DownloadTheLinkBrowser.place(x=177, y=49)
            CopyDownloadLink.place(x=6, y=49)
            DownloadTheLinkBuiltin2.place(x=83, y=135)
            DownloadTheLinkBrowser2.place(x=177, y=135)
            CopyDownloadLink2.place(x=6, y=135)
            DownloadLinks.place(x=310, y=168)
            self.focus_force()

            self.mainloop()

    class ToolTip:
        def __init__(self, widget, justify, background, foreground, relief, borderwidth, font, locationinvert, heightinvert):
            self.widget = widget
            self.tipwindow = None
            self.id = None
            self.x = self.y = 0
            
            self.transition = 10

            self.justify = justify
            self.background = background
            self.foreground = foreground
            self.relief = relief
            self.borderwidth = borderwidth
            self.font = font
            self.locationinvert = locationinvert
            self.heightinvert = heightinvert

        def showtip(self, text):
            self.text = text
            if self.tipwindow or not self.text:
                return

            x, y, _, cy = self.widget.bbox("insert")
            x = x + self.winfo_pointerx() + 2
            y = y + cy + self.winfo_pointery() + 15
            self.tipwindow = tw = Toplevel(self.widget)

            tw.wm_overrideredirect(1)
            tw.wm_geometry("+%d+%d" % (x, y))
            tw.attributes("-alpha", 0)
            label = Label(tw, text=self.text, justify=LEFT, relief=SOLID, borderwidth=1, foreground="#6f6f6f", background="white", takefocus=0)
            label.pack(ipadx=1)
            tw.attributes("-alpha", 0)
            try:
                tw.tk.call("::tk::unsupported::MacWindowStyle", "style", tw._w, "help", "noActivates")
            except TclError:
                pass

            def fade_in():
                alpha = tw.attributes("-alpha")
                if alpha != self.attributes("-alpha"):
                    alpha += .1
                    tw.attributes("-alpha", alpha)
                    tw.after(self.transition, fade_in)
                else:
                    tw.attributes("-alpha", self.attributes("-alpha"))
            fade_in()
        
        def hidetip(self):
            tw = self.tipwindow
            self.tipwindow = None
            try:
                def fade_away():
                    alpha = tw.attributes("-alpha")
                    if alpha > 0:
                        alpha -= .1
                        tw.attributes("-alpha", alpha)
                        tw.after(self.transition, fade_away)
                    else:
                        tw.destroy()
                if not tw.attributes("-alpha") in [0, 1]:
                    tw.destroy()
                else:
                    fade_away()
            except:
                if tw:
                    tw.destoy()

    def createToolTip(self, widget: Any, text: str):
        toolTip = self.ToolTip(widget)

        def enter(event = None):
            if not self.showTooltip.get() == 0:
                self.task = self.after(1000, toolTip.showtip, text, widget, event)
        def leave(event = None):
            toolTip.hidetip(widget)

        widget.bind('<Enter>', enter)
        widget.bind('<Leave>', leave)
        widget.bind('<Button-1>', leave)

if __name__ == "__main__":
    root = Interface()
    root.mainloop()
else:
    print("This is the source code of a Windows app, therefore it's not intended to be imported in another code for any usage.")
