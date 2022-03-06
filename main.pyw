"""
MIT License

Copyright © 2017-2022 Yılmaz Alpaslan

Permission is hereby granted, free of charge to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be included in all copies
or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NOINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

__title__ = "Encrypt-n-Decrypt"
__author__ = "Yilmaz04"
__license__ = "MIT"
__copyright__ = "Copyright © 2017-2022 Yilmaz Alpaslan"
__version__ = "1.0.0"

from tkinter import (
    NORMAL, DISABLED, WORD, FLAT, END, LEFT,
    SOLID, X, Y, RIGHT, LEFT, BOTH, CENTER,
    TOP, SUNKEN, HORIZONTAL, BOTTOM, W,
    Text, Toplevel, Menu, Pack, Grid, Tk,
    Place, IntVar, StringVar, Label, Frame,
    filedialog, messagebox, TclError
)
TkLabel = Label
from tkinter.ttk import (
    Entry, Button, Label, LabelFrame, Frame,
    Widget, Notebook, Radiobutton, Checkbutton,
    Scrollbar, Progressbar, Separator, Combobox
)

from typing import (
    Union, Optional, Literal, Callable, overload
)
from urllib.request import urlopen
from markdown import markdown
from tkinterweb import HtmlFrame
from requests import get
from webbrowser import open as openweb
from string import ascii_letters, digits
from datetime import datetime
from random import randint, choice
from ttkthemes import ThemedStyle
from threading import Thread
from hurry.filesize import size, alternative

from Crypto.Cipher import AES, PKCS1_OAEP, DES3
from Crypto.PublicKey import RSA, DSA, ECC
from Crypto.Signature import DSS
from Crypto.Hash import (
    SHA1, SHA224, SHA256, SHA384, SHA512, MD2, MD4, MD5
)
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

import base64, os, logging, pyperclip, binascii
import functools, multipledispatch, sqlite3
import atexit, inspect

def threaded(function: Callable):
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        Thread(target=function, args=args, kwargs=kwargs).start()
    return wrapper

class Cryptography(object, metaclass=type):
    def __init__(self, master: Tk):
        self.master = master
        self.__encryption_busy: bool = False
        self.__decryption_busy: bool = False

    @staticmethod
    def generate_key(length: int = 32) -> str:
        if not isinstance(length, int):
            length = int(length)
        key = str()
        for _ in range(length):
            random = randint(1, 32)
            if random < 25:
                key += choice(ascii_letters)
            elif random >= 25 and random < 30:
                key += choice(digits)
            elif random >= 30:
                key += choice("!'^+%&/()=?_<>#${[]}\|__--$__--")
        return key

    @overload
    def derivate_key(password: bytes) -> bytes: ...
    @overload
    def derivate_key(password: str) -> Optional[bytes]: ...

    def derivate_key(password: Union[str, bytes]) -> Optional[bytes]:
        try:
            return base64.urlsafe_b64encode(scrypt(password.decode("utf-8") if isinstance(password, bytes) else password, get_random_bytes(16), 24, N=2**14, r=8, p=1))
        except UnicodeDecodeError:
            return None

    def traffic_controlled(function: Callable):
        @functools.wraps(function)
        def wrapper(*args, **kwargs):
            if function.__name__ == "encrypt":
                if not bool(args[0].master.mainNotebook.encryptionFrame.algorithmSelect.index(args[0].master.mainNotebook.encryptionFrame.algorithmSelect.select())):
                    args[0].master.mainNotebook.encryptionFrame.encryptButton.configure(state=DISABLED if bool(args[0].master.dataSourceVar.get()) else NORMAL)
                else:
                    args[0].master.mainNotebook.encryptionFrame.encryptButton.configure(state=DISABLED)
                if args[0].__encryption_busy and args[0].__encryption_busy is not None:
                    return
                args[0].__encryption_busy = True
                try:
                    return function(*args, **kwargs)
                except Exception:
                    pass
                finally:
                    args[0].__encryption_busy = False
                    if not bool(args[0].master.mainNotebook.index(args[0].master.mainNotebook.select())):
                        args[0].master.mainNotebook.encryptionFrame.encryptButton.configure(state=NORMAL)
                    else:
                        args[0].master.mainNotebook.decryptionFrame.decryptButton.configure(state=NORMAL)
            else:
                args[0].master.mainNotebook.decryptionFrame.decryptButton.configure(state=DISABLED) if bool(args[0].master.decryptSourceVar.get()) else None
                if args[0].__decryption_busy and args[0].__decryption_busy is not None:
                    return
                args[0].__decryption_busy = True
                try:
                    return function(*args, **kwargs)
                except Exception:
                    pass
                finally:
                    args[0].__decryption_busy = False
                    if not bool(args[0].master.mainNotebook.index(args[0].master.mainNotebook.select())):
                        args[0].master.mainNotebook.encryptionFrame.encryptButton.configure(state=NORMAL)
                    else:
                        args[0].master.mainNotebook.decryptionFrame.decryptButton.configure(state=NORMAL)
        return wrapper

    def update_status(self, status: str = "Ready"):
        self.master.statusBar.configure(text=f"Status: {status}")
        self.master.update()

    @property
    def encryption_busy(self) -> bool:
        return self.__encryption_busy
    @encryption_busy.setter
    def encryption_busy(self, value: bool):
        if self.__encryption_busy == value and value:
            raise Exception
        self.__encryption_busy = value

    @property
    def decryption_busy(self) -> bool:
        return self.__decryption_busy
    @decryption_busy.setter
    def decryption_busy(self, value: bool):
        if self.__decryption_busy == value and value:
            raise Exception
        self.__decryption_busy = value

    @threaded
    @traffic_controlled
    def encrypt(self):
        if not bool(self.master.dataSourceVar.get()):
            data: str = self.master.textEntryVar.get()
        else:
            self.update_status("Reading the file...")
            path: str = self.master.mainNotebook.encryptionFrame.fileEntry.get()
            try:
                with open(path, mode="rb") as file:
                    data: bytes = file.read()
            except PermissionError:
                messagebox.showerror("Permission denied", "Access to the file you've specified has been denied. Try running the program as administrator and make sure read & write access for the file is permitted.")
                self.master.logger.error("Read permission for the file specified has been denied, encryption was interrupted")
                self.update_status("Ready")
                return

        if not bool(self.master.mainNotebook.encryptionFrame.algorithmSelect.index(self.master.mainNotebook.encryptionFrame.algorithmSelect.select())):
            if not bool(self.master.keySourceSelection.get()):
                self.update_status("Generating the key...")
                key: bytes = self.generate_key(int(self.master.generateRandomAESVar.get() if not bool(self.master.generateAlgorithmSelection.get()) else self.master.generateRandomDESVar.get()) / 8).encode("utf-8")
            else:
                key: bytes = self.master.keyEntryVar.get().encode("utf-8")

            self.update_status("Creating the cipher...")
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
                    self.master.logger.error("Key with invalid length was specified")
                    self.update_status("Ready")
                    return
                else:
                    messagebox.showerror("Invalid key", "The key you've entered is invalid for encryption. Please enter another key or consider generating one instead.")
                    self.master.logger.error("Invalid key was specified")
                    self.update_status("Ready")
                    return

            self.update_status("Encrypting...")
            try:
                self.master.lastResult = iv + cipher.encrypt(data.encode("utf-8") if type(data) is str else data)
            except MemoryError:
                messagebox.showerror("Not enough memory", "Your computer has run out of memory while encrypting the file. Try closing other applications or restart your computer.")
                self.master.logger.error("Device has run out of memory while encrypting, encryption was interrupted")
                self.update_status("Ready")
                return
            del data
            self.update_status("Encoding the result...")
            try:
                try:
                    self.master.lastResult = base64.urlsafe_b64encode(self.master.lastResult).decode("utf-8")
                except TypeError:
                    self.update_status("Ready")
                    return
            except MemoryError:
                messagebox.showerror("Not enough memory", "Your computer has run out of memory while encoding the result. Try closing other applications or restart your computer.")
                self.master.logger.error("Device has run out of memory while encoding, encryption was interrupted")
                self.update_status("Ready")
                return
            self.master.lastKey = key

            failure = False
            if bool(self.master.dataSourceVar.get()) and bool(self.master.writeFileContentVar.get()):
                self.update_status("Writing to the file...")
                for _ in range(1):
                    try:
                        with open(path, mode="wb") as file:
                            file.write(bytes(self.master.lastResult, "utf-8"))
                    except PermissionError:
                        if messagebox.askyesnocancel("Permission denied", "Write access to the file you've specified had been denied. Do you want to save the encrypted data as another file?"):
                            newpath = filedialog.asksaveasfilename(title="Save encrypted data", initialfile=os.path.basename(path[:-1] if path[-1:] == "\\" else path), initialdir=os.path.dirname(path), filetypes=[("All files","*.*")], defaultextension="*.key")
                            if newpath == "":
                                failure = True
                                self.master.logger.error("Write permission for the file specified has been denied, encryped data could not be saved to the destination")
                                break
                            else:
                                with open(newpath, mode="wb") as file:
                                    file.write(bytes(self.master.lastResult, "utf-8"))
                        self.master.logger.error("Write permission for the file specified has been denied, encrypted data could not be saved to the destination")
                        self.update_status("Ready")
                        failure = True
                        return
                    except OSError as details:
                        if "No space" in str(details):
                            messagebox.showerror("No space left", "There is no space left on your device. Free up some space and try again.")
                            self.master.logger.error("No space left on device, encrypted data could not be saved to the destination")
                            self.update_status("Ready")
                            failure = True
                            pass

            if not len(self.master.lastResult) > 15000:
                self.master.mainNotebook.encryptionFrame.outputFrame.outputText.configure(foreground="black", wrap=None)
                self.master.mainNotebook.encryptionFrame.outputFrame.outputText.replace(self.master.lastResult)
            else:
                self.master.mainNotebook.encryptionFrame.outputFrame.outputText.configure(foreground="gray", wrap=WORD)
                self.master.mainNotebook.encryptionFrame.outputFrame.outputText.replace("The encrypted text is not being displayed because it is longer than 15.000 characters.")

            self.master.mainNotebook.encryptionFrame.outputFrame.AESKeyText.replace(key.decode("utf-8"))
            self.master.mainNotebook.encryptionFrame.outputFrame.RSAPublicText.configure(bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, highlightcolor="#cccccc")
            self.master.mainNotebook.encryptionFrame.outputFrame.RSAPrivateText.configure(bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, highlightcolor="#cccccc")
            self.master.mainNotebook.encryptionFrame.outputFrame.RSAPublicText.clear()
            self.master.mainNotebook.encryptionFrame.outputFrame.RSAPrivateText.clear()

            self.update_status("Ready")
            if not failure:
                if not bool(self.master.keySourceSelection.get()):
                    self.master.logger.info(f"{'Entered text' if not bool(self.master.dataSourceVar.get()) else 'Specified file'} has been successfully encrypted using {'AES' if not bool(self.master.generateAlgorithmSelection.get()) else '3DES'}-{len(key) * 8} algorithm")
                else:
                    self.master.logger.info(f"{'Entered text' if not bool(self.master.dataSourceVar.get()) else 'Specified file'} has been successfully encrypted using {'AES' if not bool(self.master.entryAlgorithmSelection.get()) else '3DES'}-{len(key) * 8} algorithm")

        else:
            self.update_status("Generating the key...")
            key = RSA.generate(self.master.generateRandomRSAVar.get())
            publicKey = key.publickey()
            privateKey = key.exportKey()

            self.update_status("Defining the cipher...")
            cipher = PKCS1_OAEP.new(publicKey)

            self.update_status("Encrypting...")
            try:
                encrypted = cipher.encrypt(data.encode("utf-8") if isinstance(data, str) else data)
            except ValueError:
                messagebox.showerror(f"{'Text is too long' if not bool(self.master.dataSourceVar) else 'File is too big'}", "The {} is too {} for RSA-{} encryption. Select a longer RSA key and try again.".format('text you\'ve entered' if not bool(self.master.dataSourceVar.get()) else 'file you\'ve specified', 'long' if not bool(self.master.dataSourceVar.get()) else 'big', self.master.generateRandomRSAVar.get()))
                self.master.logger.error(f"Too {'long text' if not bool(self.master.dataSourceVar) else 'big file'} was specified, encryption was interrupted")
                self.update_status("Ready")
                return

            self.master.mainNotebook.encryptionFrame.outputFrame.outputText.replace(base64.urlsafe_b64encode(encrypted).decode("utf-8"))
            self.master.mainNotebook.encryptionFrame.outputFrame.AESKeyText.clear()
            self.master.mainNotebook.encryptionFrame.outputFrame.RSAPublicText.replace(base64.urlsafe_b64encode(publicKey.export_key()).decode("utf-8"))
            self.master.mainNotebook.encryptionFrame.outputFrame.RSAPrivateText.replace(base64.urlsafe_b64encode(privateKey).decode("utf-8"))

            """
            decryptor = PKCS1_OAEP.new(RSA.import_key(privateKey))
            decrypted = decryptor.decrypt(encrypted)
            print('Decrypted:', decrypted.decode())
            """

            self.update_status("Ready")

    @threaded
    @traffic_controlled
    def decrypt(self):
        if not bool(self.master.decryptSourceVar.get()):
            self.update_status("Decoding encrypted data...")
            data = base64.urlsafe_b64decode(self.master.textDecryptVar.get().encode("utf-8"))
        else:
            self.update_status("Reading the file...")
            try:
                with open(self.master.mainNotebook.decryptionFrame.fileDecryptEntry.get(), mode="r+b") as file:
                    data = file.read()
            except PermissionError:
                messagebox.showerror("Permission denied", "Access to the file you've specified has been denied. Try running the program as administrator and make sure read & write access for the file is permitted.")
                self.master.logger.error("Read permission for the file specified has been denied, decryption was interrupted")
                self.update_status("Ready")
                return
            self.update_status("Decoding the file data...")
            try:
                decodedData = base64.urlsafe_b64decode(data)
            except:
                messagebox.showerror("Unencrypted file", f"This file seems to be not encrypted using {'AES' if not bool(self.master.decryptAlgorithmVar.get()) else '3DES'} symmetric key encryption algorithm.")
                self.master.logger.error("Unencrypted file was specified")
                self.update_status("Ready")
                return
            else:
                if data == base64.urlsafe_b64encode(decodedData):
                    data = decodedData
                    del decodedData
                else:
                    messagebox.showerror("Unencrypted file", f"This file seems to be not encrypted using {'AES' if not bool(self.master.decryptAlgorithmVar.get()) else '3DES'} symmetric key encryption algorithm.")
                    self.master.logger.error("Unencrypted file was specified")
                    self.update_status("Ready")
                    return
        iv = data[:16 if not bool(self.master.decryptAlgorithmVar.get()) else 8]
        key = self.master.decryptKeyVar.get()[:-1 if self.master.decryptKeyVar.get().endswith("\n") else None].encode("utf-8")

        self.update_status("Defining cipher...")
        try:
            if not bool(self.master.decryptAlgorithmVar.get()):
                cipher = AES.new(key, AES.MODE_CFB, iv=iv)
            else:
                cipher = DES3.new(key, DES3.MODE_OFB, iv=iv)
        except ValueError as details:
            if (len(iv)) != 16 if not bool(self.master.decryptAlgorithmVar.get()) else 8:
                messagebox.showerror("Unencrypted data", f"The text you've entered seems to be not encrypted using {'AES' if not bool(self.master.decryptAlgorithmVar.get()) else '3DES'} symmetric key encryption algorithm.")
                self.master.logger.error("Unencrypted text was entered")
                self.update_status("Ready")
                return
            elif not len(key) in [16, 24, 32 if "AES" in str(details) else False]:
                messagebox.showerror("Invalid key length", "The length of the encryption key you've entered is invalid! It can be either 16, 24 or 32 characters long.")
                self.master.logger.error("Key with invalid length was entered for decryption")
                self.update_status("Ready")
                return
            else:
                messagebox.showerror("Invalid key", "The key you've entered is invalid.")
                self.master.logger.error("Invalid key was entered for decryption")
                self.update_status("Ready")
                return
        self.update_status("Decrypting...")
        try:
            result = cipher.decrypt(data.replace(iv, b""))
        except UnicodeDecodeError:
            messagebox.showerror("Invalid key", "The encryption key you've entered seems to be not the right key. Make sure you've entered the correct key.")
            self.master.logger.error("Wrong key entered for decryption")
            self.update_status("Ready")
            return

        self.update_status("Writing to the file...")
        if bool(self.master.decryptSourceVar.get()):
            try:
                with open(self.master.mainNotebook.decryptionFrame.fileDecryptEntry.get(), mode="wb") as file:
                    file.write(result)
            except PermissionError:
                messagebox.showerror("Permission denied", "Access to the file you've specified has been denied. Try running the program as administrator and make sure write access for the file is permitted.")
                self.master.logger.error("Write permission for the file specified has been denied, decryption was interrupted")
                self.update_status("Ready")
                return

        self.update_status("Displaying the result...")
        try:
            result = result.decode("utf-8")
        except UnicodeDecodeError:
            if bool(self.master.decryptSourceVar.get()):
                self.master.mainNotebook.decryptionFrame.decryptOutputText.configure(foreground="gray")
                self.master.mainNotebook.decryptionFrame.decryptOutputText.replace("Decrypted data is not being displayed because it's in an unknown encoding.")
            else:
                messagebox.showerror("Invalid key", "The encryption key you've entered seems to be not the right key. Make sure you've entered the correct key.")
                self.master.logger.error("Wrong key was entered for decryption")
                self.update_status("Ready")
                return
        else:
            if not len(result) > 15000:
                self.master.mainNotebook.decryptionFrame.decryptOutputText.configure(foreground="black")
                self.master.mainNotebook.decryptionFrame.decryptOutputText.replace(result)
            else:
                self.master.mainNotebook.decryptionFrame.decryptOutputText.configure(foreground="gray")
                self.master.mainNotebook.decryptionFrame.decryptOutputText.replace("Decrypted data is not being displayed because it's longer than 15.000 characters.")
        self.update_status("Ready")

class Cache(object):
    def __init__(self, master: Tk):
        super().__init__()
        self.master = master

        self.loggings_history: list[dict[logging.LogRecord, dict[str, Union[str, int, bool]]]] = []
        self.encryptions_history: list[dict] = []
        self.decryptions_history: list[dict] = []

class Handler(logging.Handler):
    def __init__(self, widget: Optional[Text], master: Tk, cache: Cache = None):
        super().__init__()
        self.widget = widget
        self.master = master
        self.cache = cache

    def emit(self, record: logging.LogRecord):
        message = self.format(record)
        def append():
            levels = {
                "NOTSET": 0, "DEBUG": 10, "INFO": 20,
                "WARNING": 30, "ERROR": 40, "CRITICAL": 50
            }
            if record.levelno < levels[self.master.levelSelectVar.get()]:
                return
            self.widget.configure(state=NORMAL)
            self.widget.insert(END, message, record.levelname.lower())
            self.widget.configure(state=DISABLED)

            self.widget.yview(END)
        if self.widget is not None:
            self.widget.after(0, append)
        record_dict: dict = {}
        record_dict[record] = {
            "message": message,
            "levelname": record.levelname,
            "levelno": record.levelno,
            "in_file": bool(self.master.loggingAutoSaveVar.get())
        }
        self.cache.loggings_history.append(record_dict)

        if bool(self.master.loggingAutoSaveVar.get()):
            temp_list: list = []
            for entry in self.cache.loggings_history:
                record: logging.LogRecord = list(entry.keys())[0]
                message: str = list(entry.values())[0]["message"]
                in_file: bool = list(entry.values())[0]["in_file"]
                if in_file:
                    temp_list.append(message)
            if os.path.exists(f"{__title__}.log"):
                with open(f"{__title__}.log", mode="r", encoding="utf-8") as file:
                    index = file.read()
                    new_index: list = []
                    for line in index.splitlines()[::-1]:
                        if "Start of logging session at" in line:
                            continue
                        new_index.append(line)
            else:
                index = str()
            with open(f"{__title__}.log", mode="a+", encoding="utf-8") as file:
                if ''.join(index.split()) == '' or index.endswith((f"{'='*24} End of logging session {'='*25}\n", f"{'='*24} End of logging session {'='*25}")):
                    endl = "\n"
                    file.write(f"{endl if ''.join(index.split()) != '' else ''}============ Start of logging session at {str(datetime.now().strftime(r'%Y-%m-%d %H:%M:%S'))} ============\n")
                file.write(message)

    @staticmethod
    def format(record: logging.LogRecord) -> str:
        return str(datetime.now().strftime(r'%Y-%m-%d %H:%M:%S') + f" [{record.levelname}] " + record.getMessage())

class Logger(object):
    def __init__(self, widget: Optional[Text], root: Tk):
        self.widget = widget
        self.root = root

        loghandler = Handler(widget=self.widget, master=self.root, cache=self.root.cache)
        logging.basicConfig(
            format = '%(asctime)s [%(levelname)s] %(message)s',
            level = logging.DEBUG,
            datefmt = r'%Y-%m-%d %H:%M:%S',
            handlers = [loghandler]
        )
        self.logger = logging.getLogger()
        self.logger.propagate = False

    def end_logging_file(self):
        if bool(self.root.loggingAutoSaveVar.get()):
            try:
                with open(f"{__title__}.log", mode="r", encoding="utf-8") as file:
                    index = file.read()
            except FileNotFoundError:
                return
            with open(f"{__title__}.log", mode="a", encoding="utf-8") as file:
                if ''.join(index.split()) != '':
                    file.write(f"{'='*24} End of logging session {'='*25}\n")

    def debug(self, message: str, newline: bool = True):
        self.logger.debug(message + ("\n" if newline else ""))
    def info(self, message: str, newline: bool = True):
        self.logger.info(message + ("\n" if newline else ""))
    def warning(self, message: str, newline: bool = True):
        self.logger.warning(message + ("\n" if newline else ""))
    def error(self, message: str, newline: bool = True):
        self.logger.error(message + ("\n" if newline else ""))
    def critical(self, message: str, newline: bool = True):
        self.logger.critical(message + ("\n" if newline else ""))

class ToolTip(object):
    def __init__(self, widget: Widget, tooltip: str, interval: int = 1000, length: int = 400):
        self.widget = widget
        self.interval = interval
        self.wraplength = length
        self.text = tooltip
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.leave)
        self.widget.bind("<ButtonPress>", self.leave)
        self.id = None
        self.tw = None

    def enter(self, event=None):
        self.schedule()

    def leave(self, event=None):
        self.unschedule()
        self.hidetip()

    def schedule(self):
        self.unschedule()
        self.id = self.widget.after(self.interval, self.showtip)

    def unschedule(self):
        id = self.id
        self.id = None
        if id:
            self.widget.after_cancel(id)

    def showtip(self, event=None):
        x = root.winfo_pointerx() + 12
        y = root.winfo_pointery() + 16

        self.tw = Toplevel(self.widget)
        self.tw.attributes("-alpha", 0)

        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry("+%d+%d" % (x, y))
        label = Label(self.tw, text=self.text,
            justify='left', background="#ffffff",
            foreground="#6f6f6f", relief='solid',
            borderwidth=1, wraplength=self.wraplength)
        label.pack(ipadx=1)

        def fade_in():
            if not self.widget is root.winfo_containing(root.winfo_pointerx(), root.winfo_pointery()):
                self.tw.destroy()
                return
            alpha = self.tw.attributes("-alpha")
            if alpha != 1:
                alpha += .1
                self.tw.attributes("-alpha", alpha)
                self.tw.after(8, fade_in)
            else:
                self.tw.attributes("-alpha", 1)
                return
        fade_in()

    def hidetip(self):
        if self.tw:
            def fade_away():
                if not self.widget is root.winfo_containing(root.winfo_pointerx(), root.winfo_pointery()):
                    self.tw.destroy()
                    return
                try:
                    alpha = self.tw.attributes("-alpha")
                except TclError:
                    return
                if alpha != 0:
                    alpha -= .1
                    self.tw.attributes("-alpha", alpha)
                    self.tw.after(8, fade_away)
                else:
                    self.tw.destroy()
            fade_away()

class ScrolledText(Text):
    def __init__(self, master: Union[Tk, Frame, LabelFrame], tooltip: Optional[str] = None, *args, **kwargs):
        try:
            self._textvariable = kwargs.pop("textvariable")
        except KeyError:
            self._textvariable = None
        self.frame = Frame(master)
        self.vbar = Scrollbar(self.frame)
        self.vbar.pack(side=RIGHT, fill=Y)
        kwargs.update({'yscrollcommand': self.vbar.set})
        super().__init__(self.frame, *args, **kwargs)
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
        self.tk.eval("""
        proc widget_proxy {widget widget_command args} {

            set result [uplevel [linsert $args 0 $widget_command]]

            if {([lindex $args 0] in {insert replace delete})} {
                event generate $widget <<Change>> -when tail
            }

            return $result
        }""")
        self.tk.eval('''
            rename {widget} _{widget}
            interp alias {{}} ::{widget} {{}} widget_proxy {widget} _{widget}
        '''.format(widget=str(Text.__str__(self))))
        self.bind("<<Change>>", self._on_widget_change)

        if self._textvariable is not None:
            self._textvariable.trace("wu", self._on_var_change)

        if tooltip is not None:
            self.toolTip = ToolTip(widget=self, tooltip=tooltip)

    @multipledispatch.dispatch(str)
    def replace(self, chars: str):
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete("1.0", END)
        self.insert("1.0", chars)
        self.configure(state=old_val)

    @multipledispatch.dispatch(str, str, str)
    def replace(self, chars: str, start_index: str, end_index: str):
        self.tk.call(self._w, 'replace', start_index, end_index, chars)

    def clear(self):
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete("1.0", END)
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
    def __init__(self, master: Union[Tk, Frame, LabelFrame], tooltip: Optional[str] = None, *args, **kwargs):
        try:
            self._textvariable = kwargs.pop("textvariable")
        except KeyError:
            self._textvariable = None

        super().__init__(master, *args, **kwargs)

        if self._textvariable is not None:
            self.insert("1.0", self._textvariable.get())
        self.tk.eval("""
        proc widget_proxy {widget widget_command args} {

            set result [uplevel [linsert $args 0 $widget_command]]

            if {([lindex $args 0] in {insert replace delete})} {
                event generate $widget <<Change>> -when tail
            }

            return $result
        }""")
        self.tk.eval('''
            rename {widget} _{widget}
            interp alias {{}} ::{widget} {{}} widget_proxy {widget} _{widget}
        '''.format(widget=str(self)))
        self.bind("<<Change>>", self._on_widget_change)

        if self._textvariable is not None:
            self._textvariable.trace("wu", self._on_var_change)
        
        if tooltip is not None:
            self.toolTip = ToolTip(widget=self, tooltip=tooltip)

    @multipledispatch.dispatch(str)
    def replace(self, chars: str):
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete("1.0", END)
        self.insert("1.0", chars)
        self.configure(state=old_val)

    @multipledispatch.dispatch(str, str, str)
    def replace(self, chars: str, start_index: str, end_index: str):
        self.tk.call(self._w, 'replace', start_index, end_index, chars)

    def clear(self):
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete("1.0", END)
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

class Notebook(Notebook):
    def __init__(self, master: Union[Tk, Frame, LabelFrame], *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.bind("<<NotebookTabChanged>>", lambda _: self.on_tab_change())
        self.__history: Optional[list] = list()

    @property
    def last_tab(self) -> Optional[int]:
        try:
            return self.__history[-2]
        except IndexError:
            if bool(len(self.__history)):
                return self.__history[0]
            else:
                return None

    def on_tab_change(self, event = None):
        if self.master.__class__.__name__ == "Interface":
            if self.index(self.select()) == 4:
                if not hasattr(self, "HTML"):
                    self.master.statusBar.configure(text="Status: Downloading HTML...")
                    self.master.update()
                    try:
                        request = get("https://raw.githubusercontent.com/Yilmaz4/Encrypt-n-Decrypt/main/README.md").text
                    except Exception as details:
                        messagebox.showerror("No Internet Connection", "Your internet connection appears to be offline. We were unable to download required content to show this page.")
                        self.master.logger.error(f"Connection to 'raw.githubusercontent.com' has failed, downloading HTML was interrupted. Error details: {str(details)}")
                        self.master.mainNotebook.select(self.master.mainNotebook.last_tab)
                        return
                    self.HTML = markdown(request)
                    self.master.statusBar.configure(text="Status: Ready")
                    self.master.update()
                self.master.readmePage = HtmlFrame(self.master, messages_enabled=False, vertical_scrollbar=True)
                self.master.readmePage.load_html(self.HTML)
                self.master.readmePage.set_zoom(0.8)
                self.master.readmePage.grid_propagate(0)
                self.master.readmePage.enable_images(1)
                self.master.readmePage.place(x=5, y=27, height=528, width=790)
            else:
                if hasattr(self.master, "readmePage"):
                    try:
                        self.master.readmePage.place_forget()
                        self.master.readmePage.destroy()
                    except TclError:
                        pass
        if len(self.__history) >= 2:
            del self.__history[0]
        self.__history.append(self.index(self.select()))

class Widget(Widget):
    def __init__(self, master: Union[Tk, Frame, LabelFrame], tooltip: Optional[str] = None, *args, **kwargs):
        super().__init__(master, *args, **kwargs)

        if tooltip is not None:
            self.toolTip = ToolTip(widget=self, tooltip=tooltip)

class Entry(Widget, Entry):
    def replace(self, string: str):
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete(0, END)
        self.insert(0, string)
        self.configure(state=old_val)

    def clear(self):
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete(0, END)
        self.configure(state=old_val)

class Button(Widget, Button): ...

class Label(Widget, Label): ...

class Radiobutton(Widget, Radiobutton): ...

class Checkbutton(Widget, Checkbutton): ...

class Interface(Tk):
    def __init__(self):

        super().__init__()

        self.theme = ThemedStyle(self, gif_override=True)
        self.theme.set_theme("vista" if os.name == "nt" else "arc")

        self.__initialize_vars()

        self.withdraw()

        self.height = 580
        self.width = 800
        self.version = __version__

        self.wm_title(f"{__title__} v{self.version}")
        self.wm_geometry(f"{self.width}x{self.height}")
        self.wm_resizable(width=False, height=False)
        self.wm_minsize(width = self.width, height = self.height)
        self.wm_maxsize(width = self.width, height = self.height)
        try:
            self.wm_iconbitmap("icon.ico")
        except TclError:
            pass

        self.crypto = Cryptography(self)
        self.cache = Cache(self)

        class mainNotebook(Notebook):
            def __init__(self, master: Interface):
                super().__init__(master, width=380, height=340)

                class encryptionFrame(Frame):
                    def __init__(self, master: mainNotebook = None, **kwargs):
                        super().__init__(master=master, **kwargs)
                        self.root = self.master.master

                        self.textEntryCheck = Radiobutton(self, text="Plain text:", tooltip="Select this if you want to encrypt a short message", value=0, variable=self.root.dataSourceVar, command=self.changeDataSource, takefocus=0)
                        self.textEntry = Entry(self, width=48, font=("Consolas", 9), state=NORMAL, takefocus=0, textvariable=self.root.textEntryVar)
                        self.textPasteButton = Button(self, text="Paste", tooltip="Paste the contents of the clipboard into the entry above", width=14, state=NORMAL, command=lambda: self.textEntry.replace(str(self.root.clipboard_get())), takefocus=0)
                        self.textClearButton = Button(self, text="Clear", tooltip="Delete everything written in the above entry", width=14, command=lambda: self.textEntry.delete(0, END), takefocus=0, state=DISABLED)
                        self.textEntryHideCharCheck = Checkbutton(self, text="Hide characters", tooltip="Check this if you want the things you write in the above entry to be not visible", variable=self.root.textEntryHideCharVar, onvalue=1, offvalue=0, command=self.changeDataEntryHideChar, takefocus=0)

                        self.fileEntryCheck = Radiobutton(self, text="File:", value=1, variable=self.root.dataSourceVar, command=self.changeDataSource, takefocus=0)
                        self.fileValidityLabel = Label(self, text="Validity: [Blank]", foreground="gray")
                        self.fileEntry = Entry(self, width=48, font=("Consolas", 9), state=DISABLED, takefocus=0, textvariable=self.root.fileEntryVar)
                        self.fileBrowseButton = Button(self, text="Browse...", width=14, state=DISABLED, command=self.fileEntryBrowse, takefocus=0)
                        self.fileClearButton = Button(self, text="Clear", width=14, state=DISABLED, command=lambda: self.fileEntry.delete(0, END), takefocus=0)

                        self.root.textEntryVar.trace("w", self.textEntryCallback)
                        self.root.fileEntryVar.trace("w", self.fileEntryCallback)

                        self.textEntryCheck.place(x=8, y=2)
                        self.textEntry.place(x=24, y=22)
                        self.textPasteButton.place(x=23, y=49)
                        self.textClearButton.place(x=124, y=49)
                        self.textEntryHideCharCheck.place(x=263, y=50)

                        self.fileEntryCheck.place(x=8, y=76)
                        self.fileValidityLabel.place(x=51, y=77)
                        self.fileEntry.place(x=24, y=96)
                        self.fileBrowseButton.place(x=23, y=123)
                        self.fileClearButton.place(x=124, y=123)

                        class algorithmSelect(Notebook):
                            def __init__(self, master: encryptionFrame):
                                super().__init__(master, width=355, height=290, takefocus=0)

                                class symmetricEncryption(Frame):
                                    def __init__(self, master: Notebook, **kwargs):
                                        super().__init__(master, **kwargs)
                                        self.root = self.master.master.master.master

                                        self.generateRandomKeyCheck = Radiobutton(self, text="Generate a random key", value=0, variable=self.root.keySourceSelection, command=self.master.master.changeSourceSelection, takefocus=0)

                                        self.AESAlgorithmCheck = Radiobutton(self, text="AES (Advanced Encryption Standard)", value=0, variable=self.root.generateAlgorithmSelection, command=self.master.master.changeAlgorithmSelection, takefocus=0)
                                        self.AES128Check = Radiobutton(self, text="AES-128 Key", value=128, variable=self.root.generateRandomAESVar, takefocus=0)
                                        self.AES192Check = Radiobutton(self, text="AES-192 Key", value=192, variable=self.root.generateRandomAESVar, takefocus=0)
                                        self.AES256Check = Radiobutton(self, text="AES-256 Key", value=256, variable=self.root.generateRandomAESVar, takefocus=0)

                                        self.DESAlgorithmCheck = Radiobutton(self, text="3DES (Triple Data Encryption Standard)", value=1, variable=self.root.generateAlgorithmSelection, command=self.master.master.changeAlgorithmSelection, takefocus=0)
                                        self.DES128Check = Radiobutton(self, text="3DES-128 Key", value=128, state=DISABLED, variable=self.root.generateRandomDESVar, takefocus=0)
                                        self.DES192Check = Radiobutton(self, text="3DES-192 Key", value=192, state=DISABLED, variable=self.root.generateRandomDESVar, takefocus=0)

                                        self.selectKeyCheck = Radiobutton(self, text="Use this key:", value=1, variable=self.root.keySourceSelection, command=self.master.master.changeSourceSelection, takefocus=0)
                                        self.keyEntry = Entry(self, width=46, font=("Consolas",9), state=DISABLED, textvariable=self.root.keyEntryVar, takefocus=0)
                                        self.keyValidityStatusLabel = Label(self, text="Validity: [Blank]", foreground="gray", takefocus=0)
                                        self.keyEntryHideCharCheck = Checkbutton(self, text="Hide characters", onvalue=1, offvalue=0, variable=self.root.keyEntryHideCharVar, state=DISABLED, takefocus=0)
                                        self.keyBrowseButton = Button(self, text="Browse key file...", width=21, state=DISABLED, command=self.master.master.getKeyFromFile, takefocus=0)
                                        self.keyPasteButton = Button(self, text="Paste", width=13, state=DISABLED, command=lambda: self.keyEntry.replace(self.root.clipboard_get()), takefocus=0)
                                        self.keyClearButton = Button(self, text="Clear", width=13, state=DISABLED, command=lambda: self.keyEntry.clear(), takefocus=0)
                                        self.keyEnteredAlgAES = Radiobutton(self, text="AES (Advanced Encryption Standard)", value=0, variable=self.root.entryAlgorithmSelection, command=self.master.master.limitKeyEntry, state=DISABLED, takefocus=0)
                                        self.keyEnteredAlgDES = Radiobutton(self, text="3DES (Triple Data Encryption Standard)", value=1, variable=self.root.entryAlgorithmSelection, command=self.master.master.limitKeyEntry, state=DISABLED, takefocus=0)

                                        self.root.keyEntryVar.trace("w", self.master.master.limitKeyEntry)

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

                                class asymmetricEncryption(Frame):
                                    def __init__(self, master: Notebook, **kwargs):
                                        super().__init__(master, **kwargs)
                                        self.root = self.master.master.master.master

                                        self.generateRandomKeyCheck = Radiobutton(self, text="Generate a random key", value=0, variable=self.root.keySourceSelection, command=self.master.master.changeSourceSelection, takefocus=0)

                                        self.RSA1024Check = Radiobutton(self, text="RSA-1024 Key", value=1024, variable=self.root.generateRandomRSAVar, command=lambda: self.RSACustomEntry.configure(state=DISABLED if self.root.generateRandomRSAVar.get() else NORMAL), takefocus=0)
                                        self.RSA2048Check = Radiobutton(self, text="RSA-2048 Key", value=2048, variable=self.root.generateRandomRSAVar, command=lambda: self.RSACustomEntry.configure(state=DISABLED if self.root.generateRandomRSAVar.get() else NORMAL), takefocus=0)
                                        self.RSA3072Check = Radiobutton(self, text="RSA-3072 Key", value=3072, variable=self.root.generateRandomRSAVar, command=lambda: self.RSACustomEntry.configure(state=DISABLED if self.root.generateRandomRSAVar.get() else NORMAL), takefocus=0)
                                        self.RSA4096Check = Radiobutton(self, text="RSA-4096 Key", value=4096, variable=self.root.generateRandomRSAVar, command=lambda: self.RSACustomEntry.configure(state=DISABLED if self.root.generateRandomRSAVar.get() else NORMAL), takefocus=0)
                                        self.RSA6144Check = Radiobutton(self, text="RSA-6144 Key", value=6144, variable=self.root.generateRandomRSAVar, command=lambda: self.RSACustomEntry.configure(state=DISABLED if self.root.generateRandomRSAVar.get() else NORMAL), takefocus=0)
                                        self.RSA8196Check = Radiobutton(self, text="RSA-8192 Key", value=8192, variable=self.root.generateRandomRSAVar, command=lambda: self.RSACustomEntry.configure(state=DISABLED if self.root.generateRandomRSAVar.get() else NORMAL), takefocus=0)
                                        self.RSACustomCheck = Radiobutton(self, text="Custom RSA key length:", value=0, variable=self.root.generateRandomRSAVar, command=lambda: self.RSACustomEntry.configure(state=DISABLED if self.root.generateRandomRSAVar.get() else NORMAL), takefocus=0)
                                        self.RSACustomEntry = Entry(self, width=6, state=DISABLED, validate = 'all', validatecommand = (self.root.register(lambda P: (str.isdigit(P) or P == "") and len(P) <= 6), '%P'), textvariable=self.root.customRSALengthVar, takefocus=0)
                                        self.RSACustomEntry.replace("1024")

                                        self.selectKeyCheck = Radiobutton(self, text="Use this key:", value=1, variable=self.root.keySourceSelection, command=self.master.master.changeSourceSelection, takefocus=0)
                                        self.keyEntry = Entry(self, width=46, font=("Consolas", 9), state=DISABLED, textvariable=self.root.keyEntryVar, takefocus=0)
                                        self.keyValidityStatusLabel = Label(self, text="Validity: [Blank]", foreground="gray", takefocus=0)
                                        self.keyEntryHideCharCheck = Checkbutton(self, text="Hide characters", onvalue=1, offvalue=0, variable=self.root.keyEntryHideCharVar, state=DISABLED, takefocus=0)
                                        self.keyBrowseButton = Button(self, text="Browse key file...", width=21, state=DISABLED, command=self.master.master.getKeyFromFile, takefocus=0)
                                        self.keyPasteButton = Button(self, text="Paste", width=13, state=DISABLED, command=lambda: self.keyEntry.insert(0, self.master.master.clipboard_get()), takefocus=0)
                                        self.keyClearButton = Button(self, text="Clear", width=13, state=DISABLED, command=lambda: self.keyEntry.delete(0, END), takefocus=0)
                                        self.keyEnteredAlgAES = Radiobutton(self, text="AES (Advanced Encryption Standard)", value=0, variable=self.root.entryAlgorithmSelection, command=self.master.master.limitKeyEntry, state=DISABLED, takefocus=0)
                                        self.keyEnteredAlgDES = Radiobutton(self, text="3DES (Triple Data Encryption Standard)", value=1, variable=self.root.entryAlgorithmSelection, command=self.master.master.limitKeyEntry, state=DISABLED, takefocus=0)

                                        self.root.keyEntryVar.trace("w", self.master.master.limitKeyEntry)

                                        self.generateRandomKeyCheck.place(x=5, y=5)
                                        self.RSA1024Check.place(x=16, y=25)
                                        self.RSA2048Check.place(x=16, y=44)
                                        self.RSA3072Check.place(x=16, y=63)
                                        self.RSA4096Check.place(x=120, y=25)
                                        self.RSA6144Check.place(x=120, y=44)
                                        self.RSA8196Check.place(x=120, y=63)
                                        self.RSACustomCheck.place(x=16, y=82)
                                        self.RSACustomEntry.place(x=170, y=83)
                                        
                                        self.keyEntry.place(x=18, y=181)
                                        self.keyValidityStatusLabel.place(x=92, y=159)
                                        self.keyClearButton.place(x=114, y=207)
                                        self.keyPasteButton.place(x=17, y=207)
                                        self.keyBrowseButton.place(x=211, y=207)
                                        self.keyEntryHideCharCheck.place(x=244, y=158)
                                        self.selectKeyCheck.place(x=5, y=158)
                                        self.keyEnteredAlgAES.place(x=16, y=235)
                                        self.keyEnteredAlgDES.place(x=16, y=254)


                                self.symmetricEncryption = symmetricEncryption(self)
                                self.asymmetricEncryption = asymmetricEncryption(self)

                                self.add(self.symmetricEncryption, text="Symmetric Key Encryption")
                                self.add(self.asymmetricEncryption, text="Asymmetric Key Encryption", state=DISABLED)

                        self.algorithmSelect = algorithmSelect(self)
                        self.encryptButton = Button(self, text="Encrypt", width=22, command=self.master.master.crypto.encrypt, takefocus=0)
                        self.writeFileContentCheck = Checkbutton(self, text="Write encrypted data to the file", variable=self.master.master.writeFileContentVar, state=DISABLED, takefocus=0)

                        self.algorithmSelect.place(x=10, y=155)
                        self.encryptButton.place(x=9, y=480)
                        self.writeFileContentCheck.place(x=160, y=482)

                        class outputFrame(LabelFrame):
                            def __init__(self, master: Frame):
                                super().__init__(master, text="Output", height=502, width=403, takefocus=0)
                                self.root = self.master.master.master

                                self.outputText = ScrolledText(self, height = 6, width = 52, state=DISABLED, font = ("Consolas", 9), bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, textvariable=self.root.outputVar, highlightcolor="#cccccc")
                                self.AESKeyText = Text(self, width=54, height=1, state=DISABLED, font=("Consolas",9), bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, textvariable=self.root.AESKeyVar, highlightcolor="#cccccc")
                                self.RSAPublicText = ScrolledText(self, height = 6, width = 52, state=DISABLED, font = ("Consolas", 9), bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", textvariable=self.root.RSAPublicVar, highlightthickness=1, highlightcolor="#cccccc")
                                self.RSAPrivateText = ScrolledText(self, height = 6, width = 52, state=DISABLED, font = ("Consolas", 9), bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", textvariable=self.root.RSAPrivateVar, highlightthickness=1, highlightcolor="#cccccc")
                                self.AESKeyLabel = Label(self, text="AES/3DES Key:", takefocus=0)
                                self.RSAPublicLabel = Label(self, text="RSA Public Key:", takefocus=0)
                                self.RSAPrivateLabel = Label(self, text="RSA Private Key:", takefocus=0)

                                self.root.outputVar.trace("w", self.outputTextCallback)
                                self.root.AESKeyVar.trace("w", self.AESKeyTextCallback)
                                self.root.RSAPublicVar.trace("w", self.RSAPublicTextCallback)
                                self.root.RSAPrivateVar.trace("w", self.RSAPrivateTextCallback)

                                self.copyOutputButton = Button(self, text = "Copy", width=10, command=lambda: self.root.clipboard_set(self.root.lastResult), state=DISABLED, takefocus=0)
                                self.clearOutputButton = Button(self, text = "Clear", width=10, command=lambda: self.outputText.clear(), state=DISABLED, takefocus=0)
                                self.saveOutputButton = Button(self, width=15, text="Save as...", command=self.saveOutput, state=DISABLED, takefocus=0)
                                self.copyAESKeyButton = Button(self, width = 10, text="Copy", command=lambda: self.root.clipboard_set(self.AESKeyText.get("1.0", END)), state=DISABLED, takefocus=0)
                                self.clearAESKeyButton = Button(self, width = 10, text="Clear", command=lambda: self.AESKeyText.clear(), state=DISABLED, takefocus=0)
                                self.saveAESKeyButton = Button(self, width=15, text="Save as...", command=self.saveAESKey, state=DISABLED, takefocus=0)
                                self.copyRSAPublicButton = Button(self, width = 10, text="Copy", command=lambda: self.root.clipboard_set(self.RSAPublicText.get("1.0", END)), state=DISABLED, takefocus=0)
                                self.clearRSAPublicButton = Button(self, width = 10, text="Clear", command=lambda: self.RSAPublicText.clear(), state=DISABLED, takefocus=0)
                                self.saveRSAPublicButton = Button(self, width=15, text="Save as...", command=self.saveRSAPublic, state=DISABLED, takefocus=0)
                                self.copyRSAPrivateButton = Button(self, width = 10, text="Copy", command=lambda: self.root.clipboard_set(self.RSAPrivateText.get("1.0", END)), state=DISABLED, takefocus=0)
                                self.clearRSAPrivateButton = Button(self, width = 10, text="Clear", command=lambda: self.RSAPrivateText.clear(), state=DISABLED, takefocus=0)
                                self.saveRSAPrivateButton = Button(self, width=15, text="Save as...", command=self.saveRSAPrivate, state=DISABLED, takefocus=0)

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

                            def saveOutput(self):
                                files = [("Text document", "*.txt"), ("All files", "*.*")]
                                path = filedialog.asksaveasfilename(title="Save encrypted data", initialfile="Encrypted Data.txt", filetypes=files, defaultextension="*.txt")
                                if path == "":
                                    return
                                with open(path, encoding="utf-8", mode="w") as file:
                                    file.write(self.root.outputVar.get())

                            def saveAESKey(self):
                                files = [("Encrypt'n'Decrypt key file", "*.key"), ("Text document", "*.txt"), ("All files", "*.*")]
                                path = filedialog.asksaveasfilename(title="Save encryption key", initialfile="Encryption Key.key", filetypes=files, defaultextension="*.key")
                                if path == "":
                                    return
                                if os.path.splitext(path)[1] == ".key":
                                    self.master.saveKey(path, self.root.AESKeyVar.get())
                                else:
                                    with open(path, encoding="utf-8", mode="w") as file:
                                        file.write(self.root.AESKeyVar.get())

                            def saveRSAPublic(self):
                                files = [("Text document", "*.txt"), ("All files", "*.*")]
                                path = filedialog.asksaveasfilename(title="Save public key", initialfile="Public Key.txt", filetypes=files, defaultextension="*.txt")
                                if path == "":
                                    return
                                with open(path, encoding="utf-8", mode="w") as file:
                                    file.write(self.root.RSAPublicVar.get())

                            def saveRSAPrivate(self):
                                files = [("Text document", "*.txt"), ("All files", "*.*")]
                                path = filedialog.asksaveasfilename(title="Save private key", initialfile="Private Key.txt", filetypes=files, defaultextension="*.txt")
                                if path == "":
                                    return
                                with open(path, encoding="utf-8", mode="w") as file:
                                    file.write(self.root.RSAPrivateVar.get())

                            def outputTextCallback(self, *args, **kwargs):
                                if self.root.outputVar.get() == "":
                                    self.outputText.configure(bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, highlightcolor="#cccccc")
                                    self.clearOutputButton.configure(state=DISABLED)
                                    self.copyOutputButton.configure(state=DISABLED)
                                    self.saveOutputButton.configure(state=DISABLED)
                                else:
                                    self.outputText.configure(bg="white", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1, highlightcolor="#7a7a7a")
                                    self.clearOutputButton.configure(state=NORMAL)
                                    self.copyOutputButton.configure(state=NORMAL)
                                    self.saveOutputButton.configure(state=NORMAL)

                            def AESKeyTextCallback(self, *args, **kwargs):
                                if self.root.AESKeyVar.get() == "":
                                    self.AESKeyText.configure(bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, highlightcolor="#cccccc")
                                    self.clearAESKeyButton.configure(state=DISABLED)
                                    self.copyAESKeyButton.configure(state=DISABLED)
                                    self.saveAESKeyButton.configure(state=DISABLED)
                                else:
                                    self.AESKeyText.configure(bg="white", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1, highlightcolor="#7a7a7a")
                                    self.clearAESKeyButton.configure(state=NORMAL)
                                    self.copyAESKeyButton.configure(state=NORMAL)
                                    self.saveAESKeyButton.configure(state=NORMAL)

                            def RSAPublicTextCallback(self, *args, **kwargs):
                                if self.root.RSAPublicVar.get() == "":
                                    self.RSAPublicText.configure(bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, highlightcolor="#cccccc")
                                    self.clearRSAPublicButton.configure(state=DISABLED)
                                    self.copyRSAPublicButton.configure(state=DISABLED)
                                    self.saveRSAPublicButton.configure(state=DISABLED)
                                else:
                                    self.RSAPublicText.configure(bg="white", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1, highlightcolor="#7a7a7a")
                                    self.clearRSAPublicButton.configure(state=NORMAL)
                                    self.copyRSAPublicButton.configure(state=NORMAL)
                                    self.saveRSAPublicButton.configure(state=NORMAL)

                            def RSAPrivateTextCallback(self, *args, **kwargs):
                                if self.root.RSAPrivateVar.get() == "":
                                    self.RSAPrivateText.configure(bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, highlightcolor="#cccccc")
                                    self.clearRSAPrivateButton.configure(state=DISABLED)
                                    self.copyRSAPrivateButton.configure(state=DISABLED)
                                    self.saveRSAPrivateButton.configure(state=DISABLED)
                                else:
                                    self.RSAPrivateText.configure(bg="white", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1, highlightcolor="#7a7a7a")
                                    self.clearRSAPrivateButton.configure(state=NORMAL)
                                    self.copyRSAPrivateButton.configure(state=NORMAL)
                                    self.saveRSAPrivateButton.configure(state=NORMAL)

                        self.outputFrame = outputFrame(self)
                        self.outputFrame.place(x=377, y=4)

                    def changeDataEntryHideChar(self):
                        self.textEntry.configure(show="●" if bool(self.root.textEntryHideCharVar.get()) else "")

                    def changeEnterKeySectionState(self, state = DISABLED):
                        self.algorithmSelect.symmetricEncryption.keyEntry.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.keyEntryHideCharCheck.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.keyClearButton.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.keyPasteButton.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.keyBrowseButton.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.keyEnteredAlgDES.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.keyEnteredAlgAES.configure(state=state)
                        self.limitKeyEntry()

                    def changeGenerateKeySectionState(self, state = NORMAL):
                        self.algorithmSelect.symmetricEncryption.AESAlgorithmCheck.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.DESAlgorithmCheck.configure(state=state)

                    def changeAESState(self, state = NORMAL):
                        self.algorithmSelect.symmetricEncryption.AES128Check.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.AES192Check.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.AES256Check.configure(state=state)
                    
                    def changeDESState(self, state = DISABLED):
                        self.algorithmSelect.symmetricEncryption.DES128Check.configure(state=state)
                        self.algorithmSelect.symmetricEncryption.DES192Check.configure(state=state)

                    def changeAlgorithmSelection(self):
                        self.changeAESState(state = DISABLED if bool(self.master.master.generateAlgorithmSelection.get()) else NORMAL)
                        self.changeDESState(state = NORMAL if bool(self.master.master.generateAlgorithmSelection.get()) else DISABLED)

                    def changeSourceSelection(self):
                        self.changeGenerateKeySectionState(state = DISABLED if bool(self.master.master.keySourceSelection.get()) else NORMAL)
                        self.changeAESState(state = DISABLED if bool(self.root.keySourceSelection.get()) else DISABLED if bool(self.master.master.generateAlgorithmSelection.get()) else NORMAL)
                        self.changeDESState(state = DISABLED if bool(self.root.keySourceSelection.get()) else NORMAL if bool(self.master.master.generateAlgorithmSelection.get()) else DISABLED)
                        self.changeEnterKeySectionState(state = NORMAL if bool(self.master.master.keySourceSelection.get()) else DISABLED)

                        if not bool(self.root.keySourceSelection.get()) and (not bool(self.root.dataSourceVar.get() or (bool(self.root.dataSourceVar.get() and ''.join(self.root.fileEntryVar.get().split()) != '')))):
                            self.encryptButton.configure(state=NORMAL)
                        elif bool(self.root.keySourceSelection.get()) and (not bool(self.root.dataSourceVar.get() or (bool(self.root.dataSourceVar.get() and ''.join(self.root.fileEntryVar.get().split()) != '')))):
                            self.encryptButton.configure(state=NORMAL)
                            self.limitKeyEntry()

                        if not bool(self.master.master.keySourceSelection.get()):
                            self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel.configure(foreground="gray")
                        else:
                            colors = {
                                "Validity: Valid": "green",
                                "Validity: Invalid": "red",
                                "Validity: [Blank]": "gray"
                            }
                            self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel.configure(foreground=colors[" ".join(self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel["text"].split()[:2])])

                    def getKey(self, path: str) -> Optional[str]:
                        if not os.path.getsize(path) in [16, 24, 32, 76, 88, 96]:
                            messagebox.showwarning("ERR_INVALID_KEY_FILE","The specified file does not contain any valid key for encryption.")
                            self.master.master.logger.error("Key file with no valid key inside was specified.")
                            return
                        with open(path, encoding = 'utf-8', mode="r") as file:
                            global index
                            index = file.read()
                        index = str(index)
                        where = -1
                        for _ in range(len(index)):
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
                                        if len(output_key) in [16, 24, 32]:
                                            return output_key
                                    except:
                                        continue
                        with open(path, encoding = 'utf-8', mode="r") as file:
                            if len(file.read()) == 16 or len(file.read()) == 24 or len(file.read()) == 32:
                                return str(file.read())
                            else:
                                return None

                    def getKeyFromFile(self):
                        path = filedialog.askopenfilename(title="Select key file", filetypes=[("Encrypt'n'Decrypt key file", "*.key"), ("Text document", "*.txt"), ("All files", "*.*")])
                        if path == "":
                            return
                        if os.path.splitext(path)[1] != ".txt":
                            key = self.getKey(path)
                            if not key:
                                messagebox.showwarning("ERR_INVALID_KEY_FILE","The specified file does not contain any valid key for encryption.")
                                self.master.master.logger.error("Key file with no valid key inside was specified.")
                                return
                        else:
                            with open(path, encoding="utf-8", mode="r") as file:
                                key = file.read()
                        self.algorithmSelect.symmetricEncryption.keyEntry.replace(key)

                    def limitKeyEntry(self, *args, **kwargs) -> None:
                        global value
                        if len(self.master.master.keyEntryVar.get()) > 32:
                            self.master.master.keyEntryVar.set(self.master.master.keyEntryVar.get()[:32])
                        value = self.master.master.keyEntryVar.get()
                        if ''.join(str(self.master.master.keyEntryVar.get()).split()) == "":
                            self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel.configure(foreground="gray", text="Validity: [Blank]")
                            self.encryptButton.configure(state=DISABLED)
                            self.algorithmSelect.symmetricEncryption.keyClearButton.configure(state=DISABLED)
                        else:
                            self.algorithmSelect.symmetricEncryption.keyClearButton.configure(state=NORMAL)
                            if not bool(self.master.master.keySourceSelection.get()):
                                cond = bool(self.master.master.generateAlgorithmSelection.get())
                            else:
                                cond = bool(self.master.master.entryAlgorithmSelection.get())
                            iv = get_random_bytes(AES.block_size if not cond else DES3.block_size)
                            try:
                                if not cond:
                                    AES.new(bytes(value, 'utf-8'), mode=AES.MODE_OFB, iv=iv)
                                else:
                                    DES3.new(bytes(value, 'utf-8'), mode=DES3.MODE_OFB, iv=iv)
                            except:
                                if not len(value) in [16, 24, 32]:
                                    self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel.configure(foreground="red", text=f"Validity: Invalid Key")
                                else:
                                    self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel.configure(foreground="red", text=f"Validity: Invalid {'AES' if not cond else '3DES'}-{len(value) * 8} Key")
                                if "3DES-256" in self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel["text"]:
                                    self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel.configure(text="Validity: Invalid Key")
                                self.encryptButton.configure(state=DISABLED)
                            else:
                                self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel.configure(foreground="green", text=f"Validity: Valid {'AES' if not cond else '3DES'}-{len(value) * 8} Key")
                                self.encryptButton.configure(state=NORMAL if (not bool(self.root.dataSourceVar.get() or (bool(self.root.dataSourceVar.get() and ''.join(self.root.fileEntryVar.get().split()) != '')))) else DISABLED)

                    def changeDataSource(self):
                        if bool(self.master.master.dataSourceVar.get()):
                            self.writeFileContentCheck.configure(state=NORMAL)
                            self.textEntry.configure(state=DISABLED)
                            self.textEntryHideCharCheck.configure(state=DISABLED)
                            self.textClearButton.configure(state=DISABLED)
                            self.textPasteButton.configure(state=DISABLED)

                            self.fileEntry.configure(state=NORMAL)
                            self.fileBrowseButton.configure(state=NORMAL)
                            if  (not bool(self.root.dataSourceVar.get() or (bool(self.root.dataSourceVar.get() and ''.join(self.root.fileEntryVar.get().split()) != '')))):
                                self.fileClearButton.configure(state=NORMAL)
                                self.encryptButton.configure(state=NORMAL)
                            else:
                                self.fileClearButton.configure(state=DISABLED)
                                self.encryptButton.configure(state=DISABLED)
                        else:
                            self.writeFileContentCheck.configure(state=DISABLED)
                            self.textEntry.configure(state=NORMAL)
                            if self.master.master.textEntryVar.get() != "":
                                self.textClearButton.configure(state=NORMAL)
                            else:
                                self.textClearButton.configure(state=DISABLED)
                            self.textEntryHideCharCheck.configure(state=NORMAL)
                            self.textPasteButton.configure(state=NORMAL)

                            self.fileEntry.configure(state=DISABLED)
                            self.fileBrowseButton.configure(state=DISABLED)
                            self.fileClearButton.configure(state=DISABLED)
                            self.encryptButton.configure(state=NORMAL)
                            if bool(self.master.master.keySourceSelection.get()):
                                self.limitKeyEntry()
                        if not bool(self.master.master.dataSourceVar.get()):
                            not self.fileValidityLabel["foreground"] in ["gray", "grey"] and not "[Blank]" in self.fileValidityLabel["text"]
                            if not self.fileValidityLabel["foreground"] in ["gray", "grey"] and not "[Blank]" in self.fileValidityLabel["text"]:
                                self.fileValidityStatusColor = self.fileValidityLabel["foreground"]
                            self.fileValidityLabel.configure(foreground="gray")
                        else:
                            try:
                                self.fileValidityLabel.configure(foreground=self.fileValidityStatusColor)
                            except AttributeError:
                                self.fileValidityLabel.configure(foreground="gray")

                    def fileEntryBrowse(self):
                        files = [("All files", "*.*")]
                        filePath = filedialog.askopenfilename(title = "Open a file to encrypt", filetypes=files)

                        filePath != "" and self.fileEntry.replace(filePath)

                    def textEntryCallback(self, *args, **kwargs):
                        self.textClearButton.configure(state=DISABLED if self.master.master.textEntryVar.get() == "" else NORMAL)
                    
                    def fileEntryCallback(self, *args, **kwargs):
                        self.fileClearButton.configure(state=DISABLED if self.master.master.fileEntryVar.get() == "" else NORMAL)
                        self.encryptButton.configure(state=DISABLED if self.master.master.fileEntryVar.get() == "" else NORMAL if (not bool(self.root.dataSourceVar.get() or (bool(self.root.dataSourceVar.get() and ''.join(self.root.fileEntryVar.get().split()) != '')))) else DISABLED)
                        if self.fileEntry.get() != "":
                            if os.path.isfile(self.fileEntry.get()):
                                try:
                                    if os.path.getsize(self.fileEntry.get()) < 104857600:
                                        with open(self.fileEntry.get(), mode="rb") as file:
                                            content = file.read()
                                    else:
                                        self.fileValidityLabel.configure(text="Validity: Encryptable", foreground="green")
                                except OSError:
                                    self.fileValidityLabel.configure(text="Validity: Read access was denied", foreground="red")
                                else:
                                    try:
                                        with open(self.fileEntry.get(), mode="wb") as file:
                                            file.write(content)
                                    except OSError:
                                        self.fileValidityLabel.configure(text="Validity: Encryptable but not writable", foreground="#c6832a")
                                    else:
                                        self.fileValidityLabel.configure(text="Validity: Encryptable", foreground="green")
                            else:
                                self.fileValidityLabel.configure(text="Validity: Not a file", foreground="red")
                        else:
                            self.fileValidityLabel.configure(text="Validity: [Blank]", foreground="gray")

                    def saveKey(self, path: str, key: Union[str, bytes]):
                        key_to_use = self.master.master.crypto.generate_key(32)

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
                                self.root.logger.debug("Encryption key has been saved to \"{}\"".format(path))

                class decryptionFrame(Frame):
                    def __init__(self, master: Notebook = None, **kwargs):
                        super().__init__(master=master, **kwargs)

                        self.textDecryptRadio = Radiobutton(self, text = "Encrypted text:", value=0, variable=self.master.master.decryptSourceVar, command=self.changeDecryptSource, takefocus=0)
                        self.textDecryptValidityLabel = Label(self, text="Validity: [Blank]", foreground="gray")
                        self.textDecryptEntry = ScrolledText(self, width=105, height=5, font=("Consolas", 9), textvariable=self.master.master.textDecryptVar, bg="white", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1)
                        self.textDecryptPasteButton = Button(self, width=15, text="Paste", command=lambda: self.textDecryptEntry.replace(self.master.master.clipboard_get()), takefocus=0)
                        self.textDecryptClearButton = Button(self, width=15, text="Clear", command=lambda: self.textDecryptEntry.delete("1.0", END), takefocus=0, state=DISABLED)

                        self.fileDecryptRadio = Radiobutton(self, text = "Encrypted file:", value=1, variable=self.master.master.decryptSourceVar, command=self.changeDecryptSource, takefocus=0)
                        self.fileDecryptEntry = Entry(self, width=107, font=("Consolas", 9), textvariable=self.master.master.fileDecryptVar, state=DISABLED, takefocus=0)
                        self.fileDecryptBrowseButton = Button(self, width=15, text="Browse...", state=DISABLED, command=self.decryptBrowseFile, takefocus=0)
                        self.fileDecryptClearButton = Button(self, width=15, text="Clear", state=DISABLED, command=lambda: self.fileDecryptEntry.delete(0, END), takefocus=0)

                        self.decryptNotebook = Notebook(self, height=160, width=765, takefocus=0)
                        self.symmetricDecryption = Frame(self.decryptNotebook, takefocus=0)
                        self.asymmetricEncryption = Frame(self.decryptNotebook, takefocus=0)
                        self.decryptNotebook.add(self.symmetricDecryption, text="Symmetric Key Decryption")
                        self.decryptNotebook.add(self.asymmetricEncryption, text="Asymmetric Key Decryption", state=DISABLED)
                        self.decryptAlgorithmFrame = LabelFrame(self.symmetricDecryption, text="Select algorithm", height=63, width=749, takefocus=0)
                        self.decryptAESCheck = Radiobutton(self.decryptAlgorithmFrame, text="AES (Advanced Encryption Standard)", value=0, variable=self.master.master.decryptAlgorithmVar, takefocus=0)
                        self.decryptDESCheck = Radiobutton(self.decryptAlgorithmFrame, text="3DES (Triple Data Encryption Standard)", value=1, variable=self.master.master.decryptAlgorithmVar, takefocus=0)
                        self.decryptKeyFrame = LabelFrame(self.symmetricDecryption, text="Enter encryption key", height=84, width=749, takefocus=0)
                        self.decryptKeyValidity = Label(self.symmetricDecryption, text="Validity: [Blank]", foreground="gray")
                        self.decryptKeyEntry = Entry(self.decryptKeyFrame, width=103, font=("Consolas", 9), textvariable=self.master.master.decryptKeyVar, takefocus=0)
                        self.decryptKeyBrowseButton = Button(self.decryptKeyFrame, width=21, text="Browse key file...", takefocus=0)
                        self.decryptKeyPasteButton = Button(self.decryptKeyFrame, width=15, text="Paste", takefocus=0, command=lambda: self.decryptKeyEntry.replace(self.master.master.clipboard_get()))
                        self.decryptKeyClearButton = Button(self.decryptKeyFrame, width=15, text="Clear", takefocus=0, command=lambda: self.decryptKeyEntry.delete(0, END), state=DISABLED)

                        self.decryptButton = Button(self, width=22, text="Decrypt", command=self.master.master.crypto.decrypt, takefocus=0, state=DISABLED)
                        self.decryptOutputFrame = LabelFrame(self, text="Decrypted text", height=84, width=766, takefocus=0)
                        self.decryptOutputText = Text(self.decryptOutputFrame, width=105, height=1, font=("Consolas", 9), state=DISABLED, bg="#F0F0F0", relief=FLAT, highlightbackground="#cccccc", highlightthickness=1, takefocus=0, textvariable=self.master.master.decryptOutputVar, highlightcolor="#cccccc")
                        self.decryptCopyButton = Button(self.decryptOutputFrame, text="Copy", width=17, takefocus=0, state=DISABLED)
                        self.decryptClearButton = Button(self.decryptOutputFrame, text="Clear", width=17, takefocus=0, state=DISABLED)
                        self.decryptSaveButton = Button(self.decryptOutputFrame, text="Save as...", width=20, takefocus=0, state=DISABLED)

                        self.master.master.textDecryptVar.trace("w", self.textDecryptCallback)
                        self.master.master.fileDecryptVar.trace("w", self.fileDecryptCallback)
                        self.master.master.decryptKeyVar.trace("w", self.decryptLimitKeyEntry)
                        self.master.master.decryptOutputVar.trace("w", self.decryptOutputCallback)

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

                    def changeDecryptSource(self):
                        if not bool(self.master.master.decryptSourceVar.get()):
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
                            self.textDecryptEntry.configure(state=DISABLED, bg="#F0F0F0", foreground="gray", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, highlightcolor="#cccccc")
                            self.textDecryptPasteButton.configure(state=DISABLED)
                            self.textDecryptClearButton.configure(state=DISABLED)
                            self.fileDecryptEntry.configure(state=NORMAL)
                            self.fileDecryptBrowseButton.configure(state=NORMAL)
                            self.fileDecryptClearButton.configure(state=NORMAL)
                            if os.path.isfile(self.fileDecryptEntry.get()):
                                self.decryptButton.configure(state=NORMAL)
                            else:
                                self.decryptButton.configure(state=DISABLED)

                    def textDecryptCallback(self, *args, **kwargs):
                        if not ''.join(str(self.textDecryptEntry.get("1.0", END)).split()) == "":
                            try:
                                if base64.urlsafe_b64encode(base64.urlsafe_b64decode(self.textDecryptEntry.get("1.0", END).encode("utf-8"))) == self.textDecryptEntry.get("1.0", END).rstrip().encode("utf-8"):
                                    self.textDecryptValidityLabel.configure(text="Validity: Valid base64 encoded data", foreground="green")
                                    self.decryptButton.configure(state=NORMAL)
                                    self.decryptLimitKeyEntry()
                                else:
                                    self.textDecryptValidityLabel.configure(text="Validity: Invalid base64 encoded data", foreground="red")
                                    self.decryptButton.configure(state=DISABLED)
                            except binascii.Error:
                                self.textDecryptValidityLabel.configure(text="Validity: Invalid base64 encoded data", foreground="red")
                                self.decryptButton.configure(state=DISABLED)
                        else:
                            self.textDecryptValidityLabel.configure(text="Validity: [Blank]", foreground="gray")
                            self.decryptButton.configure(state=DISABLED)

                    def fileDecryptCallback(self, *args, **kwargs):
                        if not ''.join(str(self.fileDecryptEntry.get()).split()) == "":
                            if os.path.isfile(self.fileDecryptEntry.get()):
                                self.decryptButton.configure(state=NORMAL)
                                self.decryptLimitKeyEntry()
                            else:
                                self.decryptButton.configure(state=DISABLED)
                        else:
                            self.decryptButton.configure(state=DISABLED)

                    def decryptLimitKeyEntry(self, *args, **kwargs):
                        global value
                        if len(self.master.master.decryptKeyVar.get()) > 32:
                            self.master.master.decryptKeyVar.set(self.master.master.decryptKeyVar.get()[:32])
                        value = self.master.master.decryptKeyVar.get()
                        if ''.join(str(self.master.master.decryptKeyVar.get()).split()) == "":
                            self.decryptKeyClearButton.configure(state=DISABLED)
                        else:
                            self.decryptKeyClearButton.configure(state=NORMAL)
                        if len(value) == 0:
                            self.decryptButton.configure(state=DISABLED)
                        else:
                            cond = bool(self.master.master.decryptAlgorithmVar.get())
                            iv = get_random_bytes(AES.block_size if not cond else DES3.block_size)
                            try:
                                if not cond:
                                    AES.new(bytes(value, 'utf-8'), mode=AES.MODE_OFB, iv=iv)
                                else:
                                    DES3.new(bytes(value, 'utf-8'), mode=DES3.MODE_OFB, iv=iv)
                            except:
                                self.decryptButton.configure(state=DISABLED)
                            else:
                                if not bool(self.master.master.decryptSourceVar.get()):
                                    if ''.join(self.textDecryptEntry.get("1.0", END).split()) != "" and base64.urlsafe_b64encode(base64.urlsafe_b64decode(self.textDecryptEntry.get("1.0", END).encode("utf-8"))) == self.textDecryptEntry.get("1.0", END).rstrip().encode("utf-8"):
                                        self.decryptButton.configure(state=NORMAL)
                                    else:
                                        self.decryptButton.configure(state=DISABLED)
                                else:
                                    if os.path.isfile(self.fileDecryptEntry.get()):
                                        self.decryptButton.configure(state=NORMAL)
                                    else:
                                        self.decryptButton.configure(state=DISABLED)
                    
                    def decryptBrowseFile(self):
                        files = [("All files","*.*")]
                        filePath = filedialog.askopenfilename(title = "Open a file to decrypt", filetypes=files)
                        if filePath != "":
                            self.fileDecryptEntry.replace(filePath)

                    def decryptOutputCallback(self, *args, **kwargs):
                        if not ''.join(str(self.master.master.decryptOutputVar.get()).split()) == "":
                            self.decryptClearButton.configure(state=NORMAL)
                            self.decryptCopyButton.configure(state=NORMAL)
                            self.decryptSaveButton.configure(state=NORMAL)
                        else:
                            self.decryptClearButton.configure(state=DISABLED)
                            self.decryptCopyButton.configure(state=DISABLED)
                            self.decryptSaveButton.configure(state=DISABLED)

                class miscFrame(Frame):
                    def __init__(self, master: mainNotebook = None):
                        super().__init__(master=master)

                        class base64Frame(LabelFrame):
                            def __init__(self, master: Frame = None):
                                super().__init__(master=master, height=342, width=405, text="Base64 Encoder & Decoder")
                                self.root = self.master.master.master

                                self.base64InputLabel = Label(self, text="Input", takefocus=0)
                                self.base64InputValidity = Label(self, text="Validity: [Blank]", foreground="gray")
                                self.base64InputText = ScrolledText(self, height=4, width=45, textvariable=self.root.base64InputVar, bg="white", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1)
                                self.inputClearButton = Button(self, width=15, text="Clear", command=self.base64InputText.clear, state=DISABLED, takefocus=0)
                                self.inputPasteButton = Button(self, width=15, text="Paste", command=lambda: self.base64InputText.replace(self.root.clipboard_get()), takefocus=0)
                                self.inputBrowseButton = Button(self, width=17, text="Browse...", command=self.browseBase64InputFile, takefocus=0)

                                class encodeOrDecodeFrame(LabelFrame):
                                    def __init__(self, master: LabelFrame = None):
                                        super().__init__(master=master, height=65, width=382, text="Encode/decode")
                                        self.root = self.master.master.master.master

                                        self.encodeRadiobutton = Radiobutton(self, text="Encode", value=0, variable=self.root.encodeOrDecodeVar, command=self.master.base64InputCallback, takefocus=0)
                                        self.decodeRadiobutton = Radiobutton(self, text="Decode", value=1, variable=self.root.encodeOrDecodeVar, command=self.master.base64InputCallback, takefocus=0)

                                        self.encodeRadiobutton.place(x=10, y=0)
                                        self.decodeRadiobutton.place(x=10, y=21)

                                self.base64OutputLabel = Label(self, text="Output", takefocus=0)
                                self.base64OutputText = ScrolledText(self, height=4, width=45, textvariable=self.root.base64OutputVar, state=DISABLED, bg="white", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1)
                                self.outputClearButton = Button(self, width=15, text="Clear", command=self.base64OutputText.clear, state=DISABLED, takefocus=0)
                                self.outputCopyButton = Button(self, width=15, text="Copy", command=lambda: self.root.clipboard_set(self.base64OutputText.get("1.0", END)[:-1 if self.base64OutputText.get("1.0", END).endswith("\n") else 0]), state=DISABLED, takefocus=0)

                                self.root.base64InputVar.trace("w", self.base64InputCallback)
                                self.root.base64OutputVar.trace("w", self.base64OutputCallback)

                                self.base64InputLabel.place(x=7, y=0)
                                self.base64InputValidity.place(x=42, y=0)
                                self.base64InputText.place(x=10, y=22)
                                self.inputClearButton.place(x=116, y=98)
                                self.inputPasteButton.place(x=9, y=98)
                                self.inputBrowseButton.place(x=281, y=98)

                                self.encodeOrDecodeFrame = encodeOrDecodeFrame(self)
                                self.encodeOrDecodeFrame.place(x=10, y=125)
                                self.base64OutputLabel.place(x=7, y=190)
                                self.base64OutputText.place(x=10, y=212)
                                self.outputClearButton.place(x=116, y=288)
                                self.outputCopyButton.place(x=9, y=288)

                            def browseBase64InputFile(self):
                                filePath = filedialog.askopenfilename(title=f"Open a file to {'encode' if not bool(self.root.encodeOrDecodeVar.get()) else 'decode'}", filetypes=[("All files", "*.*")])
                                if ''.join(filePath.split()) != '':
                                    try:
                                        with open(filePath, mode="rb") as file:
                                            index = file.read()
                                    except PermissionError:
                                        messagebox.showerror("Permission denied", "Access to the file you've specified has been denied. Try running the program as administrator and make sure read & write access for the file is permitted.")
                                        self.root.logger.error("Read permission for the file specified has been denied, base64 encoding was interrupted.")
                                        return
                                    try:
                                        index = index.decode("utf-8")
                                    except UnicodeDecodeError:
                                        self.base64InputText.configure(foreground="gray", wrap=WORD)
                                        self.base64InputText.replace("File content is not being displayed because it's in an unknown encoding.")
                                    else:
                                        if len(index) > 15000:
                                            self.base64InputText.configure(foreground="gray", wrap=WORD)
                                            self.base64InputText.replace("File content is not being displayed because it's longer than 15.000 characters.")
                                        else:
                                            self.base64InputText.configure(foreground="black")
                                            self.base64InputText.replace(index)
                                    finally:
                                        self.index = index

                            def base64InputCallback(self, *args, **kwargs):
                                if ''.join(self.base64InputText.get("1.0", END).split()) != "":
                                    self.inputClearButton.configure(state=NORMAL)
                                else:
                                    self.inputClearButton.configure(state=DISABLED)
                                index = self.index
                                if not bool(self.root.encodeOrDecodeVar.get()) and ''.join(self.base64InputText.get("1.0", END).split()) != "":
                                    self.base64InputValidity.configure(text="Validity: Encodable", foreground="green")
                                    self.base64OutputText.replace(base64.urlsafe_b64encode(self.base64InputText.get("1.0", END).encode("utf-8")).decode("utf-8"))
                                    self.base64OutputText.configure(foreground="black")
                                elif bool(self.root.encodeOrDecodeVar.get()) and ''.join(self.base64InputText.get("1.0", END).split()) != "":
                                    try:
                                        if base64.urlsafe_b64encode(base64.urlsafe_b64decode(self.base64InputText.get("1.0", END).encode("utf-8")).decode("utf-8").encode("utf-8")) == self.base64InputText.get("1.0", END).rstrip().encode("utf-8"):
                                            self.base64InputValidity.configure(text="Validity: Valid base64 encoded data", foreground="green")
                                            self.base64OutputText.replace(base64.urlsafe_b64decode(self.base64InputText.get("1.0", END).encode("utf-8")).decode("utf-8"))
                                            self.base64OutputText.configure(foreground="black")
                                        else:
                                            self.base64InputValidity.configure(text="Validity: Invalid", foreground="red")
                                            self.base64OutputText.configure(foreground="gray")
                                    except binascii.Error as ExceptionDetails:
                                        self.base64InputValidity.configure(text=f"Validity: {'Incorrect padding' if 'padding' in str(ExceptionDetails) else 'Invalid'}", foreground="red")
                                        self.base64OutputText.configure(foreground="gray")
                                    except UnicodeDecodeError:
                                        self.base64InputValidity.configure(text="Validity: Unknown encoding", foreground="red")
                                        self.base64OutputText.configure(foreground="gray")
                                else:
                                    self.base64InputValidity.configure(text="Validity: [Blank]", foreground="gray")
                                    self.base64OutputText.clear()

                            def base64OutputCallback(self, *args, **kwargs):
                                if ''.join(self.base64OutputText.get("1.0", END).split()) != "":
                                    self.outputClearButton.configure(state=NORMAL)
                                    self.outputCopyButton.configure(state=NORMAL)
                                else:
                                    self.outputClearButton.configure(state=DISABLED)
                                    self.outputCopyButton.configure(state=DISABLED)

                        class keyDerivationFrame(LabelFrame):
                            def __init__(self, master: miscFrame):
                                super().__init__(master=master, height=150, width=354, text="Key Derivation Function (KDF)")
                                self.root = self.master.master.master

                                self.keyInputLabel = Label(self, text="Input", takefocus=0)
                                self.keyInputValidity = Label(self, text="Validity: [Blank]", foreground="gray")
                                self.keyInputEntry = Entry(self, width=46, font=("Consolas", 10), textvariable=self.root.keyInputVar, takefocus=0)
                                self.keyInputHideCheck = Checkbutton(self, text="Hide characters", takefocus=0, onvalue=1, offvalue=0, variable=self.root.keyInputHideVar, command=lambda: self.keyInputEntry.configure(show="●" if bool(self.root.keyInputHideVar.get()) else ""))
                                self.inputClearButton = Button(self, width=15, text="Clear", command=self.keyInputEntry.clear, state=DISABLED, takefocus=0)
                                self.inputPasteButton = Button(self, width=15, text="Paste", command=lambda: self.keyInputEntry.replace(self.root.clipboard_get()), takefocus=0)

                                self.keyOutputLabel = Label(self, text="Output (Derived Key)", takefocus=0)
                                self.keyOutputEntry = Entry(self, width=34, state="readonly", font=("Consolas", 10), textvariable=self.root.keyOutputVar, takefocus=0)
                                self.outputCopyButton = Button(self, text="Copy", state=DISABLED, command=lambda: self.root.clipboard_set(self.keyOutputEntry.get()[:-1 if self.keyOutputEntry.get().endswith("\n") else 0]), takefocus=0)

                                self.root.keyInputVar.trace("w", self.keyInputCallback)
                                self.root.keyOutputVar.trace("w", lambda *args, **kwargs: self.outputCopyButton.configure(state=NORMAL if ''.join(self.keyOutputEntry.get().split()) != '' else DISABLED))

                                self.keyInputLabel.place(x=8, y=0)
                                self.keyInputValidity.place(x=43, y=0)
                                self.keyInputHideCheck.place(x=236, y=49)
                                self.keyInputEntry.place(x=10, y=22)
                                self.inputClearButton.place(x=117, y=48)
                                self.inputPasteButton.place(x=10, y=48)

                                self.keyOutputLabel.place(x=8, y=75)
                                self.keyOutputEntry.place(x=10, y=97)
                                self.outputCopyButton.place(x=262, y=95)

                            def keyInputCallback(self, *args, **kwargs):
                                if ''.join(self.keyInputEntry.get().split()) != "":
                                    self.inputClearButton.configure(state=NORMAL)
                                    try:
                                        salt = get_random_bytes(16)
                                        result = base64.urlsafe_b64encode(scrypt(self.keyInputEntry.get(), salt, 24, N=2**14, r=8, p=1)).decode("utf-8")
                                    except:
                                        self.keyInputValidity.configure(text="Validity: Underivative", foreground="red")
                                        self.keyOutputEntry.configure(foreground="gray")
                                    else:
                                        self.keyInputValidity.configure(text="Validity: Derivative", foreground="green")
                                        self.keyOutputEntry.replace(result)
                                        self.keyOutputEntry.configure(foreground="black")
                                else:
                                    self.inputClearButton.configure(state=DISABLED)
                                    self.keyOutputEntry.clear()
                                    self.keyInputValidity.configure(text="Validity: [Blank]", foreground="gray")

                        class hashDigestFrame(LabelFrame):
                            def __init__(self, master: miscFrame):
                                super().__init__(master, height=363, width=354, text="Hash Calculator")
                                self.root = self.master.master.master
                                self.__last_file: dict = {"path": None, "size": None}

                                self.plainRadiobutton = Radiobutton(self, text="Plain text:", value=0, variable=self.root.hashCalculationSourceVar, command=self.changeSourceSelection, takefocus=0)
                                self.plainEntry = Entry(self, width=44, font=("Consolas", 10), textvariable=self.root.hashPasswordEntryVar, takefocus=0)
                                self.plainClearButton = Button(self, width=15, text="Clear", command=self.plainEntry.clear, state=DISABLED, takefocus=0)
                                self.plainPasteButton = Button(self, width=15, text="Paste", command=lambda: self.plainEntry.replace(self.root.clipboard_get()), takefocus=0)

                                self.fileRadiobutton = Radiobutton(self, text="File:", value=1, variable=self.root.hashCalculationSourceVar, command=self.changeSourceSelection, takefocus=0)
                                self.fileValidity = Label(self, text="Validity: [Blank]", foreground="gray", state=DISABLED)
                                self.fileEntry = Entry(self, width=44, font=("Consolas", 10), textvariable=self.root.hashFileEntryVar, takefocus=0, state=DISABLED)
                                self.fileClearButton = Button(self, width=15, text="Clear", command=self.plainEntry.clear, takefocus=0, state=DISABLED)
                                self.fileBrowseButton = Button(self, width=15, text="Browse...", command=self.browseFile, takefocus=0, state=DISABLED)

                                self.SHA1Label = Label(self, text="SHA-1")
                                self.SHA1Entry = Entry(self, width=34, font=("Consolas", 10), state="readonly", takefocus=0)
                                self.SHA1CopyButton = Button(self, text="Copy", state=DISABLED, takefocus=0)
                                self.SHA256Label = Label(self, text="SHA-256")
                                self.SHA256Entry = Entry(self, width=34, font=("Consolas", 10), state="readonly", takefocus=0)
                                self.SHA256CopyButton = Button(self, text="Copy", state=DISABLED, takefocus=0)
                                self.SHA512Label = Label(self, text="SHA-512")
                                self.SHA512Entry = Entry(self, width=34, font=("Consolas", 10), state="readonly", takefocus=0)
                                self.SHA512CopyButton = Button(self, text="Copy", state=DISABLED, takefocus=0)
                                self.MD5Label = Label(self, text="MD-5")
                                self.MD5Entry = Entry(self, width=34, font=("Consolas", 10), state="readonly", takefocus=0)
                                self.MD5CopyButton = Button(self, text="Copy", state=DISABLED, takefocus=0)

                                self.root.hashPasswordEntryVar.trace("w", self.hashPasswordEntryCallback)
                                self.root.hashFileEntryVar.trace("w", self.hashFileEntryCallback)

                                self.plainRadiobutton.place(x=7, y=0)
                                self.plainEntry.place(x=22, y=22)
                                self.plainClearButton.place(x=129, y=48)
                                self.plainPasteButton.place(x=22, y=48)

                                self.fileRadiobutton.place(x=8, y=76)
                                self.fileValidity.place(x=52, y=77)
                                self.fileEntry.place(x=23, y=99)
                                self.fileClearButton.place(x=130, y=125)
                                self.fileBrowseButton.place(x=23, y=125)

                                self.SHA1Label.place(x=8, y=155)
                                self.SHA1Entry.place(x=10, y=176)
                                self.SHA1CopyButton.place(x=262, y=174)
                                self.SHA256Label.place(x=8, y=200)
                                self.SHA256Entry.place(x=10, y=221)
                                self.SHA256CopyButton.place(x=262, y=219)
                                self.SHA512Label.place(x=8, y=245)
                                self.SHA512Entry.place(x=10, y=266)
                                self.SHA512CopyButton.place(x=262, y=264)
                                self.MD5Label.place(x=8, y=290)
                                self.MD5Entry.place(x=10, y=311)
                                self.MD5CopyButton.place(x=262, y=309)

                            def changeSourceSelection(self):
                                if bool(self.root.hashCalculationSourceVar.get()):
                                    self.fileValidity.configure(state=NORMAL)
                                    self.fileEntry.configure(state=NORMAL)
                                    if ''.join(self.fileEntry.get()) != '':
                                        self.fileClearButton.configure(state=NORMAL)
                                        if os.path.isfile(self.fileEntry.get()):
                                            self.hash(self.fileEntry.get())
                                            self.SHA1Entry.configure(foreground="black")
                                            self.SHA256Entry.configure(foreground="black")
                                            self.SHA512Entry.configure(foreground="black")
                                            self.MD5Entry.configure(foreground="black")
                                        else:
                                            self.SHA1Entry.configure(foreground="gray")
                                            self.SHA256Entry.configure(foreground="gray")
                                            self.SHA512Entry.configure(foreground="gray")
                                            self.MD5Entry.configure(foreground="gray")
                                    else:
                                        self.fileClearButton.configure(state=DISABLED)
                                        self.plainClearButton.configure(state=DISABLED)
                                        self.SHA1Entry.configure(foreground="gray")
                                        self.SHA256Entry.configure(foreground="gray")
                                        self.SHA512Entry.configure(foreground="gray")
                                        self.MD5Entry.configure(foreground="gray")
                                    self.fileBrowseButton.configure(state=NORMAL)

                                    self.plainEntry.configure(state=DISABLED)
                                    self.plainClearButton.configure(state=DISABLED)
                                    self.plainPasteButton.configure(state=DISABLED)
                                else:
                                    self.fileValidity.configure(state=DISABLED)
                                    self.fileEntry.configure(state=DISABLED)
                                    self.fileClearButton.configure(state=DISABLED)
                                    self.fileBrowseButton.configure(state=DISABLED)

                                    self.plainEntry.configure(state=NORMAL)
                                    if ''.join(self.plainEntry.get()) != '':
                                        self.plainClearButton.configure(state=NORMAL)
                                        self.SHA1Entry.configure(foreground="black")
                                        self.SHA256Entry.configure(foreground="black")
                                        self.SHA512Entry.configure(foreground="black")
                                        self.MD5Entry.configure(foreground="black")
                                        self.hash(bytes(self.plainEntry.get(), "utf-8"))
                                    else:
                                        self.plainClearButton.configure(state=DISABLED)
                                        self.SHA1Entry.configure(foreground="gray")
                                        self.SHA256Entry.configure(foreground="gray")
                                        self.SHA512Entry.configure(foreground="gray")
                                        self.MD5Entry.configure(foreground="gray")
                                    self.plainPasteButton.configure(state=NORMAL)

                            @threaded
                            def hash(self, index: Union[str, bytes], force: bool = False):
                                if not force and isinstance(index, str) and self.__last_file["path"] == self.fileEntry.get() and self.__last_file["size"] == os.path.getsize(self.fileEntry.get()):
                                    return
                                self.SHA1Entry.configure(foreground="gray")
                                self.SHA256Entry.configure(foreground="gray")
                                self.SHA512Entry.configure(foreground="gray")
                                self.MD5Entry.configure(foreground="gray")

                                self.plainEntry.configure(state=DISABLED)
                                self.plainPasteButton.configure(state=DISABLED)
                                self.plainClearButton.configure(state=DISABLED)
                                self.plainRadiobutton.configure(state=DISABLED)
                                self.fileEntry.configure(state=DISABLED)
                                self.fileBrowseButton.configure(state=DISABLED)
                                self.fileClearButton.configure(state=DISABLED)
                                self.fileRadiobutton.configure(state=DISABLED)

                                if isinstance(index, str):
                                    self.root.statusBar.configure(text="Status: Reading the file...")
                                    self.root.update()
                                    try:
                                        with open(index, mode="rb") as file:
                                            index = file.read()
                                    except (OSError, PermissionError):
                                        messagebox.showerror("Permission denied", "Access to the file you've specified has been denied. Try running the program as administrator and make sure read & write access for the file is permitted.")
                                        self.root.logger.error("Read permission for the file specified has been denied, hash calculation was interrupted.")
                                        self.root.statusBar.configure(text="Status: Ready")
                                        self.root.update()
                                        return
                                    else:
                                        self.__last_file["path"] = self.fileEntry.get()
                                        self.__last_file["size"] = os.path.getsize(self.fileEntry.get())
                                self.root.statusBar.configure(text="Status: Calculating SHA-1 hash...")
                                self.root.update()
                                hasher = SHA1.new()
                                hasher.update(index)
                                self.SHA1Entry.replace(hasher.hexdigest())
                                self.SHA1Entry.configure(foreground="black")
                                self.SHA1CopyButton.configure(state=NORMAL)
                                self.root.statusBar.configure(text="Status: Calculating SHA-256 hash...")
                                self.root.update()
                                hasher = SHA256.new()
                                hasher.update(index)
                                self.SHA256Entry.replace(hasher.hexdigest())
                                self.SHA256Entry.configure(foreground="black")
                                self.SHA256CopyButton.configure(state=NORMAL)
                                self.root.statusBar.configure(text="Status: Calculating SHA-512 hash...")
                                self.root.update()
                                hasher = SHA512.new()
                                hasher.update(index)
                                self.SHA512Entry.replace(hasher.hexdigest())
                                self.SHA512Entry.configure(foreground="black")
                                self.SHA512CopyButton.configure(state=NORMAL)
                                self.root.statusBar.configure(text="Status: Calculating MD-5 hash...")
                                self.root.update()
                                hasher = MD5.new()
                                hasher.update(index)
                                self.MD5Entry.replace(hasher.hexdigest())
                                self.MD5Entry.configure(foreground="black")
                                self.MD5CopyButton.configure(state=NORMAL)
                                self.root.statusBar.configure(text="Status: Ready")
                                self.root.update()
                                
                                self.fileRadiobutton.configure(state=NORMAL)
                                self.plainRadiobutton.configure(state=NORMAL)
                                if not bool(self.root.hashCalculationSourceVar.get()):
                                    self.plainEntry.configure(state=NORMAL)
                                    self.plainPasteButton.configure(state=NORMAL)
                                    self.plainClearButton.configure(state=NORMAL)
                                else:
                                    self.fileEntry.configure(state=NORMAL)
                                    self.fileBrowseButton.configure(state=NORMAL)
                                    self.fileClearButton.configure(state=NORMAL)

                            def browseFile(self):
                                filePath = filedialog.askopenfilename(title=f"Open a file to check its hash", filetypes=[("All files", "*.*")])
                                if ''.join(filePath.split()) != '':
                                    self.fileEntry.replace(filePath)

                            def hashPasswordEntryCallback(self, *args, **kwargs):
                                if ''.join(self.plainEntry.get().split()) == '':
                                    self.SHA1Entry.clear()
                                    self.SHA256Entry.clear()
                                    self.SHA512Entry.clear()
                                    self.MD5Entry.clear()
                                    self.SHA1CopyButton.configure(state=DISABLED)
                                    self.SHA256CopyButton.configure(state=DISABLED)
                                    self.SHA512CopyButton.configure(state=DISABLED)
                                    self.MD5CopyButton.configure(state=DISABLED)
                                    return
                                index = bytes(self.plainEntry.get(), "utf-8")
                                self.SHA1Entry.configure(foreground="black")
                                self.SHA256Entry.configure(foreground="black")
                                self.SHA512Entry.configure(foreground="black")
                                self.MD5Entry.configure(foreground="black")
                                self.hash(index)

                            def hashFileEntryCallback(self, *args, **kwargs):
                                def grayoutEntries():
                                    self.SHA1Entry.configure(foreground="gray")
                                    self.SHA256Entry.configure(foreground="gray")
                                    self.SHA512Entry.configure(foreground="gray")
                                    self.MD5Entry.configure(foreground="gray")
                                def degrayEntries():
                                    self.SHA1Entry.configure(foreground="black")
                                    self.SHA256Entry.configure(foreground="black")
                                    self.SHA512Entry.configure(foreground="black")
                                    self.MD5Entry.configure(foreground="black")
                                if ''.join(self.fileEntry.get().split()) != '':
                                    self.fileClearButton.configure(state=NORMAL)
                                    if os.path.isfile(self.fileEntry.get()):
                                        try:
                                            self.fileValidity.configure(text="Validity: Hashable", foreground="green")
                                            degrayEntries()
                                            self.hash(self.fileEntry.get())
                                            return
                                        except (OSError, PermissionError):
                                            self.fileValidity.configure(text="Validity: Read access was denied", foreground="red")
                                            grayoutEntries()
                                            return
                                        except Exception:
                                            self.fileValidity.configure(text="Validity: Not hashable", foreground="red")
                                            grayoutEntries()
                                            return
                                    else:
                                        self.fileValidity.configure(text="Validity: Not a file", foreground="red")
                                        grayoutEntries()
                                else:
                                    self.fileClearButton.configure(state=DISABLED)
                                    self.fileValidity.configure(text="Validity: [Blank]", foreground="gray")
                                    grayoutEntries()

                        self.base64Frame = base64Frame(self)
                        self.keyDerivationFrame = keyDerivationFrame(self)
                        self.hashDigestFrame = hashDigestFrame(self)

                        self.base64Frame.place(x=10, y=5)
                        self.keyDerivationFrame.place(x=423, y=5)
                        self.hashDigestFrame.place(x=423, y=158)

                class loggingFrame(Frame):
                    def __init__(self, master: mainNotebook = None, **kwargs):
                        super().__init__(master=master, **kwargs)
                        self.root: Interface = self.master.master

                        self.loggingWidget = ScrolledText(self, height=33, width=107, font=("Consolas", 9), state=DISABLED, textvariable=self.root.loggingTextVar, bg="white", wrap="none", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1)
                        self.loggingWidget.tag_config("debug", foreground="gray")
                        self.loggingWidget.tag_config("info", foreground="black")
                        self.loggingWidget.tag_config("warning", foreground="orange")
                        self.loggingWidget.tag_config("error", foreground="red")
                        self.loggingWidget.tag_config("critical", foreground="red")

                        self.root.loggingTextVar.trace("w", self.onLoggingWidgetInsert)

                        self.root.logger = Logger(self.loggingWidget, self.root)

                        self.copyButton = Button(self, text="Copy", width=15, command=lambda: self.root.clipboard_set(self.loggingWidget.get("1.0", END)), takefocus=0, state=DISABLED)
                        self.clearButton = Button(self, text="Clear", width=15, command=lambda: self.loggingWidget.clear(), takefocus=0, state=DISABLED)
                        self.showOnlyLabel = Label(self, text="Logging level:")
                        levels = ["NOTSET", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

                        self.loggingLevelSelect = Combobox(self, values=levels, textvariable=self.root.levelSelectVar, state="readonly", takefocus=0)
                        self.loggingLevelSelect.bind("<<ComboboxSelected>>", self.onLoggingLevelChange)
                        self.autoSaveCheck = Checkbutton(self, text="Auto-save", onvalue=1, offvalue=0, variable=self.root.loggingAutoSaveVar, takefocus=0)
                        self.saveAsButton = Button(self, text="Save as...", width=19, takefocus=0)

                        self.loggingWidget.place(x=10, y=10)
                        self.copyButton.place(x=9, y=491)
                        self.clearButton.place(x=119, y=491)
                        self.showOnlyLabel.place(x=229, y=494)
                        self.loggingLevelSelect.place(x=312, y=492)
                        self.autoSaveCheck.place(x=573, y=493)
                        self.saveAsButton.place(x=657, y=491)

                    def onLoggingLevelChange(self, event=None):
                        self.loggingWidget.clear()
                        levels = {"NOTSET": 0, "DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
                        if list(self.root.cache.loggings_history[-1].values())[0]["message"].replace("Logging level has been set to ", "").split()[-1] != self.root.levelSelectVar.get():
                            self.root.logger.debug(f"Logging level has been set to {self.root.levelSelectVar.get()}")
                        for entry in self.root.cache.loggings_history[:-1]:
                            record: logging.LogRecord = list(entry.keys())[0]
                            string: str = list(entry.values())[0]["message"]
                            if record.levelno >= levels[self.root.levelSelectVar.get()]:
                                self.loggingWidget.configure(state=NORMAL)
                                self.loggingWidget.insert(END, string, record.levelname.lower())
                                self.loggingWidget.configure(state=DISABLED)
                            else:
                                continue

                    def onLoggingWidgetInsert(self, *args, **kwargs):
                        if ''.join(self.loggingWidget.get("1.0", END).split()) == '':
                            self.clearButton.configure(state=DISABLED)
                            self.copyButton.configure(state=DISABLED)
                        else:
                            self.clearButton.configure(state=NORMAL)
                            self.copyButton.configure(state=NORMAL)

                class helpFrame(Frame):
                    def __init__(self, master: Notebook, **kwargs):
                        super().__init__(master, **kwargs)

                        self.loadingText = Label(self, text="Loading...")
                        self.loadingText.place(relx=.5, rely=.5, anchor=CENTER)

                self.encryptionFrame = encryptionFrame(self)
                self.decryptionFrame = decryptionFrame(self)
                self.miscFrame = miscFrame(self)
                self.loggingFrame = loggingFrame(self)
                self.helpFrame = helpFrame(self)

                self.add(self.encryptionFrame, text="Encryption")
                self.add(self.decryptionFrame, text="Decryption")
                self.add(self.miscFrame, text="Miscellaneous")
                self.add(self.loggingFrame, text="Logs")
                self.add(self.helpFrame, text="Help & About")

        self.mainNotebook = mainNotebook(self)
        self.mainNotebook.pack(fill=BOTH, expand=1, pady=4, padx=4, side=TOP)

        self.statusBar = TkLabel(self, text="Status: Ready", bd=1, relief=SUNKEN, anchor=W)
        self.statusBar.pack(side=BOTTOM, fill=X)

        self.__initialize_menu()
        self.__initialize_protocols()
        self.__initialize_bindings()
        self.__load_database()

        self.deiconify()

    def __initialize_vars(self):
        self.showTextChar = IntVar(value=0)
        self.showTooltip = IntVar(value=1)
        self.showInfoBox = IntVar(value=1)
        self.showWarnBox = IntVar(value=1)
        self.showErrorBox = IntVar(value=1)
        self.windowAlpha = IntVar(value=1)
        self.updateInterval = IntVar(value=1)
        self.languageVar = IntVar(value=0)
        self.themeVar = StringVar(value="vista")
        self.loggingTextVar = StringVar()
        self.loggingAutoSaveVar = IntVar(value=0)
        self.levelSelectVar = StringVar(value="INFO")

        self.generateRandomAESVar = IntVar(value=256)
        self.generateRandomDESVar = IntVar(value=192)
        self.generateRandomRSAVar = IntVar(value=2048)
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
        self.customRSALengthVar = IntVar()

        self.decryptSourceVar = IntVar(value=0)
        self.decryptAlgorithmVar = IntVar(value=0)
        self.textDecryptVar = StringVar()
        self.fileDecryptVar = StringVar()
        self.decryptKeyVar = StringVar()
        self.decryptOutputVar = StringVar()

        self.encodeOrDecodeVar = IntVar(value=0)
        self.base64InputVar = StringVar()
        self.base64OutputVar = StringVar()
        self.keyInputVar = StringVar()
        self.keyInputHideVar = IntVar(value=0)
        self.keyOutputVar = StringVar()
        self.hashCalculationSourceVar = IntVar(value=0)
        self.hashPasswordEntryVar = StringVar()
        self.hashFileEntryVar = StringVar()

        self.showProgramNameVar = IntVar(value=1)
        self.showProgramVersionVar = IntVar(value=1)
        self.showTimeVar = IntVar(value=0)
        self.showDateVar = IntVar(value=0)
        self.titlebarUpdateInterval = IntVar(value=200)
        self.autoSaveConfigVar = IntVar(value=1)

    def on_close(self):
        self.logger.end_logging_file()
        if not hasattr(self, "success"):
            self.__save_database()
            self.success = True
        try:
            self.destroy()
        except Exception:
            return

    def __initialize_protocols(self):
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def __save_database(self):
        con = sqlite3.connect(f"{os.getenv('APPDATA')}\\Encrypt-n-Decrypt\\settings.sqlite")
        cur = con.cursor()
        operation = "INSERT INTO user_data VALUES ('{key}', '{value}')" if not cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_data'").fetchall() else "UPDATE user_data SET value = '{value}' WHERE key = '{key}'"
        cur.execute("CREATE TABLE IF NOT EXISTS user_data (key, value)")
        for attribute in [a for a in inspect.getmembers(self, lambda a: not(inspect.isroutine(a))) if not(a[0].startswith('__') and a[0].endswith('__'))]:
            name: str = attribute[0]
            value: Union[IntVar, StringVar] = attribute[1]
            if isinstance(value, IntVar) or any(ext in name for ext in ["themeVar", "levelSelectVar"]):
                cur.execute(operation.format(key=name, value=value.get()))
        con.commit()
        con.close()

    def __load_database(self):
        try:
            con = sqlite3.connect(f"{os.getenv('APPDATA')}\\Encrypt-n-Decrypt\\settings.sqlite")
        except sqlite3.OperationalError:
            os.mkdir(f"{os.getenv('APPDATA')}\\Encrypt-n-Decrypt")
            con = sqlite3.connect(f"{os.getenv('APPDATA')}\\Encrypt-n-Decrypt\\settings.sqlite")
        cur = con.cursor()
        if not cur.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'user_data'").fetchall():
            return
        else:
            cur.execute("SELECT * FROM user_data")
            for key, value in cur.fetchall():
                eval(f"self.{key}.set(" + (value if not any(ext in key for ext in ["themeVar", "levelSelectVar"]) else f'\'{value}\'') + ")")

            self.mainNotebook.encryptionFrame.changeAlgorithmSelection()
            self.mainNotebook.encryptionFrame.changeSourceSelection()
            self.mainNotebook.encryptionFrame.changeDataSource()
            self.mainNotebook.encryptionFrame.changeDataEntryHideChar()

            self.mainNotebook.miscFrame.hashDigestFrame.changeSourceSelection()

            self.theme.set_theme(self.themeVar.get())

    def __initialize_bindings(self):
        def encrypt(*args, **kwargs):
            if self.mainNotebook.index(self.mainNotebook.select()) == 0:
                self.crypto.encrypt()
            elif self.mainNotebook.index(self.mainNotebook.select()) == 1:
                self.crypto.decrypt()
            else:
                return
        def give_focus(*args, **kwargs):
            self.after(200, self.encryptionFrame.textEntry.focus_set())

        self.bind("<Return>", encrypt)
        self.bind("<Tab>", give_focus)

        self.bind("<Control_L><Alt_L>t", lambda _: self.theme.set_theme("vista"))
        self.bind("<Control_L>e", lambda _: self.mainNotebook.select(0))
        self.bind("<Control_L>d", lambda _: self.mainNotebook.select(1))
        self.bind("<Control_L>m", lambda _: self.mainNotebook.select(2))
        self.bind("<Control_L>l", lambda _: self.mainNotebook.select(3))
        self.bind("<F1>", lambda _: self.mainNotebook.select(4))

    def __del__(self):
        if not hasattr(self, "success"):
            self.__save_database()
            self.success = True

    def __initialize_menu(self):
        class menuBar(Menu):
            def __init__(self, master: Interface):
                super().__init__(master, tearoff=0)

                class fileMenu(Menu):
                    def __init__(self, master: menuBar):
                        super().__init__(master, tearoff=0)
                        self.add_command(label = "Encryption", command=lambda: self.master.master.mainNotebook.select(0), accelerator="Ctrl+E", underline=0)
                        self.add_command(label = "Decryption", command=lambda: self.master.master.mainNotebook.select(1), accelerator="Ctrl+D", underline=0)
                        self.add_command(label = "Miscellaneous", command=lambda: self.master.master.mainNotebook.select(2), accelerator="Ctrl+M", underline=0)
                        self.add_command(label = "Logs", command=lambda: self.master.master.mainNotebook.select(3), accelerator="Ctrl+L", underline=0)
                        self.add_command(label = "Help & About", command=lambda: self.master.master.mainNotebook.select(4), accelerator="F1", underline=0)
                        self.add_separator()
                        self.add_command(label = "Check for updates", command=lambda: self.master.master.Updates(self.master.master), accelerator="Ctrl+Alt+U", underline=10)
                        self.add_separator()
                        self.add_command(label = "Exit", accelerator="Alt+F4", command=lambda: self.master.destroy())

                class viewMenu(Menu):
                    def __init__(self, master: menuBar):
                        super().__init__(master, tearoff=0)
                        self.root = self.master.master
                        self.add_checkbutton(label = "Show tooltips on hover", accelerator="Ctrl+Alt+T", onvalue=1, offvalue=0, variable=self.root.showTooltip, underline=5)
                        self.add_separator()
                        self.add_checkbutton(label = "Show info message dialogs", accelerator="Ctrl+Alt+I", onvalue=1, offvalue=0, variable=self.root.showInfoBox, underline=5)
                        self.add_checkbutton(label = "Show warning message dialogs", accelerator="Ctrl+Alt+W", onvalue=1, offvalue=0, variable=self.root.showWarnBox, underline=5)
                        self.add_checkbutton(label = "Show error message dialogs", accelerator="Ctrl+Alt+E", onvalue=1, offvalue=0, variable=self.root.showErrorBox, underline=5)
                        self.add_separator()
                        class titleMenu(Menu):
                            def __init__(self, master: viewMenu):
                                super().__init__(master, tearoff=0)
                                self.root = self.master.master.master
                                self.add_checkbutton(label = "Show program name in titlebar", onvalue=1, offvalue=0, variable=self.root.showProgramNameVar)
                                self.add_checkbutton(label = "Show program version in titlebar", onvalue=1, offvalue=0, variable=self.root.showProgramVersionVar)
                                self.add_checkbutton(label = "Show time in titlebar", onvalue=1, offvalue=0, variable=self.root.showTimeVar)
                                self.add_checkbutton(label = "Show date in titlebar", onvalue=1, offvalue=0, variable=self.root.showDateVar)
                                self.add_separator()
                                class speedMenu(Menu):
                                    def __init__(self, master: titleMenu):
                                        super().__init__(master, tearoff=0)
                                        self.root = self.master.master.master.master
                                        self.add_radiobutton(label = "Fast", value=1, variable=self.root.updateInterval)
                                        self.add_radiobutton(label = "Moderate", value=2, variable=self.root.updateInterval)
                                        self.add_radiobutton(label = "Slow", value=3, variable=self.root.updateInterval)
                                        self.add_radiobutton(label = "Paused", value=0, variable=self.root.updateInterval)
                                        self.add_separator()
                                        self.add_command(label = "Update now")
                                self.speedMenu = speedMenu(self)
                                self.add_cascade(menu=self.speedMenu, label="Titlebar update interval")
                        self.titleMenu = titleMenu(self)
                        self.add_cascade(menu=self.titleMenu, label = "Window titlebar configuration")
                        class opacityMenu(Menu):
                            def __init__(self, master: viewMenu):
                                super().__init__(master, tearoff=0)
                                self.add_radiobutton(label = "%20", value=20, variable=self.master.master.master.windowAlpha, command=lambda: self.master.master.master.attributes("-alpha", 20/100))
                                self.add_radiobutton(label = "%40", value=40, variable=self.master.master.master.windowAlpha, command=lambda: self.master.master.master.attributes("-alpha", 40/100))
                                self.add_radiobutton(label = "%60", value=60, variable=self.master.master.master.windowAlpha, command=lambda: self.master.master.master.attributes("-alpha", 60/100))
                                self.add_radiobutton(label = "%80", value=80, variable=self.master.master.master.windowAlpha, command=lambda: self.master.master.master.attributes("-alpha", 80/100))
                                self.add_radiobutton(label = "%90", value=90, variable=self.master.master.master.windowAlpha, command=lambda: self.master.master.master.attributes("-alpha", 90/100))
                                self.add_radiobutton(label = "Opaque", value=100, variable=self.master.master.master.windowAlpha, command=lambda: self.master.master.master.attributes("-alpha", 10))
                                self.add_separator()
                                self.add_command(label = "Reset opacity", command=lambda: self.attributes("-alpha", 10), accelerator="Ctrl+Alt+O", underline=6)
                        self.opacityMenu = opacityMenu(self)
                        self.add_cascade(menu=self.opacityMenu, label="Window opacity configuration")
                        class themeMenu(Menu):
                            def __init__(self, master: viewMenu):
                                super().__init__(master, tearoff=0)
                                self.root = self.master.master.master
                                self.add_radiobutton(label="Adapta", value="adapta", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("adapta"), accelerator="adapta")
                                self.add_radiobutton(label="Alt", value="alt", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("alt"), accelerator="alt")
                                self.add_radiobutton(label="Aquativo", value="aquativo", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("aquativo"), accelerator="aquativo")
                                self.add_radiobutton(label="Arc", value="arc", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("arc"), accelerator="arc")
                                self.add_radiobutton(label="Black", value="black", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("black"), accelerator="black")
                                self.add_radiobutton(label="Blue", value="blue", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("blue"), accelerator="blue")
                                self.add_radiobutton(label="Breeze", value="breeze", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("breeze"), accelerator="breeze")
                                self.add_radiobutton(label="Clearlooks", value="clearlooks", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("clearlooks"), accelerator="clearlooks")
                                self.add_radiobutton(label="Elegance", value="elegance", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("elegance"), accelerator="elegance")
                                self.add_radiobutton(label="Equilux", value="equilux", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("equilux"), accelerator="equilux")
                                self.add_radiobutton(label="Keramik", value="keramik", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("keramik"), accelerator="keramik")
                                self.add_radiobutton(label="Kroc", value="kroc", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("kroc"), accelerator="kroc")
                                self.add_radiobutton(label="Plastik", value="plastik", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("plastik"), accelerator="plastik")
                                self.add_radiobutton(label="Radiance", value="radiance", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("radiance"), accelerator="radiance")
                                self.add_radiobutton(label="Scidblue", value="scidblue", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("scidblue"), accelerator="scidblue")
                                self.add_radiobutton(label="Scidgreen", value="scidgreen", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("scidgreen"), accelerator="scidgreen")
                                self.add_radiobutton(label="Scidgrey", value="scidgrey", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("scidgrey"), accelerator="scidgrey")
                                self.add_radiobutton(label="Scidmint", value="scidmint", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("scidmint"), accelerator="scidmint")
                                self.add_radiobutton(label="Scidpink", value="scidpink", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("scidpink"), accelerator="scidpink")
                                self.add_radiobutton(label="Scidpurple", value="scidpurple", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("scidpurple"), accelerator="scidpurple")
                                self.add_radiobutton(label="Scidsand", value="scidsand", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("scidsand"), accelerator="scidsand")
                                self.add_radiobutton(label="Ubuntu", value="ubuntu", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("ubuntu"), accelerator="ubuntu")
                                self.add_radiobutton(label="Windows Native", value="winnative", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("winnative"), accelerator="winnative")
                                self.add_radiobutton(label="Windows XP Blue", value="winxpblue", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("winxpblue"), accelerator="winxpblue")
                                self.add_radiobutton(label="Windows Vista", value="vista", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("vista"), accelerator="vista")
                                self.add_radiobutton(label="Yaru", value="yaru", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("yaru"), accelerator="yaru")
                                self.add_separator()
                                self.add_command(label="Reset theme", command=lambda: (self.root.themeVar.set("vista"), self.root.theme.set_theme("vista")), accelerator="Ctrl+Alt+T")
                            def changeTheme(self, theme: str = "vista"):
                                self.root.theme.set_theme(theme)
                        self.themeMenu = themeMenu(self)
                        self.add_cascade(menu=self.themeMenu, label="Window theme configuration")
                        self.add_separator()
                        self.add_checkbutton(label="Auto-save configurations", onvalue=1, offvalue=0, variable=self.root.autoSaveConfigVar)
                        self.add_command(label="Save the configurations now", command=self.root._Interface__save_database)
                        self.add_separator()
                        class langMenu(Menu):
                            def __init__(self, master: viewMenu):
                                super().__init__(master, tearoff=0)
                                self.root = self.master.master.master
                                self.add_radiobutton(label="English", value=0, variable=self.root.languageVar)
                                self.add_radiobutton(label="Turkish (coming soon)", value=1, variable=self.root.languageVar, state=DISABLED)
                                self.add_radiobutton(label="German (coming soon)", value=2, variable=self.root.languageVar, state=DISABLED)
                                self.add_radiobutton(label="French (coming soon)", value=3, variable=self.root.languageVar, state=DISABLED)
                                self.add_separator()
                                self.add_command(label="Reset language to default", accelerator="Ctrl+Alt+L")
                        self.langMenu = langMenu(self)
                        self.add_cascade(menu=self.langMenu, label="Language")

                self.fileMenu = fileMenu(self)
                self.viewMenu = viewMenu(self)

                self.add_cascade(label = "Main", menu=self.fileMenu)
                self.add_cascade(label = "Preferences", menu=self.viewMenu)
                self.add_command(label = "Help", command=lambda: self.master.mainNotebook.select(4))

        self.menuBar = menuBar(self)
        self.config(menu = self.menuBar)

    def clipboard_get(self) -> Optional[str]:
        clipboard: Optional[str] = pyperclip.paste()
        if not clipboard:
            return str()
        elif len(clipboard) > 15000:
            if messagebox.askyesno("Super long text", "The text you're trying to paste is too long (longer than 15.000 characters) which can cause the program to freeze. Are you sure?"):
                return clipboard
            else:
                return str()
        else:
            return clipboard

    def clipboard_set(self, text: str = None):
        pyperclip.copy(text)

    class Settings(Toplevel):
        def __init__(self, master: Tk):
            self.master = master
            
            self.grab_set()
            self.width = 200
            self.height = 200

            self.wm_title("Encrypt-n-Decrypt Settings")
            self.wm_geometry(f"{self.width}x{self.height}")
            self.wm_resizable(height=False, width=False)
            self.wm_attributes("-fullscreen", False)
            self.wm_maxsize(self.width, self.height)
            self.wm_minsize(self.width, self.height)

    class Updates(Toplevel):
        def __init__(self, master: Tk):
            self.master = master
            releases = get("https://api.github.com/repos/Yilmaz4/Encrypt-n-Decrypt/releases").json()

            latest = None
            for release in releases:
                if not release["draft"] and not release["prerelease"]:
                    latest = release
                    break
            success = True if int(__version__.replace(".", "")) < int(latest["tag_name"].replace(".", "").replace("v", "")) else False if int(__version__.replace(".", "")) == int(latest["tag_name"].replace(".", "").replace("v", "")) else None

            if not success and success is not None:
                messagebox.showinfo("No updates available", "No updates avaliable yet. Please check back later.")
                self.master.logger.info("Updates checked. No updates available.")
                super().__init__(self.master)
                self.withdraw()
                self.destroy()
                return
            elif not success and success is None:
                messagebox.showwarning("sus amogus", "I really wonder how you currently have a more up-to-date version than the latest release in the official GitHub page. Pretty sure you're either me or a friend of mine.")
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

            self.wm_title("Encrypt'n'Decrypt Updater")
            self.wm_geometry(f"{self.width}x{self.height}")
            self.wm_resizable(height=False, width=False)
            self.wm_attributes("-fullscreen", False)
            self.wm_maxsize(self.width, self.height)
            self.wm_minsize(self.width, self.height)
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

if __name__ == "__main__":
    root = Interface()
    root.logger.info(f"{__title__} v{__version__} has been initialized")
    root.mainloop()
