"""
TO-DO:

Implement RSA encryption
Implement updating database keys on change, and reset database option
Implement self-update and auto update-checking
Implement skipping file when read/write fails, when the file is already not encrypted, and when the key is incorrect for the file in particular

Fix "Encrypt" button becoming disabled when multiple files and a key are selected
Fix freeze on Base64 huge file encoding

"""

__title__ = "Encrypt-n-Decrypt"
__author__ = "Yilmaz4"
__license__ = "MIT"
__copyright__ = "Copyright © 2017-2024 Yilmaz Alpaslan"
__version__ = "1.0.0"

from tkinter import (
    NORMAL, DISABLED, WORD, FLAT, END, LEFT,
    X, Y, RIGHT, LEFT, BOTH, CENTER, NONE,
    TOP, SUNKEN, HORIZONTAL, BOTTOM, W,
    VERTICAL, YES, NO, N, E, SE, S, W,
    Text, Toplevel, Menu, Pack, Grid, Tk,
    Place, IntVar, StringVar, Label, Frame,
    filedialog, messagebox, TclError
)

TkLabel = Label
from tkinter.ttk import (
    Entry, Button, Label, LabelFrame, Frame, Labelframe,
    Widget, Notebook, Radiobutton, Checkbutton,
    Scrollbar, Progressbar, Separator, Combobox,
    Treeview
)

try:
    from traceback import format_exc, print_exc
    from re import findall
    from threading import Thread
    from typing import Optional, Callable, final
    from urllib.request import urlopen
    from hurry.filesize import size, alternative
    from markdown import markdown
    from tkinterweb import HtmlFrame
    from requests import get
    from webbrowser import open as openweb
    from string import ascii_letters, digits
    from datetime import datetime
    from random import randint, choice
    from ttkthemes import ThemedStyle
    from types import FunctionType
    from zipfile import ZipFile
    from shutil import rmtree
    
    from requests.exceptions import ConnectionError
    from urllib3.exceptions import NewConnectionError, MaxRetryError
    from socket import gaierror
    
    from idlelib.percolator import Percolator
    from idlelib.colorizer import ColorDelegator

    from Crypto.Cipher import AES, PKCS1_OAEP, DES3
    from Crypto.PublicKey import RSA, DSA, ECC
    from Crypto.Signature import DSS
    from Crypto.Hash import SHA1, SHA256, SHA512, MD5
    from Crypto.Protocol.KDF import scrypt
    from Crypto.Random import get_random_bytes

    import base64, os, logging, pyperclip, binascii, sys
    import functools, multipledispatch, sqlite3, inspect

except (ModuleNotFoundError, ImportError) as exc:
    # If an error occurs while importing a module, show an error message explaining how to install the module, and exit the program
    lib: str = exc.msg.replace("No module named '", "").replace("'", "")
    match lib:
        case "Crypto.Cipher" | "Crypto.PublicKey" | "Crypto.Signature" | "Crypto.Hash" | "Crypto.Protocol.KDF" | "Crypto.Random":
            lib_name = "pycryptodome"
        case _:
            lib_name = lib
    messagebox.showerror("Missing library", "A required library named \"{name}\" is missing! You should be able to install that library with the following command:\n\npython -m pip install {name}\n\nIf that doesn't work, try googling.".format(name=lib_name))
    __import__("sys").exit()

def threaded(function: Callable):
    """
    Function decorator to run the function in a separate thread, using "threading" module
    """
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return Thread(target=function, args=args, kwargs=kwargs).start()
        except Exception:
            pass
    return wrapper

def exception_logged(function: Callable):
    """
    Function decorator to catch any exception(s) that has potential to occur
    and log the traceback to Encrypt-n-Decrypt.log file in that case.
    """
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs) if isinstance(function, FunctionType) else function(args[0])
        except Exception:
            # An exception occured in the function...
            # Get the root object (instance of 'Interface') from global variables
            print_exc()
            try:
                # If this doesn't raise KeyError, that means the exception occured after initialization of the interface
                root: Interface = globals()["root"]
            except KeyError:
                # If this raises KeyError, that means the exception occured during/before initialization
                pass
            if os.path.exists(f"{__title__}.log"):
                with open(f"{__title__}.log", mode="r", encoding="utf-8") as file:
                    index = file.read()
            else:
                index = str()
            message = f"{datetime.now().strftime(r'%Y-%m-%d %H:%M:%S')} [{'ERROR'}] {'An unexpected & unknown error has occured. Details about the can be found below. Please report this error to me over GitHub with the error details.'}"
            if "root" in globals() | locals():
                old_val: int = root.loggingAutoSaveVar.get()
                root.loggingAutoSaveVar.set(0)
                root.logger.error(message, format=False)
                for line in format_exc().splitlines():
                    root.logger.error(" " * (len(datetime.now().strftime(r'%Y-%m-%d %H:%M:%S')) + 1) + line + "\n", format=False)
                root.loggingAutoSaveVar.set(old_val)
            if "root" not in globals() | locals() or bool(root.loggingAutoSaveVar.get()):
                with open(f"{__title__}.log", mode="a+", encoding="utf-8") as file:
                    if ''.join(index.split()) == '' or index.endswith((f"{'='*24} End of logging session {'='*25}\n", f"{'='*24} End of logging session {'='*25}")):
                        endl = "\n"
                        file.write(f"{endl if ''.join(index.split()) != '' else ''}============ Start of logging session at {str(datetime.now().strftime(r'%Y-%m-%d %H:%M:%S'))} ============\n")
                    file.write(message + "\n" if not message.endswith("\n") else message)
                    for line in format_exc().splitlines():
                        file.write(" " * (len(datetime.now().strftime(r'%Y-%m-%d %H:%M:%S')) + 1) + line + "\n")
            messagebox.showerror(f"Unexpected {'fatal ' if 'root' not in globals() | locals() else ''}error", f"An unexpected & unknown {'fatal ' if 'root' not in globals() | locals() else ''}error has occured. Error details {'have been saved to Encrypt-n-Decrypt.log' if 'root' not in globals() | locals() else 'can be found in logs'}. Please report this error to me over GitHub with the error details.")
            if "root" in globals() | locals():
                root.statusBar.configure(text="Status: Ready")
    return wrapper

@exception_logged
def traffic_controlled(function: Callable):
    """
    Function decorator for the 'encrypt' and 'decrypt' methods of this class
    in order to prevent stack overflow by waiting for the previous encryption
    process to finish if it's still in progress before starting a new thread
    """
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        # args[0] is always 'self' in methods of a class
        self: Cryptography = args[0]
        root: Interface = self.master
        if function.__name__ == "encrypt":
            root.mainNotebook.encryptionFrame.encryptButton.configure(state=DISABLED if bool(root.dataSourceVar.get()) else NORMAL if not bool(root.mainNotebook.encryptionFrame.algorithmSelect.index(root.mainNotebook.encryptionFrame.algorithmSelect.select())) else DISABLED)
            if self.encryption_busy and self.encryption_busy is not None:
                # If an encryption is in progress, don't create a new thread and return instead
                return
            # If no encryptions are in progress, set the attribute representing whether an encryption is in progress or not to True
            self.encryption_busy = True
            try:
                # And start the encryption
                return function(*args, **kwargs)
            except Exception: ...
            finally:
                # Even if the encryption fails, set the attribute back to False to allow new requests
                self.encryption_busy = False
                root.mainNotebook.encryptionFrame.encryptButton.configure(state=NORMAL)
        else:
            root.mainNotebook.decryptionFrame.decryptButton.configure(state=DISABLED) if bool(root.decryptSourceVar.get()) else None
            if self.decryption_busy and self.decryption_busy is not None:
                # Likewise, if a decryption is in progress, don't create a new thread and return instead
                return
            self.decryption_busy = True
            try:
                return function(*args, **kwargs)
            except Exception: ...
            finally:
                self.decryption_busy = False
                root.mainNotebook.decryptionFrame.decryptButton.configure(state=NORMAL)
    return wrapper

class state_control_function(object):
    def __init__(self, cls: type):
        self.cls = cls

    def __call__(self, function: Callable):
        self.cls.root.scfs.append({'method': function, 'class': lambda: self._find_class(self.cls, function)})
        return function

    @staticmethod
    def _find_class(cls: type, function: Callable) -> type:
        return [subcls for subcls in [getattr(cls, subcls) for subcls in cls.__dict__ if not isinstance(getattr(cls, subcls), str)] if hasattr(subcls, function.__name__)][0]

class selfinjected(object):
    def __init__(self, name: str):
        self.name = name
    def __call__(self, function: Callable):
        function.__globals__[self.name] = function
        return function

@final
class Utilities(object):
    """
    Utilities class for some useful methods that may help me in the future
    """
    def __init__(self, root: Tk):
        self.root = root
        
    @selfinjected("self")
    def __init_subclass__(cls: type, *args, **kwargs):
        raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

    @classmethod
    def get_master_class(utils, meth: Callable) -> type:
        """
        Returns the class of the given method
        """
        if isinstance(meth, functools.partial):
            return utils.get_master_class(meth.func)
        if inspect.ismethod(meth) or (inspect.isbuiltin(meth) and getattr(meth, '__self__', None) is not None and getattr(meth.__self__, '__class__', None)):
            for cls in inspect.getmro(meth.__self__.__class__):
                if meth.__name__ in cls.__dict__:
                    return cls
            meth: Callable = getattr(meth, '__func__', meth)
        if inspect.isfunction(meth):
            cls: type = getattr(inspect.getmodule(meth),
                        meth.__qualname__.split('.<locals>', 1)[0].rsplit('.', 1)[0],
                        None)
            if isinstance(cls, type):
                return cls
        return getattr(meth, '__objclass__', None)
    
    @classmethod
    def get_inner_classes(utils, cls: type) -> list[type]:
        """
        Returns a list of all inner classes of the given class
        """
        return [cls_attr for cls_attr in cls.__dict__.values() if inspect.isclass(cls_attr)]

@final
class Cryptography(object):
    def __init__(self, master: Tk):
        self.master = self.root = master
        self.__encryption_busy = False
        self.__decryption_busy = False
    
    @selfinjected("self")
    def __init_subclass__(cls: type, *args, **kwargs):
        raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

    @staticmethod
    def generate_key(length: int = 32) -> str:
        """
        Static method to generate and return a random encryption key in the given length (defaults to 32)
        """
        if not isinstance(length, int):
            length = int(length)
        key = str()
        for _ in range(length):
            random = randint(1, 32)
            if random in range(0, 25):
                key += choice(ascii_letters)
            elif random in range(0, 30):
                key += choice(digits)
            elif random >= 30:
                key += choice("!'^+%&/()=?_<>#${[]}\|__--$__--")
        return key

    @staticmethod
    def derivate_key(password: str | bytes) -> Optional[bytes]:
        """
        Static method to derivate an encryption key from a password (using KDF protocol)
        """
        try:
            return base64.urlsafe_b64encode(scrypt(password.decode("utf-8") if isinstance(password, bytes) else password, get_random_bytes(16), 24, N=2**14, r=8, p=1))
        except Exception:
            return None

    @staticmethod
    def get_key(root: Tk, entry: Optional[Entry] = None) -> Optional[str]:
        """
        Multiply dispatched static method to get the encryption key from the given file and insert it into the optionally given entry
        """
        path = filedialog.askopenfilename(title="Open a key file", filetypes=[("Encrypt'n'Decrypt key file", "*.key"), ("Text document", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        match os.path.getsize(path):
            case 16 | 24 | 32:
                with open(path, mode="rb") as file:
                    index = file.read()
                try:
                    AES.new(index, AES.MODE_CFB, iv=get_random_bytes(AES.block_size))
                except Exception:
                    messagebox.showwarning("Invalid key file", "The specified file does not contain any valid key for encryption.")
                    root.logger.error("Key file with no valid key inside was specified.")
                    return
                else:
                    if entry:
                        entry.replace(index.decode("utf-8"))
                    return index.decode("utf-8")
            case 76 | 88 | 96:
                with open(path, mode="rb") as file:
                    index = file.read()
                for s, e in zip(range(0, len(index)), range(int(len(index) / 3), len(index))):
                    try:
                        result = AES.new(index[s:e], AES.MODE_CFB, iv=base64.urlsafe_b64decode(index.replace(index[s:e], b""))[:16]).decrypt(base64.urlsafe_b64decode(index.replace(index[s:e], b""))[16:]).decode("utf-8")
                        if entry:
                            entry.replace(result)
                        return result
                    except Exception:
                        continue
            case _:
                messagebox.showwarning("Invalid key file", "The specified file does not contain any valid key for encryption.")
                root.logger.error("Key file with no valid key inside was specified.")
                return

    @classmethod
    def save_key(cls, key: str | bytes, root: Tk) -> None:
        """
        Static method to save the encryption key to a file
        """
        if isinstance(key, str):
            key = bytes(key, "utf-8")
        path = filedialog.asksaveasfilename(title="Save encryption key", initialfile="Encryption Key.key", filetypes=[("Encrypt'n'Decrypt key file", "*.key"), ("Text document", "*.txt"), ("All files", "*.*")], defaultextension="*.key")
        if ''.join(path.split()) == '':
            # If save dialog was closed without choosing a file, simply return
            return
        if os.path.splitext(path)[1].lower() == ".key":
            # If the file extension is .key, save the key using the special algorithm
            _key = cls.generate_key(32)

            iv = get_random_bytes(AES.block_size)
            aes = AES.new(bytes(_key, "utf-8"), AES.MODE_CFB, iv=iv)
            raw = iv + aes.encrypt(key)
            res = base64.urlsafe_b64encode(raw).decode()

            index = randint(0, len(res))
            final = res[:index] + _key + res[index:]
            try:
                os.remove(path)
            except:
                pass
            finally:
                with open(path, encoding = 'utf-8', mode="w") as file:
                    file.write(str(final))
                root.logger.debug("Encryption key has been saved to \"{}\"".format(path))
        else:
            # Otherwise, simply save the key onto the file
            with open(path, encoding="utf-8", mode="wb") as file:
                file.write(key)

    @exception_logged
    def update_status(self, status: str = "Ready") -> None:
        """
        A simple method to simplify updating the status bar of the program
        """
        root: Interface = self.root
        root.statusBar.configure(text=f"Status: {status}")
        # Call the 'update()' method manually in case the interface is not responding at the moment
        root.update()

    @property
    def encryption_busy(self) -> bool:
        """
        Property to check if an encryption process is currently in progress
        """
        return self.__encryption_busy
    @encryption_busy.setter
    def encryption_busy(self, value: bool) -> None:
        if self.__encryption_busy == value and value:
            raise Exception
        self.__encryption_busy = value

    @property
    def decryption_busy(self) -> bool:
        """
        Property to check if a decryption process is currently in progress
        """
        return self.__decryption_busy
    @decryption_busy.setter
    def decryption_busy(self, value: bool) -> None:
        if self.__decryption_busy == value and value:
            raise Exception
        self.__decryption_busy = value

    @threaded
    @traffic_controlled
    @exception_logged
    def encrypt(self) -> None:
        root: Interface = self.master

        if not bool(root.mainNotebook.encryptionFrame.algorithmSelect.index(root.mainNotebook.encryptionFrame.algorithmSelect.select())):
            # If the "Symmetric Key Encryption" tab is selected...
            if not bool(root.keySourceSelection.get()):
                # If the user has chosen to generate a new key, generate one
                self.update_status("Generating the key...")
                key: bytes = self.generate_key(int(root.generateRandomAESVar.get() if not bool(root.generateAlgorithmSelection.get()) else root.generateRandomDESVar.get()) / 8).encode("utf-8")
            else:
                # Otherwise, use the key the user has provided
                key: bytes = root.keyEntryVar.get().encode("utf-8")

            self.update_status("Creating the cipher...")
            try:
                # Try to create the cipher (either AES or DES3 object according to the user's choice) with the given/generated key
                if (not bool(root.generateAlgorithmSelection.get()) and not bool(root.keySourceSelection.get())) or (not bool(root.entryAlgorithmSelection.get()) and bool(root.keySourceSelection.get())):
                    iv = get_random_bytes(AES.block_size)
                    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
                else:
                    iv = get_random_bytes(DES3.block_size)
                    cipher = DES3.new(key, mode=DES3.MODE_OFB, iv=iv)
            except ValueError as details:
                if not len(key) in [16, 24, 32 if "AES" in str(details) else False]:
                    # If the key length is not valid, show an error message
                    messagebox.showerror("Invalid key length", "The length of the encryption key you've entered is invalid! It can be either 16, 24 or 32 characters long.")
                    root.logger.error("Key with invalid length was specified")
                    self.update_status("Ready")
                    return
                else:
                    # If the key length is valid, but the key contains invalid characters, show an error message
                    messagebox.showerror("Invalid key", "The key you've entered is invalid for encryption. Please enter another key or consider generating one instead.")
                    root.logger.error("Invalid key was specified")
                    self.update_status("Ready")
                    return

            datas: list[str | bytes] = []
            if not bool(root.dataSourceVar.get()):
                # If the user has chosen to encrypt a plain text, simply put the text from the entry to the datas list
                datas.append(bytes(root.textEntryVar.get(), "utf-8"))
            else:
                # Otherwise, split the file paths from the entry using '|' character and put in the datas list
                path: str = root.mainNotebook.encryptionFrame.fileEntry.get()
                for filename in path.split('|'):
                    datas.append(filename)
            
            # Iterate over the data(s) to be encrypted
            for raw, index in [(raw.lstrip(), datas.index(raw)) for raw in datas]:
                if isinstance(raw, str):
                    # If the data is an instance of str, by other means, a file path, open the file and convert to bytes
                    try:
                        self.update_status(f"Reading the file (file {index + 1}/{len(datas)})...")
                        with open(raw, mode="rb") as file:
                            data: bytes = file.read()
                    except PermissionError:
                        messagebox.showerror("Access denied", f"Access to the file named \"{os.path.basename(raw)}\" that you've specified has been denied. Try running the program as administrator and make sure read & write access for the file is permitted.")
                        root.logger.error(f"Read permission for the file named \"{os.path.basename(raw)}\" that was specified has been denied, skipping")
                        continue
                else:
                    # Otherwise, just use the current data as is
                    data: bytes = raw
                try:
                    self.update_status(f"Encrypting (file {index + 1}/{len(datas)})..." if isinstance(raw, str) else "Encrypting...")
                    # Encrypt the data and combine it with the IV used
                    root.lastEncryptionResult = iv + cipher.encrypt(data)
                except MemoryError:
                    # If the computer runs out of memory while encrypting (happens when encrypting big files), show an error message
                    messagebox.showerror("Not enough memory", "Your computer has run out of memory while encrypting the file. Try closing other applications or restart your computer.")
                    root.logger.error("Device has run out of memory while encrypting, encryption was interrupted")
                    self.update_status("Ready")
                    return
                # Delete the data variable since we have the encrypted data held on another variable, in order to free up some memory
                del data
                self.update_status(f"Encoding (file {index + 1}/{len(datas)})..." if isinstance(raw, str) else "Encoding the result...")
                try:
                    try:
                        # Encode the result using base64
                        root.lastEncryptionResult = base64.urlsafe_b64encode(root.lastEncryptionResult).decode("utf-8")
                    except TypeError:
                        self.update_status("Ready")
                        return
                    if bool(root.encryptWriteFileContentVar.get()) and bool(root.dataSourceVar.get()):
                        self.update_status(f"Writing to the file (file {index + 1}/{len(datas)})...")
                        try:
                            with open(raw, mode="wb") as file:
                                file.write(root.lastEncryptionResult.encode("utf-8"))
                            if len(datas) != 1:
                                del root.lastEncryptionResult
                        except PermissionError:
                            # If the program doesn't have write access to the file, show an error message
                            if messagebox.askyesnocancel("Access denied", f"Write access to the file named \"{os.path.basename(raw)}\" that you've specified has been denied, therefore the result could not have been overwritten to the file. Do you want to save the encrypted data as another file?"):
                                newpath = filedialog.asksaveasfilename(title="Save encrypted data", initialfile=os.path.basename(path[:-1] if path[-1:] == "\\" else path), initialdir=os.path.dirname(path), filetypes=[("All files","*.*")], defaultextension="*.key")
                                if newpath == "":
                                    failure = True
                                    root.logger.error("Write permission for the file specified has been denied, encryped data could not be saved to the destination")
                                    break
                                else:
                                    with open(newpath, mode="wb") as file:
                                        file.write(bytes(root.lastEncryptionResult, "utf-8"))
                            root.logger.error("Write permission for the file specified has been denied, encrypted data could not be saved to the destination")
                            self.update_status("Ready")
                            failure = True
                            return
                        except OSError as details:
                            if "No space" in str(details):
                                # If no space left on device to save the result, show an error message
                                messagebox.showerror("No space left", "There is no space left on your device. Free up some space and try again.")
                                root.logger.error("No space left on device, encrypted data could not be saved to the destination")
                                self.update_status("Ready")
                                failure = True
                                pass

                except MemoryError:
                    # Again, if the computer runs out of memory while encoding, show an error message
                    messagebox.showerror("Not enough memory", "Your computer has run out of memory while encoding the result. Try closing other applications or restart your computer.")
                    root.logger.error("Device has run out of memory while encoding, encryption was interrupted")
                    self.update_status("Ready")
                    return
                # Set the variables holding the key used and the file encrypted (if applicable) in order to be able to copy later
                root.lastEncryptionKey = key
                root.lastEncryptedFile = root.fileEntryVar.get() if bool(root.dataSourceVar.get()) else None

            failure = False
                            
            if len(datas) != 1 and bool(root.dataSourceVar.get()):
                # If multiple files were encrypted, don't show the result (because how are we supposed to show anyway)
                root.mainNotebook.encryptionFrame.outputFrame.outputText.configure(foreground="gray", wrap=WORD)
                root.mainNotebook.encryptionFrame.outputFrame.outputText.replace("Encrypted data is not being displayed because multiple files were selected to be encrypted.")
                if hasattr(root, 'lastEncryptionResult'):
                    del root.lastEncryptionResult
            elif hasattr(root, "lastEncryptionResult") and len(root.lastEncryptionResult) > 15000:
                # If one file was chosen or a plain text was entered to be encrypted, but the result is over 15.000 characters, don't show the result
                root.mainNotebook.encryptionFrame.outputFrame.outputText.configure(foreground="gray", wrap=WORD)
                root.mainNotebook.encryptionFrame.outputFrame.outputText.replace("Encrypted data is not being displayed because it is longer than 15.000 characters.")
                if hasattr(root, 'lastEncryptionResult'):
                    del root.lastEncryptionResult
            else:
                # Otherwise, just show it
                root.mainNotebook.encryptionFrame.outputFrame.outputText.configure(foreground="black", wrap=None)
                root.mainNotebook.encryptionFrame.outputFrame.outputText.replace(root.lastEncryptionResult)

            root.mainNotebook.encryptionFrame.outputFrame.AESKeyText.replace(key.decode("utf-8"))
            root.mainNotebook.encryptionFrame.outputFrame.RSAPublicText.configure(bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, highlightcolor="#cccccc")
            root.mainNotebook.encryptionFrame.outputFrame.RSAPrivateText.configure(bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, highlightcolor="#cccccc")
            root.mainNotebook.encryptionFrame.outputFrame.RSAPublicText.clear()
            root.mainNotebook.encryptionFrame.outputFrame.RSAPrivateText.clear()

            self.update_status("Ready")
            if not failure:
                # If there was no error while writing the result to the file, log the success
                if not bool(root.keySourceSelection.get()):
                    root.logger.info(f"{'Entered text' if not bool(root.dataSourceVar.get()) else 'Specified file'} has been successfully encrypted using {'AES' if not bool(root.generateAlgorithmSelection.get()) else '3DES'}-{len(key) * 8} algorithm")
                else:
                    root.logger.info(f"{'Entered text' if not bool(root.dataSourceVar.get()) else 'Specified file'} has been successfully encrypted using {'AES' if not bool(root.entryAlgorithmSelection.get()) else '3DES'}-{len(key) * 8} algorithm")

        else:
            data = root.mainNotebook.encryptionFrame.textEntry.get()
            self.update_status("Generating the key...")
            key = RSA.generate(root.generateRandomRSAVar.get() if root.generateRandomRSAVar.get() >= 1024 else root.customRSALengthVar.get())
            publicKey = key.publickey()
            privateKey = key.exportKey()

            self.update_status("Defining the cipher...")
            cipher = PKCS1_OAEP.new(publicKey)

            self.update_status("Encrypting...")
            try:
                encrypted = cipher.encrypt(data.encode("utf-8") if isinstance(data, str) else data)
            except ValueError:
                messagebox.showerror(f"{'Text is too long' if not bool(root.dataSourceVar) else 'File is too big'}", "The {} is too {} for RSA-{} encryption. Select a longer RSA key and try again.".format('text you\'ve entered' if not bool(root.dataSourceVar.get()) else 'file you\'ve specified', 'long' if not bool(root.dataSourceVar.get()) else 'big', root.generateRandomRSAVar.get()))
                root.logger.error(f"Too {'long text' if not bool(root.dataSourceVar) else 'big file'} was specified, encryption was interrupted")
                self.update_status("Ready")
                return

            root.mainNotebook.encryptionFrame.outputFrame.outputText.replace(base64.urlsafe_b64encode(encrypted).decode("utf-8"))
            root.mainNotebook.encryptionFrame.outputFrame.AESKeyText.clear()
            root.mainNotebook.encryptionFrame.outputFrame.RSAPublicText.replace(base64.urlsafe_b64encode(publicKey.export_key()).decode("utf-8"))
            root.mainNotebook.encryptionFrame.outputFrame.RSAPrivateText.replace(base64.urlsafe_b64encode(privateKey).decode("utf-8"))

            """
            decryptor = PKCS1_OAEP.new(RSA.import_key(privateKey))
            decrypted = decryptor.decrypt(encrypted)
            print('Decrypted:', decrypted.decode())
            """

            self.update_status("Ready")

    @threaded
    @traffic_controlled
    @exception_logged
    def decrypt(self) -> None:
        root: Interface = self.master

        if not bool(root.mainNotebook.decryptionFrame.algorithmSelect.index(root.mainNotebook.decryptionFrame.algorithmSelect.select())):
            self.update_status("Defining cipher...")

            datas: list[str | bytes] = []
            if not bool(root.decryptSourceVar.get()):
                # If the user has chosen to decrypt a plain text, simply put the text from the entry to the datas list
                datas.append(bytes(root.textDecryptVar.get(), "utf-8"))
            else:
                # Otherwise, split the file paths from the entry using '|' character and put in the datas list
                path: str = root.mainNotebook.decryptionFrame.fileDecryptEntry.get()
                for filename in path.split('|'):
                    datas.append(filename)
            
            # Iterate over the data(s) to be decrypted
            for raw, index in [(raw.lstrip(), datas.index(raw)) for raw in datas]:
                if isinstance(raw, str):
                    # If the data is an instance of str, by other means, a file path, open the file and convert to bytes
                    try:
                        self.update_status(f"Reading the file (file {index + 1}/{len(datas)})...")
                        with open(raw, mode="rb") as file:
                            data: bytes = file.read()
                    except PermissionError:
                        messagebox.showerror("Access denied", f"Access to the file named \"{os.path.basename(raw)}\" that you've specified has been denied. Try running the program as administrator and make sure read & write access for the file is permitted.")
                        root.logger.error(f"Read permission for the file named \"{os.path.basename(raw)}\" that was specified has been denied, skipping")
                        continue
                else:
                    # Otherwise, just use the current data as is
                    data: bytes = raw
                self.update_status(f"Decoding (file {index + 1}/{len(datas)})..." if isinstance(raw, str) else "Decoding...")
                try:
                    new_data: bytes = base64.urlsafe_b64decode(data)
                except Exception as exc:
                    messagebox.showerror("Unencrypted file", f"This file doesn't seem to be encrypted using {'AES' if not bool(root.decryptAlgorithmVar.get()) else '3DES'} symmetric key encryption algorithm.")
                    root.logger.error("Unencrypted file was specified for decryption")
                    self.update_status("Ready")
                    return
                else:
                    if data == base64.urlsafe_b64encode(new_data):
                        data: bytes = new_data
                        del new_data
                    else:
                        messagebox.showerror("Unencrypted file", f"This file doesn't seem to be encrypted using {'AES' if not bool(root.decryptAlgorithmVar.get()) else '3DES'} symmetric key encryption algorithm.")
                        root.logger.error("Unencrypted file was specified")
                        self.update_status("Ready")
                        return
                if 'cipher' not in locals():
                    iv = data[:16 if not bool(root.decryptAlgorithmVar.get()) else 8]
                    key = root.decryptKeyVar.get()[:-1 if root.decryptKeyVar.get().endswith("\n") else None].encode("utf-8")

                    try:
                        if not bool(root.decryptAlgorithmVar.get()):
                            cipher = AES.new(key, AES.MODE_CFB, iv=iv)
                        else:
                            cipher = DES3.new(key, DES3.MODE_OFB, iv=iv)
                    except ValueError as details:
                        if len(iv) != 16 if not bool(root.decryptAlgorithmVar.get()) else 8:
                            messagebox.showerror("Unencrypted data", f"The text you've entered doesn't seem to be encrypted using {'AES' if not bool(root.decryptAlgorithmVar.get()) else '3DES'} symmetric key encryption algorithm.")
                            root.logger.error("Unencrypted text was entered")
                            self.update_status("Ready")
                            return
                        elif not len(key) in [16, 24, 32 if "AES" in str(details) else False]:
                            messagebox.showerror("Invalid key length", "The length of the encryption key you've entered is invalid! It can be either 16, 24 or 32 characters long.")
                            root.logger.error("Key with invalid length was entered for decryption")
                            self.update_status("Ready")
                            return
                        else:
                            messagebox.showerror("Invalid key", "The encryption key you've entered is invalid.")
                            root.logger.error("Invalid key was entered for decryption")
                            self.update_status("Ready")
                            return
                try:
                    self.update_status(f"Decrypting (file {index + 1}/{len(datas)})..." if isinstance(raw, str) else "Decrypting...")
                    # Decrypt the data
                    root.lastDecryptionResult = cipher.decrypt(data.replace(iv, b""))
                    
                except MemoryError:
                    # If the computer runs out of memory while decrypting (happens when encrypting big files), show an error message
                    messagebox.showerror("Not enough memory", "Your computer has run out of memory while decrypting the file. Try closing other applications or restart your computer.")
                    root.logger.error("Device has run out of memory while decrypting, decryption was interrupted")
                    self.update_status("Ready")
                    return
                # Delete the data variable since we have the decrypted data held on another variable, in order to free up some memory
                del data
                try:
                    if bool(root.decryptWriteFileContentVar.get()) and bool(root.decryptSourceVar.get()):
                        self.update_status(f"Writing to the file (file {index + 1}/{len(datas)})...")
                        try:
                            with open(raw, mode="wb") as file:
                                file.write(root.lastDecryptionResult)
                            if len(datas) != 1:
                                del root.lastDecryptionResult
                        except PermissionError:
                            # If the program doesn't have write access to the file, show an error message
                            if messagebox.askyesnocancel("Access denied", f"Write access to the file named \"{os.path.basename(raw)}\" that you've specified has been denied, therefore the result could not have been overwritten to the file. Do you want to save the encrypted data as another file?"):
                                newpath = filedialog.asksaveasfilename(title="Save encrypted data", initialfile=os.path.basename(path[:-1] if path[-1:] == "\\" else path), initialdir=os.path.dirname(path), filetypes=[("All files","*.*")], defaultextension="*.key")
                                if newpath == "":
                                    failure = True
                                    root.logger.error("Write permission for the file specified has been denied, encryped data could not be saved to the destination")
                                    break
                                else:
                                    with open(newpath, mode="wb") as file:
                                        file.write(bytes(root.lastEncryptionResult, "utf-8"))
                            root.logger.error("Write permission for the file specified has been denied, encrypted data could not be saved to the destination")
                            self.update_status("Ready")
                            failure = True
                            return
                        except OSError:
                            if "No space" in str(details):
                                # If no space is left on device to save the result, show an error message
                                messagebox.showerror("No space left", "There is no space left on your device. Free up some space and try again.")
                                root.logger.error("No space left on device, encrypted data could not be saved to the destination")
                                self.update_status("Ready")
                                failure = True
                                pass

                except MemoryError:
                    # Again, if the computer runs out of memory while encoding, show an error message
                    messagebox.showerror("Not enough memory", "Your computer has run out of memory while encoding the result. Try closing other applications or restart your computer.")
                    root.logger.error("Device has run out of memory while encoding, encryption was interrupted")
                    self.update_status("Ready")
                    return

            self.update_status("Displaying the result...")
            try:
                root.lastDecryptionResult = root.lastDecryptionResult.decode("utf-8")
            except UnicodeDecodeError as exc:
                if bool(root.decryptSourceVar.get()):
                    root.mainNotebook.decryptionFrame.decryptOutputText.configure(foreground="gray")
                    root.mainNotebook.decryptionFrame.decryptOutputText.replace("Decrypted data is not being displayed because it's in an unknown encoding.")
                else:
                    messagebox.showerror("Invalid key", "The encryption key you've entered doesn't seem to be the right key. Make sure you've entered the correct key.")
                    root.logger.error("Wrong key was entered for decryption")
                    self.update_status("Ready")
                    return
            except AttributeError:
                root.mainNotebook.decryptionFrame.decryptOutputText.configure(foreground="gray")
                root.mainNotebook.decryptionFrame.decryptOutputText.replace("Decrypted data is not being displayed because multiple files were selected to be decrypted.")
            else:
                if not len(root.lastDecryptionResult) > 15000:
                    root.mainNotebook.decryptionFrame.decryptOutputText.configure(foreground="black")
                    root.mainNotebook.decryptionFrame.decryptOutputText.replace(root.lastDecryptionResult)
                else:
                    root.mainNotebook.decryptionFrame.decryptOutputText.configure(foreground="gray")
                    root.mainNotebook.decryptionFrame.decryptOutputText.replace("Decrypted data is not being displayed because it's longer than 15.000 characters.")
            self.update_status("Ready")

    @threaded
    @exception_logged
    def hash(self, data: str | bytes, SHA1Widget: Widget, SHA256Widget: Widget, SHA512Widget: Widget, MD5Widget: Widget) -> None:
        # Define the widgets related to hashing
        self.__hashDigestFrame: object = self.root.mainNotebook.miscFrame.hashDigestFrame
        self.SHA1Entry, self.SHA256Entry, self.SHA512Entry, self.MD5Entry = SHA1Widget, SHA256Widget, SHA512Widget, MD5Widget
        self.__hashEntries: dict[str, Widget] = {}
        self.__hashWidgets: dict[str, dict[str, Widget]] = {
            "hash_plain": {},
            "hash_file": {},
            "output": {}
        }
        # Instead of inserting every single widget manually, just use a hack to get the widgets from the frame
        for name, value in self.__hashDigestFrame.__dict__.items():
            if name[0].islower() and isinstance(value, (Button, Entry, Radiobutton)):
                self.__hashWidgets[findall('[a-zA-Z][^A-Z]*', name)[0]][name] = value
            elif name.startswith(("SHA", "MD5")) and "copybutton" in name.lower():
                self.__hashWidgets["output"][name] = value
            elif name.startswith(("SHA", "MD5")) and "entry" in name.lower():
                self.__hashEntries[name] = value

        # No need for hacking here
        self.__hashAlgorithms: dict[str, object] = {
            "SHA-1": SHA1,
            "SHA-256": SHA256,
            "SHA-512": SHA512,
            "MD-5": MD5
        }
        
        # If the data is an instance of str data type, by other means, if a file was chosen; the same file was hashed before; and the size of the previously hashed file is exactly the same as current; return
        if isinstance(data, str) and self.__hashDigestFrame._last_file["path"] == self.__hashDigestFrame.hash_fileEntry.get() and self.__hashDigestFrame._last_file["size"] == os.path.getsize(self.__hashDigestFrame.hash_fileEntry.get()):
            return
        # For some reason, the entries turn to "normal" state, so we have to set them back to "readonly"
        for entry in self.__hashEntries.values():
            entry.configure(foreground="gray", state="readonly")

        if isinstance(data, str):
            # If a file was chosen to be hashed...
            for category in self.__hashWidgets.values():
                for widget in category.values():
                    # Disable all the widgets to prevent the user from changing them
                    widget.configure(state=DISABLED)
            self.__hashDigestFrame.root.statusBar.configure(text="Status: Reading the file...")
            self.__hashDigestFrame.root.update()
            try:
                # Attempt to read the file
                with open(data, mode="rb") as file:
                    data = file.read()
            except (OSError, PermissionError):
                # If the program has no read access to the file, show an error message
                messagebox.showerror("Access denied", "Access to the file you've specified has been denied. Try running the program as administrator and make sure read & write access to the file is permitted.")
                self.root.logger.error("Read permission for the file specified has been denied, hash calculation was interrupted.")
                self.update_status("Ready")
                determine_category = {
                    True: "hash_file",
                    False: "hash_plain"
                }
                # Set all the widgets back to "normal" state
                for widget in self.__hashWidgets[determine_category[bool(self.root.hashCalculationSourceVar.get())]].values():
                    widget.configure(state=NORMAL)
                for radiobutton in [self.__hashWidgets["hash_plain" if "hash_plain" in widget.lower() else "hash_file"][widget] for widget in [j for i in self.__hashWidgets.values() for j in i] if "radio" in widget.lower()]:
                    radiobutton.configure(state=NORMAL)
                return
            else:
                # To check later, save the file path and the file size to an attribute
                self.__hashDigestFrame._last_file["path"] = self.__hashDigestFrame.hash_fileEntry.get()
                self.__hashDigestFrame._last_file["size"] = os.path.getsize(self.__hashDigestFrame.hash_fileEntry.get())
        # Start the hashing process...
        for entry, copy_button, name, algorithm in zip(self.__hashEntries.values(), [widget for name, widget in self.__hashWidgets["output"].items() if "copy" in name.lower()], self.__hashAlgorithms.keys(), self.__hashAlgorithms.values()):
            self.update_status(f"Calculating {name} hash...")
            _hasher = algorithm.new()
            _hasher.update(data)
            entry.replace(_hasher.hexdigest())
            # As we get the hash of the data, set the copy widget of the entry back to "normal" state in order to let the user copy the hash quickly without waiting for others
            entry.configure(foreground="black", state="readonly")
            copy_button.configure(state=NORMAL)
        self.update_status("Ready")
        
        determine_category = {
            True: "hash_file",
            False: "hash_plain"
        }
        # Set all the widgets back to "normal" state
        for widget in self.__hashWidgets[determine_category[bool(self.root.hashCalculationSourceVar.get())]].values():
            widget.configure(state=NORMAL)
        for radiobutton in [self.__hashWidgets["hash_plain" if "hash_plain" in widget.lower() else "hash_file"][widget] for widget in [j for i in self.__hashWidgets.values() for j in i] if "radio" in widget.lower()]:
            radiobutton.configure(state=NORMAL)

@final
class Cache(object):
    """
    Class for storing logging history and other history data (will be implemented soon)
    """
    def __init__(self, master: Tk):
        super().__init__()
        self.master = master

        self.loggings_history: list[dict[logging.LogRecord, dict[str, int | str | bool]]] = []
        self.encryptions_history: list[dict] = []
        self.decryptions_history: list[dict] = []
    
    @selfinjected("self")
    def __init_subclass__(cls: type, *args, **kwargs):
        raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

@final
class Handler(logging.Handler):
    def __init__(self, widget: Optional[Text], master: Tk, cache: Cache = None):
        super().__init__()
        self.widget = widget
        self.master = master
        self.cache = cache
        
    @selfinjected("self")
    def __init_subclass__(cls: type, *args, **kwargs):
        raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

    def emit(self, record: logging.LogRecord):
        # Format the log message if it was not specified not to be formatted (e.g. if the log message ends with '!NO_FORMAT')
        message = record.getMessage().replace("!NO_FORMAT", "") if record.getMessage().endswith("!NO_FORMAT") else self.format(record)
        def append():
            levels = {
                "NOTSET": 0, "DEBUG": 10, "INFO": 20,
                "WARNING": 30, "ERROR": 40, "CRITICAL": 50
            }
            if record.levelno < levels[self.master.levelSelectVar.get()]:
                return
            # Insert the log message into the logging widget
            self.widget.configure(state=NORMAL)
            self.widget.insert(END, message, record.levelname.lower())
            self.widget.configure(state=DISABLED)
            
            # Scroll the widget down to the last line
            self.widget.yview(END)
        if self.widget is not None:
            # If a widget for logging was specified, call the above function
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
            # If the user has enabled auto-saving, save the log messages to a file
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
                file.write(message + "\n" if not message.endswith("\n") else message)

    @staticmethod
    def format(record: logging.LogRecord) -> str:
        """
        Static method for formatting the log message with the date created and the level of the log
        """
        return f"{datetime.now().strftime(r'%Y-%m-%d %H:%M:%S')} [{record.levelname}] {record.getMessage()}" + "{}".format('\n' if not record.getMessage().endswith('\n') else '')

@final
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
        
    @selfinjected("self")
    def __init_subclass__(cls: type, *args, **kwargs):
        raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

    @exception_logged
    def end_logging_file(self):
        """
        Method for adding ending line to the log file on termination of the program
        """
        if bool(self.root.loggingAutoSaveVar.get()):
            try:
                with open(f"{__title__}.log", mode="r", encoding="utf-8") as file:
                    index = file.read()
            except FileNotFoundError:
                return
            with open(f"{__title__}.log", mode="a", encoding="utf-8") as file:
                if ''.join(index.split()) != '':
                    file.write(f"{'='*24} End of logging session {'='*25}\n")

    # Overwrite all the methods for logging in order to implement the 'format' parameter
    def debug(self, message: str, format: bool = True):
        self.logger.debug((message + "\n" if not message.endswith("\n") else message) + ("!NO_FORMAT" if not format else ""))
    def info(self, message: str, format: bool = True):
        self.logger.info((message + "\n" if not message.endswith("\n") else message) + ("!NO_FORMAT" if not format else ""))
    def warning(self, message: str, format: bool = True):
        self.logger.warning((message + "\n" if not message.endswith("\n") else message) + ("!NO_FORMAT" if not format else ""))
    def error(self, message: str, format: bool = True):
        self.logger.error((message + "\n" if not message.endswith("\n") else message) + ("!NO_FORMAT" if not format else ""))
    def critical(self, message: str, format: bool = True):
        self.logger.critical((message + "\n" if not message.endswith("\n") else message) + ("!NO_FORMAT" if not format else ""))

@final
class ToolTip(object):
    """
    A class for creating tooltips that appear on hover. Code is mostly from StackOverflow :P
    """
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

        self.speed = 10
    
    @selfinjected("self")
    def __init_subclass__(cls: type, *args, **kwargs):
        raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

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

    @exception_logged
    def showtip(self, event=None):
        # Get the mouse position and determine the screen coordinates to show the tooltip
        x = root.winfo_pointerx() + 12
        y = root.winfo_pointery() + 16

        # Create a Toplevel because we can't just show a label out of nowhere in the main window with fade-in & fade-away animations
        self.tw = Toplevel(self.widget)
        self.tw.attributes("-alpha", 0)

        # Configure the tooltip for visuality
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry("+%d+%d" % (x, y))
        label = Label(self.tw, text=self.text,
            justify='left', background="#ffffff",
            foreground="#6f6f6f", relief='solid',
            borderwidth=1, wraplength=self.wraplength)
        label.pack(ipadx=1)

        def fade_in():
            if not self.widget is root.winfo_containing(root.winfo_pointerx(), root.winfo_pointery()):
                # If mouse is no longer on the widget, destroy the tooltip and unschedule the fade_in
                self.tw.destroy()
                return
            alpha = self.tw.attributes("-alpha")
            if alpha != 1:
                # Increase the transparency by 0.1 until it is fully visible
                alpha += .1
                self.tw.attributes("-alpha", alpha)
                # Call this function again in 10 milliseconds (value of self.speed attribute)
                self.tw.after(self.speed, fade_in)
            else:
                return
        fade_in()

    @exception_logged
    def hidetip(self):
        if self.tw:
            # If the tooltip is still a thing (i.e. it has not been destroyed unexpectedly), start fading it away
            def fade_away():
                if self.widget is root.winfo_containing(root.winfo_pointerx(), root.winfo_pointery()):
                    self.tw.destroy()
                    return
                try:
                    alpha = self.tw.attributes("-alpha")
                except TclError:
                    return
                if alpha != 0:
                    # Decrease the transparency by 0.1 until it is fully invisible
                    alpha -= .1
                    self.tw.attributes("-alpha", alpha)
                    # Call this function again in 10 milliseconds (value of self.speed attribute)
                    self.tw.after(self.speed, fade_away)
                else:
                    self.tw.destroy()
            fade_away()

@final
class ScrolledText(Text):
    """
    A Tkinter text widget with a scrollbar next to it. Code is taken from Tkinter's source code.
    """
    @exception_logged
    def __init__(self, master: Tk | Frame | LabelFrame, tooltip: Optional[str] = None, *args, **kwargs):
        try:
            self._textvariable = kwargs.pop("textvariable")
        except KeyError:
            self._textvariable = None

        # Implement the scrollbar
        self.frame = Frame(master)
        self.vbar = Scrollbar(self.frame)
        self.vbar.pack(side=RIGHT, fill=Y)
        kwargs.update({'yscrollcommand': self.vbar.set})
        super().__init__(self.frame, *args, **kwargs)
        self.pack(side=LEFT, fill=BOTH, expand=YES)
        self.vbar['command'] = self.yview
        text_meths = vars(Text).keys()
        methods = vars(Pack).keys() | vars(Grid).keys() | vars(Place).keys()
        methods = methods.difference(text_meths)

        for m in methods:
            if m[0] != '_' and m != 'config' and m != 'configure':
                setattr(self, m, getattr(self.frame, m))

        # Implement textvariable
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

        # Create the tooltip object for the widget if a string for tooltip was specified (rather than None)
        if tooltip is not None:
            self.toolTip = ToolTip(widget=self, tooltip=tooltip)
            
    @selfinjected("self")
    def __init_subclass__(cls: type, *args, **kwargs):
        raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

    @multipledispatch.dispatch(str)
    def replace(self, chars: str):
        """
        Method to replace the text in the widget entirely with the given string
        """
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete("1.0", END)
        self.insert("1.0", chars)
        self.configure(state=old_val)

    @multipledispatch.dispatch(str, str, str)
    def replace(self, chars: str, start_index: str, end_index: str):
        """
        Text class' original replace method in case the user (me) wants to replace a range of text
        """
        self.tk.call(self._w, 'replace', start_index, end_index, chars)

    @exception_logged
    def clear(self):
        """
        Method to clear all the text in the widget
        """
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete("1.0", END)
        self.configure(state=old_val)

    @exception_logged
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

@final
class Text(Text):
    @exception_logged
    def __init__(self, master: Tk | Frame | LabelFrame, tooltip: Optional[str] = None, *args, **kwargs):
        try:
            self._textvariable = kwargs.pop("textvariable")
        except KeyError:
            self._textvariable = None

        super().__init__(master, *args, **kwargs)

        # Implement textvariable
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
        
        # Create the tooltip object for the widget if a string for tooltip was specified (rather than None)
        if tooltip is not None:
            self.toolTip = ToolTip(widget=self, tooltip=tooltip)

    @selfinjected("self")
    def __init_subclass__(cls: type, *args, **kwargs):
        raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

    @multipledispatch.dispatch(str)
    def replace(self, chars: str):
        """
        Method to replace the text in the widget entirely with the given string
        """
        old_val = self["state"]
        self.configure(state=NORMAL)
        self.delete("1.0", END)
        self.insert("1.0", chars)
        self.configure(state=old_val)

    @multipledispatch.dispatch(str, str, str)
    def replace(self, chars: str, start_index: str, end_index: str):
        """
        Text class' original replace method in case the user (me) wants to replace a range of text
        """
        self.tk.call(self._w, 'replace', start_index, end_index, chars)

    @exception_logged
    def clear(self):
        """
        Method to clear all the text in the widget
        """
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
    @exception_logged
    def __init__(self, master: Tk | Frame | LabelFrame, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.bind("<<NotebookTabChanged>>", lambda _: self.on_tab_change())
        self.__history: Optional[list] = list()

    @property
    def last_tab(self) -> Optional[int]:
        """
        Property to get the index of the last tab that was selected in case an
        error occures while switching to a tab that downloads data from web and
        the program must return to the last tab
        """
        try:
            # Try to get the lastly indexed element from the history
            return self.__history[-1]
        except IndexError:
            if len(self.__history):
                return self.__history[0]
            else:
                return None

    @exception_logged
    def on_tab_change(self, event = None):
        if self.master.__class__.__name__ == Interface.__name__:
            # If the notebook we're talking about is the main notebook...
            if self.index(self.select()) == 4:
                # If the selected tab is the "About & Help" tab...
                if not hasattr(self, "HTML"):
                    # If the content isn't downloaded from web yet, downlaod it and assign the HTML to the HTML attribute so that we won't have to download it again
                    self.master.statusBar.configure(text="Status: Downloading HTML...")
                    self.master.update()
                    try:
                        request = get("https://raw.githubusercontent.com/Yilmaz4/Encrypt-n-Decrypt/main/README.md").text
                    except Exception as details:
                        messagebox.showerror("No internet connection", "Your internet connection appears to be offline. We were unable to download required content to show this page.")
                        self.master.logger.error(f"Connection to 'raw.githubusercontent.com' has failed, downloading HTML was interrupted.")
                        for line in format_exc().splitlines():
                            self.master.logger.error(" " * (len(datetime.now().strftime(r'%Y-%m-%d %H:%M:%S')) + 1) + line + "\n", format=False)
                        self.master.statusBar.configure(text="Status: Ready")
                        self.master.mainNotebook.select(self.master.mainNotebook.last_tab)
                        return
                    self.HTML = markdown(request)
                    self.master.statusBar.configure(text="Status: Ready")
                    self.master.update()
                # Re-create the widget that will show the HTML
                self.master.readmePage = HtmlFrame(self.master, messages_enabled=False, vertical_scrollbar=True)
                # Load the HTML
                self.master.readmePage.load_html(self.HTML)
                self.master.readmePage.set_zoom(0.8)
                self.master.readmePage.grid_propagate(0)
                self.master.readmePage.enable_images(1)
                self.master.readmePage.place(x=5, y=27, height=528, width=790)
            else:
                # If the selected tab is not the "About & Help" tab...
                if hasattr(self.master, "readmePage"):
                    # If the widget that shows the HTML exists, destroy it
                    try:
                        self.master.readmePage.place_forget()
                        self.master.readmePage.destroy()
                    except TclError:
                        pass
                if self.index(self.select()) == 5 and hasattr(self.master, "_sourceLoadFailure") and self.master._sourceLoadFailure:
                    # If the selected tab is the "Source Code" tab instead and there was an error while loading the source code...
                    self.master.update()
                    # Get the AppData location
                    _appdata = f"{os.getenv('APPDATA')}\\{__title__}\\"
                    try:
                        # Get the URL for downloading the source code whose version is the same as the version of the program (this would raise IndexError if version tag of this program doesn't exist in GitHub)
                        url = [release["zipball_url"] for release in get(f"https://api.github.com/repos/Yilmaz4/{__title__}/releases").json() if release["tag_name"] == f"v{__version__}"][0]
                        # Download the source code
                        src = get(url, stream=True)
                        with open(_appdata + f"source_code_v{__version__}.zip", 'wb') as file:
                            # Write the source code data to a file in AppData
                            for chunk in src.iter_content(chunk_size=512):
                                file.write(chunk)
                        # Unzip the source code to a folder
                        with ZipFile(_appdata + f"source_code_v{__version__}.zip", "r") as file:
                            file.extractall(_appdata + f"source_code_v{__version__}")
                        # Try to find the main *.py or *.pyw file in the folder
                        for filename in os.listdir(_appdata + f"source_code_v{__version__}"):
                            if os.path.isdir(_appdata + f"source_code_v{__version__}\\{filename}") and filename.startswith(__author__):
                                for _filename in os.listdir(_appdata + f"source_code_v{__version__}\\{filename}"):
                                    if os.path.splitext(_filename)[1] in [".py", ".pyw"]:
                                        with open(_appdata + f"source_code_v{__version__}\\{filename}\\{_filename}") as file:
                                            self.master.mainNotebook.sourceFrame.sourceText.replace(file.read())
                            elif os.path.splitext(filename)[1] in [".py", ".pyw"]:
                                with open(_appdata + f"source_code_v{__version__}\\{filename}") as file:
                                    self.master.mainNotebook.sourceFrame.sourceText.replace(file.read())
                        rmtree(_appdata + f"source_code_v{__version__}")
                        os.remove(_appdata + f"source_code_v{__version__}.zip")
                    except IndexError:
                        # As the error details below this comment explain, this error will pop up if the user is running the *.exe version and the version doesn't exist in the GitHub repository
                        messagebox.showerror("Source code could not be found", f"The source code of this program could not be loaded (as you're using the *.exe version) nor downloaded. This is most probably because you're using a more recent version than the latest release in GitHub repository.")
                        self.master.logger.error("Source code of this version of this program could not be found in GitHub")
                        # Print the traceback information to the logging widget
                        for line in format_exc().splitlines():
                            self.master.logger.error(" " * (len(datetime.now().strftime(r'%Y-%m-%d %H:%M:%S')) + 1) + line + "\n", format=False)
                        self.master.mainNotebook.select(self.master.mainNotebook.last_tab)
                    except (gaierror, ConnectionError, NewConnectionError, MaxRetryError):
                        # If there was any connection problem, this error will pop up
                        messagebox.showerror("No internet connection", "Your internet connection appears to be offline. We were unable to download required content to show this page.")
                        self.master.logger.error(f"Connection to 'raw.githubusercontent.com' has failed, downloading source code was interrupted.")
                        # Print the traceback information to the logging widget
                        for line in format_exc().splitlines():
                            self.master.logger.error(" " * (len(datetime.now().strftime(r'%Y-%m-%d %H:%M:%S')) + 1) + line + "\n", format=False)
                        self.master.mainNotebook.select(self.master.mainNotebook.last_tab)
                    else:
                        # If no problem has occured while downloading the source code, destroy the "Loading..." label
                        if hasattr(self.master.mainNotebook.sourceFrame, "downloadingLabel"):
                            self.master.mainNotebook.sourceFrame.downloadingLabel.place_forget()
                            del self.master.mainNotebook.sourceFrame.downloadingLabel
                        self.master._sourceLoadFailure = False
                else:
                    pass

        # Limit the last tab history to 2 tabs
        if len(self.__history) >= 2:
            del self.__history[0]
        # Add the selected tab to the history
        self.__history.append(self.index(self.select()))

class Widget(Widget):
    """
    Base-class for all the Tkinter widgets except Text and ScrolledText widgets in order to implement tooltips easily
    """
    def __init__(self, master: Tk | Frame | LabelFrame, tooltip: Optional[str] = None, *args, **kwargs):
        super().__init__(master, *args, **kwargs)

        if tooltip is not None:
            self.toolTip = ToolTip(widget=self, tooltip=tooltip)

# Multiply inherit all the widgets from the Widget class and the original Tkinter widgets in order to add tooltips to them

@final
class Entry(Widget, Entry):
    @selfinjected("self")
    def __init_subclass__(cls: type, *args, **kwargs):
        raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

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

@final
class Button(Widget, Button): ...

@final
class Label(Widget, Label): ...

@final
class Radiobutton(Widget, Radiobutton): ...

@final
class Checkbutton(Widget, Checkbutton): ...

@final
class Interface(Tk):
    """
    Main class for the user interface
    """
    @exception_logged
    def __init__(self):
        super().__init__()

        # Load either the "vista" theme (which is the default theme in Windows) or the "arc" theme depending on the operating system
        self.theme = ThemedStyle(self, gif_override=True)
        self.theme.set_theme("vista" if os.name == "nt" else "arc")

        # Create all the variables used by widgets
        self.__initialize_vars()

        # Hide the window till all the widgets are placed
        self.withdraw()

        self.height = 580
        self.width = 800
        self.version = __version__

        # Shape the window and set the title
        self.wm_title(f"{__title__} v{self.version}")
        self.wm_geometry(f"{self.width}x{self.height}")
        self.wm_resizable(width=False, height=False)
        self.wm_minsize(width = self.width, height = self.height)
        self.wm_maxsize(width = self.width, height = self.height)
        # Load the icon if it's present in the current directory
        try:
            self.wm_iconbitmap("icon.ico")
        except TclError:
            # It’s easier to ask for forgiveness than permission
            pass

        # Initialize the helper classes
        self.crypto = Cryptography(self)
        self.cache = Cache(self)
        self.utils = Utilities(self)
        self.logger: Logger = None

        # Initialize the state control functions list, in which functions that control the state/visibility
        # (either NORMAL or DISABLED) of the widgets depending on the state of radio buttons
        self.scfs: list[dict[Callable, Callable]] = []
        # The main notebook widget
        class mainNotebook(Notebook):
            def __init__(self, master: Interface):
                super().__init__(master, width=380, height=340)
                self.root: Interface = self.master

                class encryptionFrame(Frame):
                    def __init__(self, master: mainNotebook = None, **kwargs):
                        super().__init__(master=master, **kwargs)
                        self.root: Interface = self.master.master

                        self.textEntryCheck = Radiobutton(self, text="Plain text:", tooltip="Select this if you want to encrypt a short message", value=0, variable=self.root.dataSourceVar, command=self.changeDataSource, takefocus=0)
                        self.textEntry = Entry(self, width=48, font=("Consolas", 9), state=NORMAL, takefocus=0, textvariable=self.root.textEntryVar)
                        self.textPasteButton = Button(self, text="Paste", tooltip="Paste the contents of the clipboard into the entry above", width=14, state=NORMAL, command=lambda: self.textEntry.replace(str(self.root.clipboard_get())), takefocus=0)
                        self.textClearButton = Button(self, text="Clear", tooltip="Delete everything written in the above entry", width=14, command=lambda: self.textEntry.delete(0, END), takefocus=0, state=DISABLED)
                        self.textEntryHideCharCheck = Checkbutton(self, text="Hide characters", tooltip="Check this if you want the things you write in the above entry to be not visible", variable=self.root.textEntryHideCharVar, onvalue=1, offvalue=0, command=self.changeDataEntryHideChar, takefocus=0)

                        self.fileEntryCheck = Radiobutton(self, text="File(s):", value=1, variable=self.root.dataSourceVar, command=self.changeDataSource, takefocus=0)
                        self.fileValidityLabel = Label(self, text="Validity: [Blank]", cursor="hand2", foreground="gray")
                        self.fileEntry = Entry(self, width=48, font=("Consolas", 9), state=DISABLED, takefocus=0, textvariable=self.root.fileEntryVar)
                        self.fileBrowseButton = Button(self, text="Browse...", width=14, state=DISABLED, command=self.fileEntryBrowse, takefocus=0)
                        self.fileClearButton = Button(self, text="Clear", width=14, state=DISABLED, command=lambda: self.fileEntry.delete(0, END), takefocus=0)
                        self.writeFileContentCheck = Checkbutton(self, text="Write encrypted data", variable=self.root.encryptWriteFileContentVar, state=DISABLED, takefocus=0)

                        self.root.textEntryVar.trace("w", self.textEntryCallback)
                        self.root.fileEntryVar.trace("w", self.fileEntryCallback)
                        
                        self.fileValidityLabel.bind("<Button-1>", self.showDebug)

                        self.textEntryCheck.place(x=8, y=2)
                        self.textEntry.place(x=24, y=22)
                        self.textPasteButton.place(x=23, y=49)
                        self.textClearButton.place(x=124, y=49)

                        self.fileEntryCheck.place(x=8, y=76)
                        self.fileValidityLabel.place(x=63, y=77)
                        self.fileEntry.place(x=24, y=96)
                        self.fileBrowseButton.place(x=23, y=123)
                        self.fileClearButton.place(x=124, y=123)
                        self.writeFileContentCheck.place(x=236, y=124)

                        class algorithmSelect(Notebook):
                            def __init__(self, master: encryptionFrame):
                                super().__init__(master, width=355, height=290, takefocus=0)
                                self.root: encryptionFrame = self.master.master.master

                                class symmetricEncryption(Frame):
                                    def __init__(self, master: Notebook, **kwargs):
                                        super().__init__(master, **kwargs)
                                        self.root: Interface = self.master.master.master.master

                                        self.generateRandomKeyCheck = Radiobutton(self, text="Generate a random key", tooltip="Select this if you want to generate a new random encryption key", value=0, variable=self.root.keySourceSelection, command=self.master.master.changeSourceSelection, takefocus=0)

                                        self.AESAlgorithmCheck = Radiobutton(self, text="AES (Advanced Encryption Standard)", tooltip="", value=0, variable=self.root.generateAlgorithmSelection, command=self.master.master.changeAlgorithmSelection, takefocus=0)
                                        self.AES128Check = Radiobutton(self, text="AES-128 Key", value=128, variable=self.root.generateRandomAESVar, takefocus=0)
                                        self.AES192Check = Radiobutton(self, text="AES-192 Key", value=192, variable=self.root.generateRandomAESVar, takefocus=0)
                                        self.AES256Check = Radiobutton(self, text="AES-256 Key", value=256, variable=self.root.generateRandomAESVar, takefocus=0)

                                        self.DESAlgorithmCheck = Radiobutton(self, text="3DES (Triple Data Encryption Standard)", value=1, variable=self.root.generateAlgorithmSelection, command=self.master.master.changeAlgorithmSelection, takefocus=0)
                                        self.DES128Check = Radiobutton(self, text="3DES-128 Key", value=128, state=DISABLED, variable=self.root.generateRandomDESVar, takefocus=0)
                                        self.DES192Check = Radiobutton(self, text="3DES-192 Key", value=192, state=DISABLED, variable=self.root.generateRandomDESVar, takefocus=0)

                                        self.selectKeyCheck = Radiobutton(self, text="Use this key:", value=1, variable=self.root.keySourceSelection, command=self.master.master.changeSourceSelection, takefocus=0)
                                        self.keyEntry = Entry(self, width=46, font=("Consolas",9), state=DISABLED, textvariable=self.root.keyEntryVar, takefocus=0)
                                        self.keyValidityStatusLabel = Label(self, text="Validity: [Blank]", foreground="gray", takefocus=0)
                                        self.keyEntryHideCharCheck = Checkbutton(self, text="Hide characters", onvalue=1, offvalue=0, variable=self.root.keyEntryHideCharVar, command=self.keyEntryHideCharChange, state=DISABLED, takefocus=0)
                                        self.keyBrowseButton = Button(self, text="Browse key file...", width=21, state=DISABLED, command=lambda: self.root.crypto.get_key(self.root, self.keyEntry), takefocus=0)
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

                                    def keyEntryHideCharChange(self):
                                        self.keyEntry.configure(show="●" if self.root.keyEntryHideCharVar.get() else "")

                                class asymmetricEncryption(Frame):
                                    def __init__(self, master: Notebook, **kwargs):
                                        super().__init__(master, **kwargs)
                                        self.root: Interface = self.master.master.master.master

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
                                        self.keyBrowseButton = Button(self, text="Browse key file...", width=21, state=DISABLED, command=lambda: self.root.crypto.get_key(self.keyEntry.get(), self.root, self.keyEntry), takefocus=0)
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
                                self.add(self.asymmetricEncryption, text="Asymmetric Key Encryption")

                        self.algorithmSelect = algorithmSelect(self)
                        self.encryptButton = Button(self, text="Encrypt", width=22, command=self.root.crypto.encrypt, takefocus=0)

                        self.algorithmSelect.place(x=10, y=155)
                        self.encryptButton.place(x=9, y=480)

                        class outputFrame(LabelFrame):
                            def __init__(self, master: Frame):
                                super().__init__(master, text="Output", height=502, width=403, takefocus=0)
                                self.root: Interface = self.master.master.master

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

                                self.copyOutputButton = Button(self, text = "Copy", width=10, command=lambda: self.root.clipboard_set(self.outputText.get("1.0", END)), state=DISABLED, takefocus=0)
                                self.clearOutputButton = Button(self, text = "Clear", width=10, command=lambda: self.outputText.clear(), state=DISABLED, takefocus=0)
                                self.saveOutputButton = Button(self, width=15, text="Save as...", command=self.saveOutput, state=DISABLED, takefocus=0)
                                self.copyAESKeyButton = Button(self, width = 10, text="Copy", command=lambda: self.root.clipboard_set(self.AESKeyText.get("1.0", END)), state=DISABLED, takefocus=0)
                                self.clearAESKeyButton = Button(self, width = 10, text="Clear", command=lambda: self.AESKeyText.clear(), state=DISABLED, takefocus=0)
                                self.saveAESKeyButton = Button(self, width=15, text="Save as...", command=lambda: self.root.crypto.save_key(self.root.AESKeyVar.get(), self.root), state=DISABLED, takefocus=0)
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
                                path = filedialog.asksaveasfilename(title="Save encrypted data", initialfile=os.path.split(self.root.lastEncryptedFile)[1] if self.root.lastEncryptedFile is not None else "Encrypted Text.txt", filetypes=[("All files", "*.*")], defaultextension="*.txt")
                                if ''.join(path.split()) == '':
                                    return
                                with open(path, encoding="utf-8", mode="w") as file:
                                    file.write(self.root.outputVar.get())

                            def saveRSAPublic(self):
                                path = filedialog.asksaveasfilename(title="Save public key", initialfile="Public Key.txt", filetypes=[("Text document", "*.txt"), ("All files", "*.*")], defaultextension="*.txt")
                                if ''.join(path.split()) == '':
                                    return
                                with open(path, encoding="utf-8", mode="w") as file:
                                    file.write(self.root.RSAPublicVar.get())

                            def saveRSAPrivate(self):
                                path = filedialog.asksaveasfilename(title="Save private key", initialfile="Private Key.txt", filetypes=[("Text document", "*.txt"), ("All files", "*.*")], defaultextension="*.txt")
                                if ''.join(path.split()) == '':
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

                    @state_control_function(self)
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

                    @state_control_function(self)
                    def changeAlgorithmSelection(self):
                        self.changeAESState(state = DISABLED if bool(self.root.generateAlgorithmSelection.get()) else NORMAL)
                        self.changeDESState(state = NORMAL if bool(self.root.generateAlgorithmSelection.get()) else DISABLED)

                    @state_control_function(self)
                    def changeSourceSelection(self):
                        self.changeGenerateKeySectionState(state = DISABLED if bool(self.root.keySourceSelection.get()) else NORMAL)
                        self.changeAESState(state = DISABLED if bool(self.root.keySourceSelection.get()) else DISABLED if bool(self.root.generateAlgorithmSelection.get()) else NORMAL)
                        self.changeDESState(state = DISABLED if bool(self.root.keySourceSelection.get()) else NORMAL if bool(self.root.generateAlgorithmSelection.get()) else DISABLED)
                        self.changeEnterKeySectionState(state = NORMAL if bool(self.root.keySourceSelection.get()) else DISABLED)

                        if not bool(self.root.keySourceSelection.get()):
                            self.encryptButton.configure(state=NORMAL)
                            self.fileEntryCallback()
                        elif bool(self.root.keySourceSelection.get()) and (not bool(self.root.dataSourceVar.get()) or (bool(self.root.dataSourceVar.get()) and os.path.isfile(self.fileEntry.get()))):
                            self.encryptButton.configure(state=NORMAL)
                            self.limitKeyEntry()

                        if not bool(self.root.keySourceSelection.get()):
                            self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel.configure(foreground="gray")
                        else:
                            colors = {
                                "Validity: Valid": "green",
                                "Validity: Invalid": "red",
                                "Validity: [Blank]": "gray"
                            }
                            self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel.configure(foreground=colors[" ".join(self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel["text"].split()[:2])])

                    def limitKeyEntry(self, *args, **kwargs) -> None:
                        global value
                        if len(self.master.master.keyEntryVar.get()) > 32:
                            # If the entry contains 33 characters (prolly caused by a bug in Tkinter), remove the last character
                            self.master.master.keyEntryVar.set(self.master.master.keyEntryVar.get()[:32])
                        value = self.master.master.keyEntryVar.get()
                        if ''.join(str(self.master.master.keyEntryVar.get()).split()) == "":
                            # If the entry is empty, gray out the encrypt and clear buttons, and update the status text
                            self.algorithmSelect.symmetricEncryption.keyValidityStatusLabel.configure(foreground="gray", text="Validity: [Blank]")
                            self.encryptButton.configure(state=DISABLED)
                            self.algorithmSelect.symmetricEncryption.keyClearButton.configure(state=DISABLED)
                        else:
                            # If the entry actually contains something, go ahead
                            self.algorithmSelect.symmetricEncryption.keyClearButton.configure(state=NORMAL if bool(self.root.keySourceSelection.get()) else DISABLED)
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
                                self.encryptButton.configure(state=NORMAL if (not bool(self.root.dataSourceVar.get()) or (bool(self.root.dataSourceVar.get()) and os.path.isfile(self.fileEntry.get()))) else DISABLED)
                                self.fileEntryCallback()

                    @state_control_function(self)
                    def changeDataSource(self):
                        if bool(self.master.master.dataSourceVar.get()):
                            self.writeFileContentCheck.configure(state=NORMAL)
                            self.textEntry.configure(state=DISABLED)
                            self.textEntryHideCharCheck.configure(state=DISABLED)
                            self.textClearButton.configure(state=DISABLED)
                            self.textPasteButton.configure(state=DISABLED)

                            self.fileEntry.configure(state=NORMAL)
                            self.fileBrowseButton.configure(state=NORMAL)
                            if (not bool(self.root.dataSourceVar.get()) or (bool(self.root.dataSourceVar.get()) and os.path.isfile(self.fileEntry.get()))):
                                self.fileClearButton.configure(state=NORMAL)
                                self.encryptButton.configure(state=NORMAL)
                            else:
                                self.fileClearButton.configure(state=DISABLED)
                                self.encryptButton.configure(state=DISABLED)
                            self.root.mainNotebook.encryptionFrame.algorithmSelect.tab(1, state=DISABLED)
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
                            # self.root.mainNotebook.encryptionFrame.algorithmSelect.tab(1, state=NORMAL)
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
                        filePath = filedialog.askopenfilenames(title = "Open a file to encrypt", filetypes=[("All files", "*.*")])

                        if not filePath:
                            return
                        self.fileEntry.replace(' | '.join(filePath))

                    def textEntryCallback(self, *args, **kwargs):
                        self.textClearButton.configure(state=DISABLED if self.master.master.textEntryVar.get() == "" else NORMAL)
                    
                    def fileEntryCallback(self, *args, **kwargs):
                        self.fileClearButton.configure(state=DISABLED if ''.join(self.fileEntry.get().split()) != '' else NORMAL)
                        if ''.join(self.fileEntry.get().split()) != '':
                            all_valid = all([os.path.isfile(filename) for filename in [filename.lstrip() for filename in self.fileEntry.get().split('|') if ''.join(filename.split()) != '']])
                            self.fileValidityLabel.configure(**{"text": f"Selection: {len([f.lstrip() for f in self.fileEntry.get().split('|') if ''.join(f.split()) != ''])} file{'s' if len([f.lstrip() for f in self.fileEntry.get().split('|') if ''.join(f.split()) != '']) != 1 else ''} selected", "foreground": "green" if all_valid else "red"})
                        else:
                            self.fileValidityLabel.configure(text="Selection: [Blank]", foreground="gray")
                        self.encryptButton.configure(state=DISABLED if ''.join(self.fileEntry.get().split()) == '' else NORMAL if (not bool(self.root.dataSourceVar.get()) or (bool(self.root.dataSourceVar.get()) and all_valid and (not bool(self.root.keySourceSelection.get()) or (bool(self.root.keySourceSelection.get()) and ''.join(self.root.mainNotebook.encryptionFrame.algorithmSelect.symmetricEncryption.keyEntry.get().split()) != '')))) else DISABLED)
                    
                    def showDebug(self, event=None):
                        class debugWindow(Toplevel):
                            def __init__(self, master: encryptionFrame, root: Interface):
                                self.root = root
                                self.height = 200
                                self.width = 400
                                super().__init__(master, height=self.height, width=self.width)
                                self.grab_set()

                                self.wm_title("Encrypt-n-Decrypt File Selection Debugging")
                                self.wm_resizable(height=False, width=False)
                                self.wm_attributes("-fullscreen", False)
                                self.wm_maxsize(self.width, self.height)
                                self.wm_minsize(self.width, self.height)
                                try:
                                    self.wm_iconbitmap("icon.ico")
                                except TclError:
                                    pass

                                tree = Treeview(self, columns=('file', 'status'), show='headings', selectmode="browse")

                                tree.heading('file', text='File path', anchor=CENTER)
                                tree.heading('status', text='Status', anchor=CENTER)

                                messages: dict[int, dict[str, str]] = {
                                    0: {"text": "All permissions granted", "foreground": "green"},
                                    1: {"text": "Read & write accesses were denied", "foreground": "red"},
                                    2: {"text": "Write access was denied", "foreground": "#c6832a"},
                                    3: {"text": "Not a file", "foreground": "red"}
                                }
                                try:
                                    for file, status in {[file.lstrip() for file in self.master.fileEntry.get().split('|')][index]: severity for severity, index in zip(self.master.fileSelectionResult, range(len(self.master.fileSelectionResult)))}.items():
                                        tree.insert('', END, values=(file.replace(os.path.commonprefix([file for file in [file.lstrip() for file in self.master.fileEntry.get().split('|')]])[:-10], "..."), messages[status]["text"]))
                                except AttributeError:
                                    pass

                                scrollbar = Scrollbar(self, orient=VERTICAL, command=tree.yview)
                                tree.configure(yscroll=scrollbar.set)
                                tree.place(x=0, y=0, width=384)
                                scrollbar.place(x=384, y=0, height=200)
                                
                                self.focus_force()
                                self.mainloop()
                        self.debugWindow = debugWindow(self, self.root)

                class decryptionFrame(Frame):
                    def __init__(self, master: Notebook = None, **kwargs):
                        super().__init__(master=master, **kwargs)
                        self.root: Interface = self.master.master

                        self.textDecryptRadio = Radiobutton(self, text = "Cipher text:", value=0, variable=self.root.decryptSourceVar, command=self.changeDecryptSource, takefocus=0)
                        self.textDecryptValidityLabel = Label(self, text="Validity: [Blank]", foreground="gray")
                        self.textDecryptEntry = ScrolledText(self, width=105, height=5, font=("Consolas", 9), textvariable=self.root.textDecryptVar, bg="white", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1)
                        self.textDecryptPasteButton = Button(self, width=15, text="Paste", command=lambda: self.textDecryptEntry.replace(self.root.clipboard_get()), takefocus=0)
                        self.textDecryptClearButton = Button(self, width=15, text="Clear", command=lambda: self.textDecryptEntry.delete("1.0", END), takefocus=0, state=DISABLED)

                        self.fileDecryptRadio = Radiobutton(self, text = "File(s):", value=1, variable=self.root.decryptSourceVar, command=self.changeDecryptSource, takefocus=0)
                        self.fileDecryptEntry = Entry(self, width=107, font=("Consolas", 9), textvariable=self.root.fileDecryptVar, state=DISABLED, takefocus=0)
                        self.fileDecryptBrowseButton = Button(self, width=15, text="Browse...", state=DISABLED, command=self.decryptBrowseFile, takefocus=0)
                        self.fileDecryptClearButton = Button(self, width=15, text="Clear", state=DISABLED, command=lambda: self.fileDecryptEntry.delete(0, END), takefocus=0)

                        self.textDecryptRadio.place(x=8, y=2)
                        self.textDecryptValidityLabel.place(x=92, y=3)
                        self.textDecryptEntry.place(x=24, y=24)
                        self.textDecryptPasteButton.place(x=23, y=107)
                        self.textDecryptClearButton.place(x=130, y=107)

                        self.fileDecryptRadio.place(x=8, y=132)
                        self.fileDecryptEntry.place(x=24, y=153)
                        self.fileDecryptBrowseButton.place(x=23, y=182)
                        self.fileDecryptClearButton.place(x=130, y=182)

                        class algorithmSelect(Notebook):
                            def __init__(self, master: encryptionFrame):
                                super().__init__(master, width=764, height=160, takefocus=0)
                                self.root: encryptionFrame = self.master.master.master

                                class symmetricDecryption(Frame):
                                    def __init__(self, master: Notebook, **kwargs):
                                        super().__init__(master, **kwargs)
                                        self.root: Interface = self.master.master.master.master

                                        class decryptAlgorithmFrame(LabelFrame):
                                            def __init__(self, master: symmetricDecryption, **kwargs):
                                                super().__init__(master, **kwargs)
                                                self.root: Interface = self.master.master.master.master.master

                                                self.decryptAESCheck = Radiobutton(self, text="AES (Advanced Encryption Standard)", value=0, variable=self.root.decryptAlgorithmVar, takefocus=0)
                                                self.decryptDESCheck = Radiobutton(self, text="3DES (Triple Data Encryption Standard)", value=1, variable=self.root.decryptAlgorithmVar, takefocus=0)

                                                self.decryptAESCheck.place(x=5, y=0)
                                                self.decryptDESCheck.place(x=5, y=19)

                                        self.decryptAlgorithmFrame = decryptAlgorithmFrame(self, text="Select algorithm", height=63, width=749, takefocus=0)
                                        self.decryptAlgorithmFrame.place(x=8, y=2)

                                        class decryptKeyFrame(LabelFrame):
                                            def __init__(self, master: symmetricDecryption, **kwargs):
                                                super().__init__(master, **kwargs)
                                                self.root: Interface = self.master.master.master.master.master

                                                self.decryptKeyEntry = Entry(self, width=103, font=("Consolas", 9), textvariable=self.root.decryptKeyVar, takefocus=0)
                                                self.decryptKeyBrowseButton = Button(self, width=21, text="Browse key file...", command=lambda: self.root.crypto.get_key(self.root, self.decryptKeyEntry), takefocus=0)
                                                self.decryptKeyPasteButton = Button(self, width=15, text="Paste", takefocus=0, command=lambda: self.decryptKeyEntry.replace(self.root.clipboard_get()))
                                                self.decryptKeyClearButton = Button(self, width=15, text="Clear", takefocus=0, command=lambda: self.decryptKeyEntry.delete(0, END), state=DISABLED)

                                                self.decryptKeyEntry.place(x=9, y=3)
                                                self.decryptKeyBrowseButton.place(x=601, y=30)
                                                self.decryptKeyPasteButton.place(x=8, y=30)
                                                self.decryptKeyClearButton.place(x=115, y=30)

                                                self.root.decryptKeyVar.trace("w", self.decryptLimitKeyEntry)
                                                self.root.decryptOutputVar.trace("w", self.decryptOutputCallback)

                                            def decryptLimitKeyEntry(self, *args, **kwargs):
                                                global value
                                                if len(self.root.decryptKeyVar.get()) > 32:
                                                    self.root.decryptKeyVar.set(self.root.decryptKeyVar.get()[:32])
                                                value = self.root.decryptKeyVar.get()
                                                if ''.join(str(self.root.decryptKeyVar.get()).split()) == "":
                                                    self.decryptKeyClearButton.configure(state=DISABLED)
                                                else:
                                                    self.decryptKeyClearButton.configure(state=NORMAL)
                                                if len(value) == 0:
                                                    self.master.master.master.decryptButton.configure(state=DISABLED)
                                                else:
                                                    cond = bool(self.root.decryptAlgorithmVar.get())
                                                    iv = get_random_bytes(AES.block_size if not cond else DES3.block_size)
                                                    try:
                                                        if not cond:
                                                            AES.new(bytes(value, 'utf-8'), mode=AES.MODE_OFB, iv=iv)
                                                        else:
                                                            DES3.new(bytes(value, 'utf-8'), mode=DES3.MODE_OFB, iv=iv)
                                                    except:
                                                        self.master.master.master.decryptButton.configure(state=DISABLED)
                                                    else:
                                                        if not bool(self.root.decryptSourceVar.get()):
                                                            try:
                                                                if ''.join(self.master.master.master.textDecryptEntry.get("1.0", END).split()) != "" and base64.urlsafe_b64encode(base64.urlsafe_b64decode(self.master.master.master.textDecryptEntry.get("1.0", END).encode("utf-8"))) == self.master.master.master.textDecryptEntry.get("1.0", END).rstrip().encode("utf-8"):
                                                                    self.master.master.master.decryptButton.configure(state=NORMAL)
                                                                else:
                                                                    self.master.master.master.decryptButton.configure(state=DISABLED)
                                                            except binascii.Error:
                                                                self.master.master.master.decryptButton.configure(state=DISABLED)
                                                        else:
                                                            if self.master.master.master.fileDecryptCallback():
                                                                self.master.master.master.decryptButton.configure(state=NORMAL)
                                                            else:
                                                                self.master.master.master.decryptButton.configure(state=DISABLED)

                                            def decryptOutputCallback(self, *args, **kwargs):
                                                if not ''.join(str(self.root.decryptOutputVar.get()).split()) == "":
                                                    self.master.master.master.decryptClearButton.configure(state=NORMAL)
                                                    self.master.master.master.decryptCopyButton.configure(state=NORMAL)
                                                    self.master.master.master.decryptSaveButton.configure(state=NORMAL)
                                                else:
                                                    self.master.master.master.decryptClearButton.configure(state=DISABLED)
                                                    self.master.master.master.decryptCopyButton.configure(state=DISABLED)
                                                    self.master.master.master.decryptSaveButton.configure(state=DISABLED)

                                        self.decryptKeyFrame = decryptKeyFrame(self, text="Enter encryption key", height=84, width=749, takefocus=0)
                                        self.decryptKeyFrame.place(x=8, y=68)
                                        self.decryptKeyValidity = Label(self, text="Validity: [Blank]", foreground="gray")

                                class asymmetricDecryption(Frame):
                                    def __init__(self, master: Notebook, **kwargs):
                                        super().__init__(master, **kwargs)
                                        self.root: Interface = self.master.master.master.master

                                        
                                self.symmetricDecryption = symmetricDecryption(self)
                                self.asymmetricDecryption = asymmetricDecryption(self)

                                self.add(self.symmetricDecryption, text="Symmetric Key Decryption")
                                self.add(self.asymmetricDecryption, text="Asymmetric Key Decryption", state=DISABLED)

                        self.algorithmSelect = algorithmSelect(self)
                        self.algorithmSelect.place(x=10, y=215)
                        
                        self.decryptButton = Button(self, width=22, text="Decrypt", command=self.root.crypto.decrypt, takefocus=0, state=DISABLED)
                        self.decryptOutputFrame = LabelFrame(self, text="Decrypted text", height=84, width=766, takefocus=0)
                        self.decryptOutputText = Entry(self.decryptOutputFrame, width=105, font=("Consolas", 9), state=DISABLED, textvariable=self.master.master.decryptOutputVar, takefocus=0)
                        self.decryptCopyButton = Button(self.decryptOutputFrame, text="Copy", width=17, command=lambda: self.root.clipboard_set(self.root.self.lastDecryptionResult), takefocus=0, state=DISABLED)
                        self.decryptClearButton = Button(self.decryptOutputFrame, text="Clear", width=17, command=lambda: self.decryptOutputText.clear(), takefocus=0, state=DISABLED)
                        self.decryptSaveButton = Button(self.decryptOutputFrame, text="Save as...", width=20, takefocus=0, state=DISABLED)

                        self.root.textDecryptVar.trace("w", self.textDecryptCallback)
                        self.root.fileDecryptVar.trace("w", self.fileDecryptCallback)
                        
                        self.decryptButton.place(x=9, y=406)
                        self.decryptOutputFrame.place(x=10, y=435)
                        self.decryptOutputText.place(x=10, y=3)
                        self.decryptCopyButton.place(x=9, y=30)
                        self.decryptClearButton.place(x=128, y=30)
                        self.decryptSaveButton.place(x=622, y=30)

                    @state_control_function(self)
                    def changeDecryptSource(self):
                        if not bool(self.root.decryptSourceVar.get()):
                            self.textDecryptEntry.configure(state=NORMAL, bg="white", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1, highlightcolor="#7a7a7a", foreground="black")
                            self.textDecryptPasteButton.configure(state=NORMAL)
                            self.textDecryptClearButton.configure(state=NORMAL)
                            self.fileDecryptEntry.configure(state=DISABLED)
                            self.fileDecryptBrowseButton.configure(state=DISABLED)
                            self.fileDecryptClearButton.configure(state=DISABLED)
                            if not ''.join(str(self.textDecryptEntry.get("1.0", END)).split()) == "":
                                try:
                                    if base64.urlsafe_b64encode(base64.urlsafe_b64decode(self.textDecryptEntry.get("1.0", END).encode("utf-8"))) == self.textDecryptEntry.get("1.0", END).rstrip().encode("utf-8"):
                                        self.textDecryptValidityLabel.configure(text="Validity: Valid base64 encoded data", foreground="green")
                                        self.decryptButton.configure(state=NORMAL if ''.join(self.algorithmSelect.symmetricDecryption.decryptKeyFrame.decryptKeyEntry.get().split()) != '' else DISABLED)
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
                            self.textDecryptEntry.configure(state=DISABLED, bg="#F0F0F0", relief=FLAT, takefocus=0, highlightbackground="#cccccc", highlightthickness=1, highlightcolor="#cccccc", foreground="gray")
                            self.textDecryptPasteButton.configure(state=DISABLED)
                            self.textDecryptClearButton.configure(state=DISABLED)
                            self.fileDecryptEntry.configure(state=NORMAL)
                            self.fileDecryptBrowseButton.configure(state=NORMAL)
                            self.fileDecryptClearButton.configure(state=NORMAL)
                            if os.path.isfile(self.fileDecryptEntry.get()):
                                self.decryptButton.configure(state=NORMAL if ''.join(self.algorithmSelect.symmetricDecryption.decryptKeyFrame.decryptKeyEntry.get().split()) != '' else DISABLED)
                            else:
                                self.decryptButton.configure(state=DISABLED)
                        self.algorithmSelect.symmetricDecryption.decryptKeyFrame.decryptLimitKeyEntry()

                    def textDecryptCallback(self, *args, **kwargs):
                        if not ''.join(str(self.textDecryptEntry.get("1.0", END)).split()) == "":
                            try:
                                if base64.urlsafe_b64encode(base64.urlsafe_b64decode(self.textDecryptEntry.get("1.0", END).encode("utf-8"))) == self.textDecryptEntry.get("1.0", END).rstrip().encode("utf-8"):
                                    self.textDecryptValidityLabel.configure(text="Validity: Valid base64 encoded data", foreground="green")
                                    self.decryptButton.configure(state=NORMAL)
                                    self.algorithmSelect.symmetricDecryption.decryptKeyFrame.decryptLimitKeyEntry()
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
                        self.fileDecryptClearButton.configure(state=DISABLED if ''.join(self.fileDecryptEntry.get().split()) != '' else NORMAL)
                        if ''.join(self.fileDecryptEntry.get().split()) != '':
                            all_valid = all([os.path.isfile(filename) for filename in [filename.lstrip() for filename in self.fileDecryptEntry.get().split('|') if ''.join(filename.split()) != '']])
                            #self.fileValidityLabel.configure(**{"text": f"Selection: {len([f.lstrip() for f in self.fileEntry.get().split('|') if ''.join(f.split()) != ''])} file{'s' if len([f.lstrip() for f in self.fileEntry.get().split('|') if ''.join(f.split()) != '']) != 1 else ''} selected", "foreground": "green" if all_valid else "red"})
                        else:
                            pass
                            #self.fileValidityLabel.configure(text="Selection: [Blank]", foreground="gray")
                        return_res = {
                            DISABLED: False,
                            NORMAL: True
                        }
                        state = DISABLED if ''.join(self.fileDecryptEntry.get().split()) == '' else NORMAL if (
                            not bool(self.root.dataSourceVar.get()) or (bool(self.root.dataSourceVar.get()) and all_valid and (
                                ''.join(self.root.mainNotebook.decryptionFrame.algorithmSelect.symmetricDecryption.decryptKeyFrame.decryptKeyEntry.get().split()) != ''
                            ))
                        ) else DISABLED
                                
                        self.decryptButton.configure(state=state)
                        return return_res[state]

                    def decryptBrowseFile(self):
                        filePath = filedialog.askopenfilenames(title = "Open a file to decrypt", filetypes=[("All files","*.*")])
                        if not filePath:
                            return
                        self.fileDecryptEntry.replace(' | '.join(filePath))

                class miscFrame(Frame):
                    def __init__(self, master: mainNotebook = None):
                        super().__init__(master=master)
                        self.root: Interface = self.master.master

                        class base64Frame(LabelFrame):
                            def __init__(self, master: Frame = None):
                                super().__init__(master=master, height=382, width=405, text="Base64 Encoder & Decoder")
                                self.root: Interface = self.master.master.master

                                self.base64_plainRadiobutton = Radiobutton(self, text="Plain text:", value=0, variable=self.root.base64SourceVar, command=self.base64_changeSourceSelection, takefocus=0)
                                self.base64_plainEntry = Entry(self, width=52, font=("Consolas", 10), textvariable=self.root.base64InputVar, takefocus=0)
                                self.base64_plainValidity = Label(self, text="Validity: [Blank]", foreground="gray")
                                self.base64_plainClearButton = Button(self, width=15, text="Clear", command=self.base64_plainEntry.clear, state=DISABLED, takefocus=0)
                                self.base64_plainPasteButton = Button(self, width=15, text="Paste", command=lambda: self.base64_plainEntry.replace(self.root.clipboard_get()), takefocus=0)

                                self.base64_fileRadiobutton = Radiobutton(self, text="File:", value=1, variable=self.root.base64SourceVar, command=self.base64_changeSourceSelection, takefocus=0)
                                self.base64_fileValidity = Label(self, text="Validity: [Blank]", foreground="gray", state=DISABLED)
                                self.base64_fileEntry = Entry(self, width=52, font=("Consolas", 10), textvariable=self.root.base64FileEntryVar, takefocus=0, state=DISABLED)
                                self.base64_fileClearButton = Button(self, width=15, text="Clear", command=self.base64_plainEntry.clear, takefocus=0, state=DISABLED)
                                self.base64_fileBrowseButton = Button(self, width=15, text="Browse...", command=self.base64_browseFile, takefocus=0, state=DISABLED)

                                class operationFrame(LabelFrame):
                                    def __init__(self, master: LabelFrame = None):
                                        super().__init__(master=master, height=65, width=382, text="Operation")
                                        self.root = self.master.master.master.master

                                        self.encodeRadiobutton = Radiobutton(self, text="Encode", value=0, variable=self.root.encodeOrDecodeVar, command=self.master.base64_inputCallback, takefocus=0)
                                        self.decodeRadiobutton = Radiobutton(self, text="Decode", value=1, variable=self.root.encodeOrDecodeVar, command=self.master.base64_inputCallback, takefocus=0)

                                        self.encodeRadiobutton.place(x=10, y=0)
                                        self.decodeRadiobutton.place(x=10, y=21)

                                self.base64_outputLabel = Label(self, text="Output", takefocus=0)
                                self.base64_outputText = ScrolledText(self, height=4, width=45, textvariable=self.root.base64OutputVar, state=DISABLED, bg="white", relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1)
                                self.base64_outputClearButton = Button(self, width=15, text="Clear", command=self.base64_outputText.clear, state=DISABLED, takefocus=0)
                                self.base64_outputCopyButton = Button(self, width=15, text="Copy", command=lambda: self.root.clipboard_set(self.base64_outputText.get("1.0", END)[:-1 if self.base64_outputText.get("1.0", END).endswith("\n") else 0]), state=DISABLED, takefocus=0)

                                self.root.base64InputVar.trace("w", self.base64_inputCallback)
                                self.root.base64FileEntryVar.trace("w", self.base64_fileEntryCallback)
                                self.root.base64OutputVar.trace("w", self.base64_outputCallback)

                                self.base64_plainRadiobutton.place(x=7, y=0)
                                self.base64_plainEntry.place(x=25, y=22)
                                self.base64_plainValidity.place(x=82, y=1)
                                self.base64_plainClearButton.place(x=131, y=49)
                                self.base64_plainPasteButton.place(x=24, y=49)
                                
                                self.base64_fileRadiobutton.place(x=7, y=78)
                                self.base64_fileEntry.place(x=25, y=100)
                                self.base64_fileClearButton.place(x=131, y=127)
                                self.base64_fileBrowseButton.place(x=24, y=127)

                                self.base64_operationFrame = operationFrame(self)
                                self.base64_operationFrame.place(x=10, y=159)
                                
                                self.base64_outputLabel.place(x=7, y=227)
                                self.base64_outputText.place(x=10, y=249)
                                self.base64_outputClearButton.place(x=116, y=325)
                                self.base64_outputCopyButton.place(x=9, y=325)

                            def base64_changeSourceSelection(self):
                                if not bool(self.root.base64SourceVar.get()):
                                    self.base64_plainEntry.configure(state=NORMAL)
                                    self.base64_plainClearButton.configure(state=NORMAL if ''.join(self.base64_plainEntry.get()) != '' else DISABLED)
                                    self.base64_plainPasteButton.configure(state=NORMAL)
                                    
                                    self.base64_fileEntry.configure(state=DISABLED)
                                    self.base64_fileClearButton.configure(state=DISABLED)
                                    self.base64_fileBrowseButton.configure(state=DISABLED)
                                    self.base64_inputCallback()
                                else:
                                    self.base64_plainEntry.configure(state=DISABLED)
                                    self.base64_plainClearButton.configure(state=DISABLED)
                                    self.base64_plainPasteButton.configure(state=DISABLED)
                                    
                                    self.base64_fileEntry.configure(state=NORMAL)
                                    self.base64_fileClearButton.configure(state=NORMAL if ''.join(self.base64_fileEntry.get()) != '' else DISABLED)
                                    self.base64_fileBrowseButton.configure(state=NORMAL)
                                    self.base64_fileEntryCallback()

                            def base64_browseFile(self):
                                filePath = filedialog.askopenfilename(title=f"Open a file to {'encode' if not bool(self.root.encodeOrDecodeVar.get()) else 'decode'}", filetypes=[("All files", "*.*")])
                                if ''.join(filePath.split()) != '':
                                    self.base64_fileEntry.replace(filePath)

                            def base64_inputCallback(self, *args, **kwargs):
                                if ''.join(self.base64_plainEntry.get().split()) != "":
                                    self.base64_plainClearButton.configure(state=NORMAL)
                                else:
                                    self.base64_plainClearButton.configure(state=DISABLED)
                                if not bool(self.root.encodeOrDecodeVar.get()) and ''.join(self.base64_plainEntry.get().split()) != "":
                                    self.base64_plainValidity.configure(text="Validity: Encodable", foreground="green")
                                    self.base64_outputText.replace(base64.urlsafe_b64encode(self.base64_plainEntry.get().encode("utf-8")).decode("utf-8"))
                                    self.base64_outputText.configure(foreground="black")
                                elif bool(self.root.encodeOrDecodeVar.get()) and ''.join(self.base64_plainEntry.get().split()) != "":
                                    try:
                                        if base64.urlsafe_b64encode(base64.urlsafe_b64decode(self.base64_plainEntry.get().encode("utf-8")).decode("utf-8").encode("utf-8")) == self.base64_plainEntry.get().rstrip().encode("utf-8"):
                                            self.base64_plainValidity.configure(text="Validity: Valid base64 encoded data", foreground="green")
                                            self.base64_outputText.replace(base64.urlsafe_b64decode(self.base64_plainEntry.get().encode("utf-8")).decode("utf-8"))
                                            self.base64_outputText.configure(foreground="black")
                                        else:
                                            self.base64_plainValidity.configure(text="Validity: Invalid", foreground="red")
                                            self.base64_outputText.configure(foreground="gray")
                                    except binascii.Error as ExceptionDetails:
                                        self.base64_plainValidity.configure(text=f"Validity: {'Incorrect padding' if 'padding' in str(ExceptionDetails) else 'Invalid'}", foreground="red")
                                        self.base64_outputText.configure(foreground="gray")
                                    except UnicodeDecodeError:
                                        self.base64_plainValidity.configure(text="Validity: Unknown encoding", foreground="red")
                                        self.base64_outputText.configure(foreground="gray")
                                else:
                                    self.base64_plainValidity.configure(text="Validity: [Blank]", foreground="gray")
                                    self.base64_outputText.clear()

                            def base64_fileEntryCallback(self, *args, **kwargs):
                                if ''.join(self.base64_fileEntry.get().split()) != '':
                                    self.base64_fileClearButton.configure(state=NORMAL)
                                    if os.path.isfile(self.base64_fileEntry.get()):
                                        try:
                                            with open(self.base64_fileEntry.get(), mode="rb") as file:
                                                self.base64_outputText.replace(base64.urlsafe_b64encode(file.read()).decode("utf-8"))
                                        except Exception as exc:
                                            print(exc)
                                else:
                                    self.base64_fileClearButton.configure(state=DISABLED)

                            def base64_outputCallback(self, *args, **kwargs):
                                if ''.join(self.base64_outputText.get("1.0", END).split()) != "":
                                    self.base64_outputClearButton.configure(state=NORMAL)
                                    self.base64_outputCopyButton.configure(state=NORMAL)
                                else:
                                    self.base64_outputClearButton.configure(state=DISABLED)
                                    self.base64_outputCopyButton.configure(state=DISABLED)

                        class keyDerivationFrame(LabelFrame):
                            def __init__(self, master: miscFrame):
                                super().__init__(master=master, height=150, width=354, text="Key Derivation Function (KDF)")
                                self.root: Interface = self.master.master.master

                                self.kdf_keyInputLabel = Label(self, text="Input", takefocus=0)
                                self.kdf_keyInputValidity = Label(self, text="Validity: [Blank]", foreground="gray")
                                self.kdf_keyInputEntry = Entry(self, width=46, font=("Consolas", 10), textvariable=self.root.keyInputVar, takefocus=0)
                                self.kdf_keyInputHideCheck = Checkbutton(self, text="Hide characters", takefocus=0, onvalue=1, offvalue=0, variable=self.root.keyInputHideVar, command=lambda: self.kdf_keyInputEntry.configure(show="●" if bool(self.root.keyInputHideVar.get()) else ""))
                                self.kdf_inputClearButton = Button(self, width=15, text="Clear", command=self.kdf_keyInputEntry.clear, state=DISABLED, takefocus=0)
                                self.kdf_inputPasteButton = Button(self, width=15, text="Paste", command=lambda: self.kdf_keyInputEntry.replace(self.root.clipboard_get()), takefocus=0)

                                self.kdf_keyOutputLabel = Label(self, text="Output (Derived Key)", takefocus=0)
                                self.kdf_keyOutputEntry = Entry(self, width=34, state="readonly", font=("Consolas", 10), textvariable=self.root.keyOutputVar, takefocus=0)
                                self.kdf_outputCopyButton = Button(self, text="Copy", state=DISABLED, command=lambda: self.root.clipboard_set(self.root.keyOutputVar.get()), takefocus=0)

                                self.root.keyInputVar.trace("w", self.kdf_keyInputCallback)
                                self.root.keyOutputVar.trace("w", lambda *args, **kwargs: self.kdf_outputCopyButton.configure(state=NORMAL if ''.join(self.kdf_keyOutputEntry.get().split()) != '' else DISABLED))

                                self.kdf_keyInputLabel.place(x=8, y=0)
                                self.kdf_keyInputValidity.place(x=43, y=0)
                                self.kdf_keyInputHideCheck.place(x=236, y=49)
                                self.kdf_keyInputEntry.place(x=10, y=22)
                                self.kdf_inputClearButton.place(x=117, y=48)
                                self.kdf_inputPasteButton.place(x=10, y=48)

                                self.kdf_keyOutputLabel.place(x=8, y=75)
                                self.kdf_keyOutputEntry.place(x=10, y=97)
                                self.kdf_outputCopyButton.place(x=262, y=95)

                            def kdf_keyInputCallback(self, *args, **kwargs):
                                if ''.join(self.kdf_keyInputEntry.get().split()) != "":
                                    self.kdf_inputClearButton.configure(state=NORMAL)
                                    try:
                                        result = self.root.crypto.derivate_key(self.kdf_keyInputEntry.get()).decode("utf-8")
                                    except:
                                        self.kdf_keyInputValidity.configure(text="Validity: Underivative", foreground="red")
                                        self.kdf_keyOutputEntry.configure(foreground="gray")
                                    else:
                                        self.kdf_keyInputValidity.configure(text="Validity: Derivative", foreground="green")
                                        self.kdf_keyOutputEntry.replace(result)
                                        self.kdf_keyOutputEntry.configure(foreground="black")
                                else:
                                    self.kdf_inputClearButton.configure(state=DISABLED)
                                    self.kdf_keyOutputEntry.clear()
                                    self.kdf_keyInputValidity.configure(text="Validity: [Blank]", foreground="gray")

                        class hashDigestFrame(LabelFrame):
                            def __init__(self, master: miscFrame):
                                super().__init__(master, height=363, width=354, text="Hash Calculator")
                                self.root: Interface = self.master.master.master
                                
                                self._last_file: dict = {"path": None, "size": None}
                                self.hash = self.root.crypto.hash

                                self.hash_plainRadiobutton = Radiobutton(self, text="Plain text:", value=0, variable=self.root.hashCalculationSourceVar, command=self.hash_changeSourceSelection, takefocus=0)
                                self.hash_plainEntry = Entry(self, width=44, font=("Consolas", 10), textvariable=self.root.hashPasswordEntryVar, takefocus=0)
                                self.hash_plainClearButton = Button(self, width=15, text="Clear", command=self.hash_plainEntry.clear, state=DISABLED, takefocus=0)
                                self.hash_plainPasteButton = Button(self, width=15, text="Paste", command=lambda: self.hash_plainEntry.replace(self.root.clipboard_get()), takefocus=0)

                                self.hash_fileRadiobutton = Radiobutton(self, text="File:", value=1, variable=self.root.hashCalculationSourceVar, command=self.hash_changeSourceSelection, takefocus=0)
                                self.hash_fileValidity = Label(self, text="Validity: [Blank]", foreground="gray", state=DISABLED)
                                self.hash_fileEntry = Entry(self, width=44, font=("Consolas", 10), textvariable=self.root.hashFileEntryVar, takefocus=0, state=DISABLED)
                                self.hash_fileClearButton = Button(self, width=15, text="Clear", command=self.hash_plainEntry.clear, takefocus=0, state=DISABLED)
                                self.hash_fileBrowseButton = Button(self, width=15, text="Browse...", command=self.browseFile, takefocus=0, state=DISABLED)

                                self.SHA1Label = Label(self, text="SHA-1")
                                self.SHA1Entry = Entry(self, width=34, font=("Consolas", 10), state="readonly", takefocus=0)
                                self.SHA1CopyButton = Button(self, text="Copy", state=DISABLED, command=lambda: self.root.clipboard_set(self.SHA1Entry.get()), takefocus=0)
                                self.SHA256Label = Label(self, text="SHA-256")
                                self.SHA256Entry = Entry(self, width=34, font=("Consolas", 10), state="readonly", takefocus=0)
                                self.SHA256CopyButton = Button(self, text="Copy", state=DISABLED, command=lambda: self.root.clipboard_set(self.SHA256Entry.get()), takefocus=0)
                                self.SHA512Label = Label(self, text="SHA-512")
                                self.SHA512Entry = Entry(self, width=34, font=("Consolas", 10), state="readonly", takefocus=0)
                                self.SHA512CopyButton = Button(self, text="Copy", state=DISABLED, command=lambda: self.root.clipboard_set(self.SHA512Entry.get()), takefocus=0)
                                self.MD5Label = Label(self, text="MD-5")
                                self.MD5Entry = Entry(self, width=34, font=("Consolas", 10), state="readonly", takefocus=0)
                                self.MD5CopyButton = Button(self, text="Copy", state=DISABLED, command=lambda: self.root.clipboard_set(self.MD5Entry.get()), takefocus=0)

                                self.root.hashPasswordEntryVar.trace("w", self.hash_passwordEntryCallback)
                                self.root.hashFileEntryVar.trace("w", self.hash_fileEntryCallback)

                                self.hash_plainRadiobutton.place(x=7, y=0)
                                self.hash_plainEntry.place(x=22, y=22)
                                self.hash_plainClearButton.place(x=129, y=48)
                                self.hash_plainPasteButton.place(x=22, y=48)

                                self.hash_fileRadiobutton.place(x=8, y=76)
                                self.hash_fileValidity.place(x=52, y=77)
                                self.hash_fileEntry.place(x=23, y=99)
                                self.hash_fileClearButton.place(x=130, y=125)
                                self.hash_fileBrowseButton.place(x=23, y=125)

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

                            @state_control_function(self)
                            def hash_changeSourceSelection(self):
                                if bool(self.root.hashCalculationSourceVar.get()):
                                    self.hash_fileValidity.configure(state=NORMAL)
                                    self.hash_fileEntry.configure(state=NORMAL)
                                    if ''.join(self.hash_fileEntry.get()) != '':
                                        self.hash_fileClearButton.configure(state=NORMAL)
                                        if os.path.isfile(self.hash_fileEntry.get()):
                                            self.hash(self.hash_fileEntry.get(), self.SHA1Entry, self.SHA256Entry, self.SHA512Entry, self.MD5Entry)
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
                                        self.hash_fileClearButton.configure(state=DISABLED)
                                        self.hash_plainClearButton.configure(state=DISABLED)
                                        self.SHA1Entry.configure(foreground="gray")
                                        self.SHA256Entry.configure(foreground="gray")
                                        self.SHA512Entry.configure(foreground="gray")
                                        self.MD5Entry.configure(foreground="gray")
                                    self.hash_fileBrowseButton.configure(state=NORMAL)

                                    self.hash_plainEntry.configure(state=DISABLED)
                                    self.hash_plainClearButton.configure(state=DISABLED)
                                    self.hash_plainPasteButton.configure(state=DISABLED)
                                else:
                                    self.hash_fileValidity.configure(state=DISABLED)
                                    self.hash_fileEntry.configure(state=DISABLED)
                                    self.hash_fileClearButton.configure(state=DISABLED)
                                    self.hash_fileBrowseButton.configure(state=DISABLED)

                                    self.hash_plainEntry.configure(state=NORMAL)
                                    if ''.join(self.hash_plainEntry.get()) != '':
                                        self.hash_plainClearButton.configure(state=NORMAL)
                                        self.SHA1Entry.configure(foreground="black")
                                        self.SHA256Entry.configure(foreground="black")
                                        self.SHA512Entry.configure(foreground="black")
                                        self.MD5Entry.configure(foreground="black")
                                        self.hash(bytes(self.hash_plainEntry.get(), "utf-8"), self.SHA1Entry, self.SHA256Entry, self.SHA512Entry, self.MD5Entry)
                                    else:
                                        self.hash_plainClearButton.configure(state=DISABLED)
                                        self.SHA1Entry.configure(foreground="gray")
                                        self.SHA256Entry.configure(foreground="gray")
                                        self.SHA512Entry.configure(foreground="gray")
                                        self.MD5Entry.configure(foreground="gray")
                                    self.hash_plainPasteButton.configure(state=NORMAL)

                            def browseFile(self):
                                filePath = filedialog.askopenfilename(title=f"Open a file to check its hash", filetypes=[("All files", "*.*")])
                                if ''.join(filePath.split()) != '':
                                    self.hash_fileEntry.replace(filePath)

                            def hash_passwordEntryCallback(self, *args, **kwargs):
                                if ''.join(self.hash_plainEntry.get().split()) == '':
                                    self.SHA1Entry.clear()
                                    self.SHA256Entry.clear()
                                    self.SHA512Entry.clear()
                                    self.MD5Entry.clear()
                                    self.SHA1CopyButton.configure(state=DISABLED)
                                    self.SHA256CopyButton.configure(state=DISABLED)
                                    self.SHA512CopyButton.configure(state=DISABLED)
                                    self.MD5CopyButton.configure(state=DISABLED)
                                    return
                                index = bytes(self.hash_plainEntry.get(), "utf-8")
                                self.SHA1Entry.configure(foreground="black")
                                self.SHA256Entry.configure(foreground="black")
                                self.SHA512Entry.configure(foreground="black")
                                self.MD5Entry.configure(foreground="black")
                                self.hash(index, self.SHA1Entry, self.SHA256Entry, self.SHA512Entry, self.MD5Entry)

                            def hash_fileEntryCallback(self, *args, **kwargs):
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
                                if ''.join(self.hash_fileEntry.get().split()) != '':
                                    self.hash_fileClearButton.configure(state=NORMAL)
                                    if os.path.isfile(self.hash_fileEntry.get()):
                                        try:
                                            self.hash_fileValidity.configure(text="Validity: Hashable", foreground="green")
                                            degrayEntries()
                                            self.hash(self.hash_fileEntry.get(), self.SHA1Entry, self.SHA256Entry, self.SHA512Entry, self.MD5Entry)
                                            return
                                        except (OSError, PermissionError):
                                            self.hash_fileValidity.configure(text="Validity: Read access was denied", foreground="red")
                                            grayoutEntries()
                                            return
                                        except Exception:
                                            self.hash_fileValidity.configure(text="Validity: Not hashable", foreground="red")
                                            grayoutEntries()
                                            return
                                    else:
                                        self.hash_fileValidity.configure(text="Validity: Not a file", foreground="red")
                                        grayoutEntries()
                                else:
                                    self.hash_fileClearButton.configure(state=DISABLED)
                                    self.hash_fileValidity.configure(text="Validity: [Blank]", foreground="gray")
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

                        self.loggingWidget = ScrolledText(self, height=33, width=107, font=("Consolas", 9), state=DISABLED, textvariable=self.root.loggingTextVar, bg="white", wrap=NONE, relief=FLAT, takefocus=0, highlightbackground="#7a7a7a", highlightthickness=1)
                        self.loggingWidget.tag_config("debug", foreground="gray")
                        self.loggingWidget.tag_config("info", foreground="black")
                        self.loggingWidget.tag_config("warning", foreground="orange")
                        self.loggingWidget.tag_config("error", foreground="red")
                        self.loggingWidget.tag_config("critical", foreground="red")

                        self.root.logger = Logger(self.loggingWidget, self.root)
                        self.root.loggingTextVar.trace("w", self.onLoggingWidgetInsert)

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
                        
                class sourceFrame(Frame):
                    def __init__(self, master: Notebook, **kwargs):
                        super().__init__(master=master, **kwargs)
                        self.root: Interface = self.master.master
                            
                        self.sourceText = ScrolledText(self, state=DISABLED, wrap=NONE, bg="white", relief=FLAT, takefocus=0, highlightthickness=0)
                        Percolator(self.sourceText).insertfilter(ColorDelegator())
                        try:
                            self.sourceText.replace(inspect.getsource(__import__("sys").modules[__name__]))
                        except (OSError, KeyError):
                            self.root._sourceLoadFailure = True
                            self.downloadingLabel = TkLabel(self, text="Downloading source code...", bg="white")
                            self.downloadingLabel.place(relx=.5, rely=.5, anchor=CENTER)
                        else:
                            self.root._sourceLoadFailure = False
                        self.sourceText.pack(expand=YES, fill=BOTH)

                self.encryptionFrame = encryptionFrame(self)
                self.decryptionFrame = decryptionFrame(self)
                self.miscFrame = miscFrame(self)
                self.loggingFrame = loggingFrame(self)
                self.helpFrame = helpFrame(self)
                self.sourceFrame = sourceFrame(self)

                self.add(self.encryptionFrame, text="Encryption")
                self.add(self.decryptionFrame, text="Decryption")
                self.add(self.miscFrame, text="Miscellaneous")
                self.add(self.loggingFrame, text="Logs")
                self.add(self.helpFrame, text="Help & About")
                # self.add(self.sourceFrame, text="Source Code")

        self.mainNotebook = mainNotebook(self)
        self.mainNotebook.pack(fill=BOTH, expand=YES, pady=4, padx=4, side=TOP)

        # This is the statusbar in the bottom of the window
        self.statusBar = TkLabel(self, text="Status: Ready", bd=1, relief=SUNKEN, anchor=W)
        self.statusBar.pack(side=BOTTOM, fill=X)

        # Ready up everything after placing all the widgets
        self.__initialize_menu()
        self.__initialize_protocols()
        self.__initialize_bindings()
        self.__load_database()

        # We're ready to go now, make the window visible
        self.deiconify()
        
    @selfinjected("self")
    def __init_subclass__(cls: type, *args, **kwargs):
        raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

    def __initialize_vars(self):
        """
        All the variables (either an instance of StringVar or IntVar) that are used by widgets are created here
        """
        self.showTextChar = IntVar(value=0)
        self.showTooltip = IntVar(value=1)
        self.showInfoBox = IntVar(value=1)
        self.showWarnBox = IntVar(value=1)
        self.showErrorBox = IntVar(value=1)
        self.windowAlpha = IntVar(value=100)
        self.updateInterval = IntVar(value=1)
        self.languageVar = IntVar(value=0)
        self.themeVar = StringVar(value="vista")
        self.loggingTextVar = StringVar()
        self.loggingAutoSaveVar = IntVar(value=0)
        self.levelSelectVar = StringVar(value="INFO")
        self.alwaysOnTopVar = IntVar(value=0)

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
        self.encryptWriteFileContentVar = IntVar(value=1)
        self.decryptWriteFileContentVar = IntVar(value=1)
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
        self.base64SourceVar = IntVar(value=0)
        self.base64FileEntryVar = StringVar()
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

    @exception_logged
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

    @exception_logged
    def __save_database(self):
        con = sqlite3.connect(f"{os.getenv('APPDATA')}\\Encrypt-n-Decrypt\\settings.sqlite")
        cur = con.cursor()
        operation = "INSERT INTO user_data VALUES ('{key}', '{value}')" if not cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_data'").fetchall() else "UPDATE user_data SET value = '{value}' WHERE key = '{key}'"
        cur.execute("CREATE TABLE IF NOT EXISTS user_data (key, value)")
        for attribute in [a for a in inspect.getmembers(self, lambda a: not(inspect.isroutine(a))) if not(a[0].startswith('__') and a[0].endswith('__'))]:
            name: str = attribute[0]
            value: IntVar | StringVar = attribute[1]
            if isinstance(value, IntVar) or any(ext in name for ext in ["themeVar", "levelSelectVar"]):
                cur.execute(operation.format(key=name, value=value.get()))
        con.commit()
        con.close()

    @exception_logged
    def __load_database(self):
        """
        Method to load the database containing the configurations for the program at startup
        """
        try:
            # If the folder for the program in AppData is present, load the database (create one if not-existent)
            con = sqlite3.connect(f"{os.getenv('APPDATA')}\\Encrypt-n-Decrypt\\settings.sqlite")
        except sqlite3.OperationalError:
            # If the folder for the program in AppData is not present, create it and load the database (create one if not-existent)
            os.mkdir(f"{os.getenv('APPDATA')}\\Encrypt-n-Decrypt")
            con = sqlite3.connect(f"{os.getenv('APPDATA')}\\Encrypt-n-Decrypt\\settings.sqlite")
        # Create the cursor as usual
        cur = con.cursor()
        # If the database was just created (therefore empty), skip attempting to load data from it
        if not cur.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'user_data'").fetchall():
            con.close()
            return
        else:
            # Check if the database is compatible with the current version of the program
            for attribute in [attr for attr in inspect.getmembers(self, lambda attr: not(inspect.isroutine(attr))) if not(attr[0].startswith('__') and attr[0].endswith('__'))]:
                if not attribute[0] in {key: value for (key, value) in cur.execute("SELECT * FROM user_data").fetchall()}:
                    break
            else:
                for attribute in [attr for attr in {key: value for (key, value) in cur.execute("SELECT * FROM user_data").fetchall()}.keys()]:
                    if not attribute in [attr[0] for attr in inspect.getmembers(self, lambda attr: not(inspect.isroutine(attr))) if not(attr[0].startswith('__') and attr[0].endswith('__'))]:
                        return
                # Iterate over the data in the database and set the corresponding variables
                cur.execute("SELECT * FROM user_data")
                for key, value in cur.fetchall():
                    eval(f"self.{key}.set(" + (value if not any(ext in key for ext in ["themeVar", "levelSelectVar"]) else f'\'{value}\'') + ")")

                # Call the methods of the GUI to update the GUI elements' states (normal or disabled) accordingly to the newly set values 
                for method, cls in [dict.values() for dict in self.scfs]:
                    method(cls())
                self.attributes("-alpha", self.windowAlpha.get() / 100)

                self.theme.set_theme(self.themeVar.get())
        # Close the connection to the database
        con.close()

    def __initialize_bindings(self):
        """
        Method to create the bindings, such as Ctrl+E, Ctrl+D, etc.
        """
        def encrypt(*args, **kwargs):
            """
            The function to be called when Enter key is pressed on keyboard
            """
            if self.mainNotebook.index(self.mainNotebook.select()) == 0:
                # If the encryption tab is selected, call the encryption method
                self.crypto.encrypt()
            elif self.mainNotebook.index(self.mainNotebook.select()) == 1:
                # If the decryption tab is selected, call the decryption method
                self.crypto.decrypt()
            else:
                # Otherwise, don't call anything
                return

        def show_source(*args, **kwargs):
            """
            The function to make the source code tab in mainNotebook visible
            """
            self.mainNotebook.add(self.mainNotebook.sourceFrame, text="Source Code")
            if any(["source" in child for child in self.mainNotebook.tabs()]):
                self.mainNotebook.select(5)

        self.bind("<Return>", encrypt)

        self.bind("<Control_L><Alt_L>t", lambda _: self.theme.set_theme("vista"))
        self.bind("<Control_L>e", lambda _: self.mainNotebook.select(0))
        self.bind("<Control_L>d", lambda _: self.mainNotebook.select(1))
        self.bind("<Control_L>m", lambda _: self.mainNotebook.select(2))
        self.bind("<Control_L>l", lambda _: self.mainNotebook.select(3))
        self.bind("<F1>", lambda _: self.mainNotebook.select(4))
        # EASTER EGG! This keybind shows the source code of the program
        self.bind("<Control_L><Alt_L>s", show_source)

    @exception_logged
    def __del__(self):
        """
        Magic method to be called when the instance gets deleted
        """
        if not hasattr(self, "success"):
            # If the database hasn't been saved yet, save it
            self.__save_database()
            self.success = True

    @exception_logged
    def __initialize_menu(self):
        """
        Method to create the drop-down menu on top of the window
        """
        class menuBar(Menu):
            def __init__(self, master: Interface):
                super().__init__(master, tearoff=0)

                class fileMenu(Menu):
                    def __init__(self, master: menuBar):
                        super().__init__(master, tearoff=0)
                        self.root: Interface = self.master.master
                        self.add_command(label = "Encryption", command=lambda: self.master.master.mainNotebook.select(0), accelerator="Ctrl+E", underline=0)
                        self.add_command(label = "Decryption", command=lambda: self.master.master.mainNotebook.select(1), accelerator="Ctrl+D", underline=0)
                        self.add_command(label = "Miscellaneous", command=lambda: self.master.master.mainNotebook.select(2), accelerator="Ctrl+M", underline=0)
                        self.add_command(label = "Logs", command=lambda: self.master.master.mainNotebook.select(3), accelerator="Ctrl+L", underline=0)
                        self.add_command(label = "Help & About", command=lambda: self.master.master.mainNotebook.select(4), accelerator="F1", underline=0)
                        self.add_separator()
                        self.add_command(label = "Check for updates", command=lambda: self.master.master.Updates(self.master.master), accelerator="Ctrl+Alt+U", underline=10)
                        self.add_separator()
                        self.add_command(label = "Exit", accelerator="Alt+F4", command=lambda: self.root.destroy())

                class viewMenu(Menu):
                    def __init__(self, master: menuBar):
                        super().__init__(master, tearoff=0)
                        self.root: Interface = self.master.master
                        self.add_checkbutton(label = "Show tooltips on hover", accelerator="Ctrl+Alt+T", onvalue=1, offvalue=0, variable=self.root.showTooltip, underline=5)
                        self.add_separator()
                        self.add_checkbutton(label = "Show info message dialogs", accelerator="Ctrl+Alt+I", onvalue=1, offvalue=0, variable=self.root.showInfoBox, underline=5)
                        self.add_checkbutton(label = "Show warning message dialogs", accelerator="Ctrl+Alt+W", onvalue=1, offvalue=0, variable=self.root.showWarnBox, underline=5)
                        self.add_checkbutton(label = "Show error message dialogs", accelerator="Ctrl+Alt+E", onvalue=1, offvalue=0, variable=self.root.showErrorBox, underline=5)
                        self.add_separator()
                        class titleMenu(Menu):
                            def __init__(self, master: viewMenu):
                                super().__init__(master, tearoff=0)
                                self.root: Interface = self.master.master.master
                                self.add_checkbutton(label = "Show program name in titlebar", onvalue=1, offvalue=0, variable=self.root.showProgramNameVar)
                                self.add_checkbutton(label = "Show program version in titlebar", onvalue=1, offvalue=0, variable=self.root.showProgramVersionVar)
                                self.add_checkbutton(label = "Show time in titlebar", onvalue=1, offvalue=0, variable=self.root.showTimeVar)
                                self.add_checkbutton(label = "Show date in titlebar", onvalue=1, offvalue=0, variable=self.root.showDateVar)
                                self.add_separator()
                                class speedMenu(Menu):
                                    def __init__(self, master: titleMenu):
                                        super().__init__(master, tearoff=0)
                                        self.root: Interface = self.master.master.master.master
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
                                self.root: Interface = self.master.master.master
                                self.add_radiobutton(label = "%20", value=20, variable=self.root.windowAlpha, command=lambda: self.root.attributes("-alpha", 20/100))
                                self.add_radiobutton(label = "%40", value=40, variable=self.root.windowAlpha, command=lambda: self.root.attributes("-alpha", 40/100))
                                self.add_radiobutton(label = "%60", value=60, variable=self.root.windowAlpha, command=lambda: self.root.attributes("-alpha", 60/100))
                                self.add_radiobutton(label = "%80", value=80, variable=self.root.windowAlpha, command=lambda: self.root.attributes("-alpha", 80/100))
                                self.add_radiobutton(label = "%90", value=90, variable=self.root.windowAlpha, command=lambda: self.root.attributes("-alpha", 90/100))
                                self.add_radiobutton(label = "Opaque", value=100, variable=self.root.windowAlpha, command=lambda: self.root.attributes("-alpha", 1))
                                self.add_separator()
                                self.add_command(label = "Reset opacity", command=lambda: self.root.attributes("-alpha", 10), accelerator="Ctrl+Alt+O", underline=6)
                        self.opacityMenu = opacityMenu(self)
                        self.add_cascade(menu=self.opacityMenu, label="Window opacity configuration")
                        class themeMenu(Menu):
                            def __init__(self, master: viewMenu):
                                super().__init__(master, tearoff=0)
                                self.root: Interface = self.master.master.master
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
                                self.add_radiobutton(label="Windows Default", value="vista", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("vista"), accelerator="vista")
                                self.add_radiobutton(label="Yaru", value="yaru", variable=self.root.themeVar, command=lambda: self.root.theme.set_theme("yaru"), accelerator="yaru")
                                self.add_separator()
                                self.add_command(label="Reset theme", command=lambda: (self.root.themeVar.set("vista"), self.root.theme.set_theme("vista")), accelerator="Ctrl+Alt+T")
                            def changeTheme(self, theme: str = "vista"):
                                self.root.theme.set_theme(theme)
                        self.themeMenu = themeMenu(self)
                        self.add_cascade(menu=self.themeMenu, label="Window theme configuration")
                        self.add_separator()
                        self.add_checkbutton(label="Always on top", onvalue=1, offvalue=0, variable=self.root.alwaysOnTopVar, command=lambda: self.root.attributes('-topmost', bool(self.root.alwaysOnTopVar.get())))
                        self.add_separator()
                        self.add_checkbutton(label="Auto-save configurations", onvalue=1, offvalue=0, variable=self.root.autoSaveConfigVar)
                        """self.add_separator()
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
                        self.add_cascade(menu=self.langMenu, label="Language")"""

                self.fileMenu = fileMenu(self)
                self.viewMenu = viewMenu(self)

                self.add_cascade(label = "Main", menu=self.fileMenu)
                self.add_cascade(label = "Preferences", menu=self.viewMenu)
                self.add_command(label = "Help", command=lambda: self.master.mainNotebook.select(4))

        self.menuBar = menuBar(self)
        self.config(menu = self.menuBar)

    @exception_logged
    def clipboard_get(self) -> Optional[str]:
        """
        Override the clipboard_get method to use pyperclip rather than the built-in copy/paste functions in Tkinter
        """
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

    @exception_logged
    def clipboard_set(self, text: str = None):
        """
        Override the clipboard_get method as well to use pyperclip
        """
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

    @final
    class Updates(Toplevel):
        @exception_logged
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

        @selfinjected("self")
        def __init_subclass__(cls: type, *args, **kwargs):
            raise TypeError(f"Class \"{Utilities.get_master_class(self).__name__}\" cannot be subclassed.") # type: ignore

if __name__ == "__main__":
    root = Interface()
    root.logger.info(f"{__title__} v{__version__} has been initialized")
    # LAUNCH!
    root.mainloop()
