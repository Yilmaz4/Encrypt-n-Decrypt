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

from tkinter import *
from tkinter import messagebox, filedialog
from tkinter.commondialog import Dialog
from tkinter.ttk import *

from typing import Any, Union, Optional, Literal
from markdown import markdown
from tkinterweb import HtmlFrame
from requests import get, head
from webbrowser import open as openweb
from string import ascii_letters, digits
from getpass import getuser
from ctypes import windll
from zipfile import ZipFile

from Crypto.Cipher import AES, PKCS1_OAEP, DES3
from Crypto.Util import Counter
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

import base64, os, time

def CheckUpdates():
    def AssetDownload(downloadPath, ProgressBar, downloadProgress, ProgressLabel, size, ExtractContent, Asset=0, chunkSize=2197318):
        startTime = time.time()
        size = int(size)
        MBFACTOR = float(1 << 20)
        try:
            os.remove(downloadPath)
        except:
            pass
        ProgressBar.configure(maximum=int(chunkSize))
        downloadProgress.set(0)
        downloadedSize = 0
        try:
            ProgressLabel.configure(text="Download progress: Creating the file in specified location . . .")
            update.update()
            file = open(downloadPath, mode='wb')
            downloadedContent = ""
            ProgressLabel.configure(text="Download progress: Getting ready for download operation . . .")
            update.update()
            for chunk in range(0, int(size), int(chunkSize)):
                try:
                    ProgressLabel.configure(text="Download progress: {:.1f} MB ({:.1f}%) out of {:.1f} MB downloaded".format(int(downloadedSize)/MBFACTOR, (100/size)*(downloadedSize), int(size)/MBFACTOR))
                    update.update()
                    downloadURL = get(Version.json()["assets"][int(Asset)]["browser_download_url"], headers={"Range":"bytes={}-{}".format(chunk, chunk+chunkSize-1)})
                except Exception as e:
                    messagebox.showerror("ERR_UNABLE_TO_CONNECT","An error occured while trying to connect to the GitHub servers. Please check your internet connection and firewall settings.\n\nError details: {}".format(e))
                    logTextWidget.config(state=NORMAL)
                    logTextWidget.insert(INSERT, strftime("[%I:%M:%S %p] ERROR: GitHub server connection failed ({})".format(e))+"\n")
                    logTextWidget.config(state=DISABLED)
                    try:
                        os.remove(downloadPath)
                    except:
                        pass
                    break
                ProgressLabel.configure(text="Download progress: {:.1f} MB ({:.1f}%) out of {:.1f} MB downloaded".format(int(downloadedSize)/MBFACTOR, (100/size)*(downloadedSize), int(size)/MBFACTOR))
                update.update()
                downloadedContent = bytes(str(downloadedContent), "utf-8") + downloadURL.content
                update.update()
                downloadedSize = downloadedSize + len(downloadURL.content)
                update.update()
                downloadProgress.set(downloadProgress.get()+len(downloadURL.content))
                update.update()
                ProgressBar.configure(maximum=size)
                update.update()
            try:
                file.write(downloadedContent)
            except Exception as e:
                if not is_admin():
                    messagebox.showerror("ERR_DESTINATION_ACCESS_DENIED","An error occured while trying to write downloaded data to '{}' path. Please try again; if problem persists, try to run the program as administrator or change the download path.\n\nError details: {}".format(downloadPath,e))
                    logTextWidget.config(state=NORMAL)
                    logTextWidget.insert(INSERT, strftime("[%I:%M:%S %p] ERROR: File write operation failed ({})".format(e))+"\n")
                    logTextWidget.config(state=DISABLED)
                    try:
                        os.remove(downloadPath)
                    except:
                        pass
                else:
                    messagebox.showerror("ERR_INVALID_PATH","An error occured while trying to write downloaded data to '{}' path. Path may be invalid or inaccessible. Please select another path.")
                    try:
                        os.remove(downloadPath)
                    except:
                        pass
        except Exception as e:
            if not is_admin():
                messagebox.showerror("ERR_DESTINATION_ACCESS_DENIED","An error occured while trying to write downloaded data to '{}' path. Please try again; if problem persists, try to run the program as administrator or change the download path.\n\nError details: {}".format(downloadPath,e))
                logTextWidget.config(state=NORMAL)
                logTextWidget.insert(INSERT, strftime("[%I:%M:%S %p] ERROR: File write operation failed ({})".format(e))+"\n")
                logTextWidget.config(state=DISABLED)
                try:
                    os.remove(downloadPath)
                except:
                    pass
            else:
                messagebox.showerror("ERR_INVALID_PATH","An error occured while trying to write downloaded data to '{}' path. Path may be invalid or inaccessible. Please select another path.")
                try:
                    os.remove(downloadPath)
                except:
                    pass
        else:
            ProgressLabel.configure(text="Download progress: Finishing download operation...")
            update.update()
            if ExtractContent.get() == 1:
                if DownloadPathEntry.get()[1:] == "\\":
                    try:
                        os.mkdir(DownloadPathEntry.get())
                    except:
                        pass
                    with ZipFile("{}{}".format(str(DownloadPathEntry.get()).replace("\\","/"),Version.json()["assets"][int(Asset)]["name"]), 'r') as zip_ref:
                        zip_ref.extractall(DownloadPathEntry.get())
                else:
                    try:
                        os.mkdir(DownloadPathEntry.get()+"/")
                    except:
                        pass
                    with ZipFile("{}/{}".format(str(DownloadPathEntry.get()).replace("\\","/"),Version.json()["assets"][int(Asset)]["name"]), 'r') as zip_ref:zip_ref.extractall(DownloadPathEntry.get())
            ProgressLabel.configure(text="Download progress:")
            downloadProgress.set(0)
            finishTime = time.time()
            messagebox.showinfo("Download complete","Downloading '{}' file from 'github.com' completed successfully. File has been saved to '{}'.\n\nDownload time: {}\nDownload Speed: {} MB/s\nFile size: {:.2f} MB".format(str(Version.json()["assets"][0]["name"]),("C:/Users/{}/Downloads/{}".format(getuser(), Version.json()["assets"][0]["name"])),str(finishTime-startTime)[:4]+" "+"Seconds",str(int(size) / MBFACTOR / float(str(finishTime-startTime)[:4]))[:4],int(size) / MBFACTOR))
    def Asset0Download():
        if DownloadPathEntry.get()[1:] == "\\":
            AssetDownload(downloadPath=("{}{}".format(str(DownloadPathEntry.get()).replace("\\","/"),Version.json()["assets"][0]["name"])), Asset=0, ProgressBar=ProgressBar, downloadProgress=downloadProgress, ProgressLabel=ProgressLabel, size=size, ExtractContent=ExtractContent)
        else:
            AssetDownload(downloadPath=("{}/{}".format(str(DownloadPathEntry.get()).replace("\\","/"),Version.json()["assets"][0]["name"])), Asset=0, ProgressBar=ProgressBar, downloadProgress=downloadProgress, ProgressLabel=ProgressLabel, size=size, ExtractContent=ExtractContent)
    def Asset1Download():
        if DownloadPathEntry.get()[1:] == "\\":
            AssetDownload(downloadPath=("{}{}".format(str(DownloadPathEntry.get()).replace("\\","/"),Version.json()["assets"][1]["name"])), Asset=1, ProgressBar=ProgressBar, downloadProgress=downloadProgress, ProgressLabel=ProgressLabel, size=size2, ExtractContent=ExtractContent)
        else:
            AssetDownload(downloadPath=("{}/{}".format(str(DownloadPathEntry.get()).replace("\\","/"),Version.json()["assets"][1]["name"])), Asset=1, ProgressBar=ProgressBar, downloadProgress=downloadProgress, ProgressLabel=ProgressLabel, size=size2, ExtractContent=ExtractContent)
    try:
        Version = get("https://api.github.com/repos/Yilmaz4/Encrypt-n-Decrypt/releases/latest")
    except Exception as e:
        messagebox.showerror("ERR_INTERNET_DISCONNECTED","An error occured while trying to connect to the GitHub API. Please check your internet connection.")
        logTextWidget.config(state=NORMAL)
        logTextWidget.insert(INSERT, strftime("[%I:%M:%S %p] ERROR: GitHub API connection failed ({})\n".format(e))+"\n")
        logTextWidget.config(state=DISABLED)
    else:
        MBFACTOR = float(1 << 20)
        try:
            response = head(Version.json()["assets"][0]["browser_download_url"], allow_redirects=True)
        except KeyError as e:
            messagebox.showerror("ERR_API_LIMIT_EXCEED","An error occured while trying to connect to the GitHub API servers. GitHub API limit may be exceed as servers has only 5000 connections limit per hour and per IP adress. Please try again after 1 hours.")
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "ERROR: GitHub API limit exceeded, connection failed. ({})\n".format(e))
            logTextWidget.config(state=DISABLED)
        else:
            size = response.headers.get('content-length', 0)
            response2 = head(Version.json()["assets"][1]["browser_download_url"], allow_redirects=True)
            size2 = response2.headers.get('content-length', 0)
            if Version.json()["tag_name"] == version:
                messagebox.showinfo("No updates available","There are currently no updates available. Please check again later.\n\nYour version: {}\nLatest version: {}".format(version, Version.json()["tag_name"]))
            else:
                if version.replace("b","").replace("v","").replace(".","") > (Version.json()["tag_name"]).replace("b","").replace("v","").replace(".",""):
                    messagebox.showinfo("Interesting.","It looks like you're using a newer version than official GitHub page. Your version may be a beta, or you're the author of this program :)\n\nYour version: {}\nLatest version: {}".format(version, Version.json()["tag_name"]))
                else:
                    def TestDirectory():
                        pass
                    update = Toplevel(root)
                    
class Interface(Tk):
    def __init__(self):
        super().__init__()

        self.height = 600
        self.width = 800
        self.version = "0.3.0"

        self.title(f"Eɲcrƴpʈ'n'Decrƴpʈ v{self.version}")
        self.geometry(f"{self.width}x{self.height}")
        self.resizable(width=False, height=False)
        self.minsize(width=self.width, height=self.height)
        self.maxsize(width=self.width, height=self.height)
        try:
            self.iconbitmap("icon.ico")
        except TclError:
            pass
        
        self.initialize_vars()
        self.initialize_menu()
        self.initialize_widgets()

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

    def initialize_widgets(self):
        self.mainNotebook = Notebook(self, width=380, height=340, takefocus=0)
        self.encryptionFrame = Frame(self.mainNotebook, takefocus=0)
        self.decryptionFrame = Frame(self.mainNotebook, takefocus=0)
        self.loggingFrame = Frame(self.mainNotebook, takefocus=0)
        self.helpFrame = Frame(self.mainNotebook, takefocus=0)

        self.mainNotebook.add(self.encryptionFrame, text="Encryption")
        self.mainNotebook.add(self.decryptionFrame, text="Decryption")
        self.mainNotebook.add(self.loggingFrame, text="Logs")
        self.mainNotebook.add(self.helpFrame, text="Help")

        self.mainNotebook.pack(fill=BOTH, expand=1, pady=4, padx=4, side=TOP)

        # ┌──────────────────┐
        # │ Encryption Frame │
        # └──────────────────┘

        # Plain text & file entries frame


        # Algorithm selection frame
        def changeAESState(state: Literal['normal', 'disabled'] = NORMAL):
            self.AES128Check.configure(state=state)
            self.AES192Check.configure(state=state)
            self.AES256Check.configure(state=state)
        def changeAlgorithmSelection():
            if self.generateAlgorithmSelection.get() == 0:
                self.AES128Check.configure(state=NORMAL)
                self.AES192Check.configure(state=NORMAL)
                self.AES256Check.configure(state=NORMAL)
                self.DES128Check.configure(state=DISABLED)
                self.DES192Check.configure(state=DISABLED)
            else:
                self.AES128Check.configure(state=DISABLED)
                self.AES192Check.configure(state=DISABLED)
                self.AES256Check.configure(state=DISABLED)
                self.DES128Check.configure(state=NORMAL)
                self.DES192Check.configure(state=NORMAL)

        def changeSourceSelection():
            if self.keySourceSelection.get() == 1:
                self.AESAlgorithmCheck.configure(state=DISABLED)
                self.DESAlgorithmCheck.configure(state=DISABLED)
                self.DES128Check.configure(state=DISABLED)
                self.DES192Check.configure(state=DISABLED)
                self.AES128Check.configure(state=DISABLED)
                self.AES192Check.configure(state=DISABLED)
                self.AES256Check.configure(state=DISABLED)
                self.keyEntry.configure(state=NORMAL)
                self.keyEntryHideCharCheck.configure(state=NORMAL)
                self.keyClearButton.configure(state=NORMAL)
                self.keyPasteButton.configure(state=NORMAL)
                self.keyBrowseButton.configure(state=NORMAL)
                self.keyEnteredAlgDES.configure(state=NORMAL)
                self.keyEnteredAlgAES.configure(state=NORMAL)
            else:
                self.AESAlgorithmCheck.configure(state=NORMAL)
                self.DESAlgorithmCheck.configure(state=NORMAL)
                self.DES128Check.configure(state=NORMAL)
                if self.generateAlgorithmSelection.get() == 1:
                    self.DES128Check.configure(state=NORMAL)
                    self.DES192Check.configure(state=NORMAL)
                    self.AES128Check.configure(state=DISABLED)
                    self.AES192Check.configure(state=DISABLED)
                    self.AES256Check.configure(state=DISABLED)
                else:
                    self.DES128Check.configure(state=DISABLED)
                    self.DES192Check.configure(state=DISABLED)
                    self.AES128Check.configure(state=NORMAL)
                    self.AES192Check.configure(state=NORMAL)
                    self.AES256Check.configure(state=NORMAL)
                self.keyEntry.configure(state=DISABLED)
                self.keyEntryHideCharCheck.configure(state=DISABLED)
                self.keyClearButton.configure(state=DISABLED)
                self.keyPasteButton.configure(state=DISABLED)
                self.keyBrowseButton.configure(state=DISABLED)
                self.keyEnteredAlgDES.configure(state=DISABLED)
                self.keyEnteredAlgAES.configure(state=DISABLED)

        def GetKey(path: str) -> Optional[Union[str, bytes]]:
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
                key = GetKey(path)
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
            if len(value) == 0:
                self.keyValidityStatusLabel.configure(foreground="gray", text="Validity: [Blank]")
            else:
                cond = bool(self.generateAlgorithmSelection.get())
                iv = get_random_bytes(AES.block_size) if not cond else Random.new().read(DES3.block_size)
                try:
                    AES.new(bytes(value, 'utf-8'), AES.MODE_OFB, iv)
                except:
                    self.keyValidityStatusLabel.configure(foreground="red", text=f"Validity: Invalid {'AES' if not cond else '3DES'}-{len(value) * 8} Key")
                else:
                    self.keyValidityStatusLabel.configure(foreground="green", text=f"Validity: Valid {'AES' if not cond else '3DES'}-{len(value) * 8} Key")

        self.algorithmSelect = Notebook(self.encryptionFrame, width=355, height=280, takefocus=0)
        self.symmetricEncryption = Frame(self.algorithmSelect, takefocus=0)
        self.asymmetricEncryption = Frame(self.algorithmSelect, takefocus=0)

        self.algorithmSelect.add(self.symmetricEncryption, text="Symmetric Key Encryption")
        self.algorithmSelect.add(self.symmetricEncryption, text="Asymmetric Key Encryption")

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

        # ┌──────────────────┐
        # │ Decryption Frame │
        # └──────────────────┘
        """TextToDecryptRadio = Radiobutton(self.decryptionFrame, text = "Encrypted text:", value=1, variable=DecryptSourceVar, command=ChangeWhatToDecrypt, takefocus=0)
        TextToDecryptPaste = Button(self.decryptionFrame, width=15, text="Paste", command=PasteEncryptedFunc, takefocus=0)
        TextToDecryptClear = Button(self.decryptionFrame, width=15, text="Clear", command=lambda: TextToDecryptEntry.delete("1.0", END), takefocus=0, state=DISABLED)
        FileToDecryptBrowse = Button(self.decryptionFrame, width=15, text="Browse...", state=DISABLED, command=BrowseEncryptedFunc, takefocus=0)
        FileToDecryptClear = Button(self.decryptionFrame, width=15, text="Clear", state=DISABLED, command=lambda: FileToDecryptEntry.delete(0, END), takefocus=0)
        FileToDecryptRadio = Radiobutton(self.decryptionFrame, text = "Encrypted file:", value=2, variable=DecryptSourceVar, command=ChangeWhatToDecrypt, takefocus=0)
        TextToDecryptEntry = Text(self.decryptionFrame, width=105, height=6, font=("Consolas", 9), takefocus=0)
        FileToDecryptEntry = Entry(self.decryptionFrame, width=107, font=("Consolas", 9), state=DISABLED, takefocus=0)
        TextToDecryptScroll = Scrollbar(self.decryptionFrame, command=TextToDecryptEntry.yview, takefocus=0)
        TextToDecryptEntry.configure(yscrollcommand=TextToDecryptScroll.set)
        KeyEntryToDecrypt = Notebook(self.decryptionFrame, height=160, width=765, takefocus=0)
        SymKeyDecrypt = Frame(KeyEntryToDecrypt, takefocus=0)
        AsymKeyDecrypt = Frame(KeyEntryToDecrypt, takefocus=0)
        KeyEntryToDecrypt.add(SymKeyDecrypt, text="Symmetric Key Decryption")
        KeyEntryToDecrypt.add(AsymKeyDecrypt, text="Asymmetric Key Decryption")
        SelectAlgorithmDecryptFrame = LabelFrame(SymKeyDecrypt, text="Select algorithm", height=63, width=749, takefocus=0)
        SelectAESradio = Radiobutton(SelectAlgorithmDecryptFrame, text="AES (Advanced Encryption Standard)", value=1, variable=DecryptAlg, takefocus=0)
        SelectDESradio = Radiobutton(SelectAlgorithmDecryptFrame, text="3DES (Triple Data Encryption Standard)", value=2, variable=DecryptAlg, takefocus=0)
        EnterKeyFrame = LabelFrame(SymKeyDecrypt, text="Enter encryption key", height=84, width=749, takefocus=0)
        SymKeyEntry = Entry(EnterKeyFrame, width=103, font=("Consolas", 9), takefocus=0)
        SymKeyBrowseButton = Button(EnterKeyFrame, width=21, text="Browse key file...", takefocus=0)
        SymKeyPasteButton = Button(EnterKeyFrame, width=15, text="Paste", takefocus=0, command=PasteKeyFunc)
        SymKeyClearButton = Button(EnterKeyFrame, width=15, text="Clear", takefocus=0, state=DISABLED)
        DecryptButton = Button(self.decryptionFrame, width=18, text="Decrypt", takefocus=0)
        OutputFrame = LabelFrame(self.decryptionFrame, text="Decrypted text", height=84, width=766, takefocus=0)
        OutputEntry = Text(OutputFrame, width=103, height=1, font=("Consolas", 9), state=DISABLED, takefocus=0)
        
        TextToDecryptRadio.place(x=8, y=2)
        FileToDecryptRadio.place(x=8, y=145)
        TextToDecryptEntry.place(x=24, y=24)
        TextToDecryptPaste.place(x=23, y=120)
        TextToDecryptClear.place(x=130, y=120)
        FileToDecryptBrowse.place(x=23, y=195)
        FileToDecryptClear.place(x=130, y=195)
        FileToDecryptEntry.place(x=24, y=166)
        TextToDecryptScroll.place(x=762, y=23, height=88)
        KeyEntryToDecrypt.place(x=10, y=228)
        SelectAlgorithmDecryptFrame.place(x=8, y=2)
        SelectAESradio.place(x=5, y=0)
        SelectDESradio.place(x=5, y=19)
        EnterKeyFrame.place(x=8, y=68)
        SymKeyEntry.place(x=9, y=3)
        SymKeyPasteButton.place(x=8, y=30)
        SymKeyBrowseButton.place(x=601, y=30)
        SymKeyClearButton.place(x=115, y=30)
        DecryptButton.place(x=9, y=421)
        OutputFrame.place(x=10, y=442)
        OutputEntry.place(x=9, y=3)"""

        # Encrypted data / output frame
        self.outputFrame = LabelFrame(self.encryptionFrame, text="Output", height=506, width=403, takefocus=0)


        self.outputFrame.place(x=377, y=4)
        # ┌───────────────┐
        # │ Logging Frame │
        # └───────────────┘
        self.loggingWidget = Text(self.loggingFrame, height=22, width=107, font=("Consolas", 9), state=DISABLED, takefocus=0)

    def initialize_vars(self):
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


    def initialize_menu(self):
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
        self.fileMenu.add_command(label = "Check for updates", accelerator="Ctrl+Alt+U", command=CheckUpdates, underline=10)
        self.fileMenu.add_separator()
        self.fileMenu.add_command(label = "Exit", accelerator="Alt+F4", command=lambda:root.destroy())
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
    
    class Updates(Toplevel):
        def __init__(self, master: Tk):
            try:
                Version = get("https://api.github.com/repos/Yilmaz4/Encrypt-n-Decrypt/releases/latest")
            except Exception as e:
                messagebox.showerror("ERR_INTERNET_DISCONNECTED","An error occured while trying to connect to the GitHub API. Please check your internet connection.")
                logTextWidget.config(state=NORMAL)
                logTextWidget.insert(INSERT, strftime("[%I:%M:%S %p] ERROR: GitHub API connection failed ({})\n".format(e))+"\n")
                logTextWidget.config(state=DISABLED)
            else:
                MBFACTOR = float(1 << 20)
                try:
                    response = head(Version.json()["assets"][0]["browser_download_url"], allow_redirects=True)
                except KeyError as e:
                    messagebox.showerror("ERR_API_LIMIT_EXCEED","An error occured while trying to connect to the GitHub API servers. GitHub API limit may be exceed as servers has only 5000 connections limit per hour and per IP adress. Please try again after 1 hours.")
                    logTextWidget.config(state=NORMAL)
                    logTextWidget.insert(INSERT, "ERROR: GitHub API limit exceeded, connection failed. ({})\n".format(e))
                    logTextWidget.config(state=DISABLED)
                else:
                    size = response.headers.get('content-length', 0)
                    response2 = head(Version.json()["assets"][1]["browser_download_url"], allow_redirects=True)
                    size2 = response2.headers.get('content-length', 0)
                    if Version.json()["tag_name"] == "v" + self.version:
                        messagebox.showinfo("No updates available","There are currently no updates available. Please check again later.\n\nYour version: {}\nLatest version: {}".format(version, Version.json()["tag_name"]))
                    else:
                        if self.version.replace(".","") > (Version.json()["tag_name"]).replace("b","").replace("v","").replace(".",""):
                            messagebox.showinfo("Interesting.","It looks like you're using a newer version than official GitHub page. Your version may be a beta, or you're the author of this program :)\n\nYour version: {}\nLatest version: {}".format(version, Version.json()["tag_name"]))
                            return
                        else:
                            pass
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

            HTML = markdown(Version.json()["body"])
            frame = HtmlFrame(self, height=558, width=300, messages_enabled=False, vertical_scrollbar=True)
            frame.load_html(HTML)
            frame.set_zoom(0.8)
            frame.grid_propagate(0)
            frame.enable_images(0)
            frame.place(x=0, y=0)
            UpdateAvailableLabel = Label(self, text="An update is available!", font=('Segoe UI', 22), foreground="#189200", takefocus=0)
            LatestVersionLabel = Label(self, text="Latest version: {}".format(Version.json()["name"], font=('Segoe UI', 11)), takefocus=0)
            YourVersionLabel = Label(self, text="Current version: Eɲcrƴpʈ'n'Decrƴpʈ v{}".format(self.version), font=('Segoe UI', 9), takefocus=0)
            DownloadLabel = Label(self, text="Download page for more information and asset files:", takefocus=0)
            DownloadLinks = LabelFrame(self, text="Download links", height=248, width=349, takefocus=0)
            OtherOptions = LabelFrame(self, text="Other options", height=128, width=349, takefocus=0)
            DownloadLinkLabel = Label(DownloadLinks, text=Version.json()["assets"][0]["name"], takefocus=0)
            DownloadLinkLabel2 = Label(DownloadLinks, text=Version.json()["assets"][1]["name"], takefocus=0)
            Separator1 = Separator(self, orient='horizontal', takefocus=0)
            Separator2 = Separator(DownloadLinks, orient='horizontal', takefocus=0)
            Separator3 = Separator(DownloadLinks, orient='horizontal', takefocus=0)
            Separator4 = Separator(OtherOptions, orient='horizontal', takefocus=0)
            CopyDownloadPage = Button(self, text="Copy", width=10, takefocus=0)
            OpenDownloadLink = Button(self, text="Open in browser", width=17, command=lambda: openweb(str(Version.json()["html_url"])), takefocus=0)
            CopyDownloadLink = Button(DownloadLinks, text="Copy", width=10, takefocus=0)
            DownloadTheLinkBrowser = Button(DownloadLinks, text="Download from browser", width=25, command=lambda: openweb(Version.json()["assets"][0]["browser_download_url"]), takefocus=0)
            DownloadTheLinkBuiltin = Button(DownloadLinks, text="Download", width=13, command=Asset0Download, takefocus=0)
            CopyDownloadLink2 = Button(DownloadLinks, text="Copy", width=10, takefocus=0)
            DownloadTheLinkBrowser2 = Button(DownloadLinks, text="Download from browser", width=25, command=lambda: openweb(Version.json()["assets"][1]["browser_download_url"]), takefocus=0)
            DownloadTheLinkBuiltin2 = Button(DownloadLinks, text="Download", width=13, command=Asset1Download, takefocus=0)
            DownloadPage = Entry(self, width=57, takefocus=0)
            DownloadPage.insert(0, str(self.json()["html_url"]))
            DownloadPage.configure(state=DISABLED)
            DownloadLink = Entry(DownloadLinks, width=54, takefocus=0)
            DownloadLink.insert(0, str(self.json()["assets"][0]["browser_download_url"]))
            DownloadLink.configure(state=DISABLED)
            DownloadLink2 = Entry(DownloadLinks, width=54, takefocus=0)
            DownloadLink2.insert(0, str(self.json()["assets"][1]["browser_download_url"]))
            DownloadLink2.configure(state=DISABLED)
            AssetSize = Label(DownloadLinks, text=("{:.2f} MB".format(int(size) / MBFACTOR)), foreground="#474747", takefocus=0)
            AssetSize2 = Label(DownloadLinks, text=("{:.2f} MB".format(int(size2) / MBFACTOR)), foreground="#474747", takefocus=0)
            DateVariable = response.headers.get('Last-Modified', 0)[:16 if response.headers.get('Last-Modified', 0)[:17][16] == " " else 17]
            Date = Label(DownloadLinks, text=DateVariable, foreground="gray", takefocus=0)
            Date2 = Label(DownloadLinks, text=DateVariable, foreground="gray", takefocus=0)
            downloadProgress = IntVar()
            downloadProgress.set(0)
            ProgressBar = Progressbar(DownloadLinks, length=329, mode='determinate', orient=HORIZONTAL, variable=downloadProgress, maximum=int(size), takefocus=0)
            ProgressLabel = Label(DownloadLinks, text="Download progress:", takefocus=0)
            DownloadPathLabel = Label(OtherOptions, text="Download directory:", takefocus=0)
            DownloadPathEntry = Entry(OtherOptions, width=54, takefocus=0)
            DownloadPathEntry.insert(0, r"C:\Users\{}\Downloads".format(getuser()))
            DownloadPathStatus = Label(OtherOptions, text="Status: OK", foreground="green", takefocus=0)
            def directoryRevert():
                DownloadPathEntry.delete(0, 'end')
                DownloadPathEntry.insert(0, r"C:\Users\{}\Downloads".format(getuser()))
            DownloadPathReset = Button(OtherOptions, text="Revert to default directory", width=24, command=directoryRevert, takefocus=0)
            DownloadPathBrowse = Button(OtherOptions, text="Browse", width=10, takefocus=0)
            ExtractContent = IntVar()
            ExtractContent.set(0)
            ExtractContentsCheck = Checkbutton(OtherOptions, text="Extract downloaded files", onvalue=1, offvalue=0, variable=ExtractContent, takefocus=0)
            DownloadPathLabel.place(x=5, y=0)
            DownloadPathEntry.place(x=7, y=21)
            DownloadPathStatus.place(x=116, y=0)
            DownloadPathReset.place(x=6, y=47)
            DownloadPathBrowse.place(x=267, y=47)
            Separator4.place(x=7, y=78, width=329)
            ExtractContentsCheck.place(x=6, y=83)
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
            Date.place(x=237 if len(DateVariable) == 17 else 240, y=0)
            Date2.place(x=237 if len(DateVariable) == 17 else 240, y=86)
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
            OtherOptions.place(x=310, y=420)
            self.focus_force()

if __name__ == "__main__":
    root = Interface()
    root.mainloop()
