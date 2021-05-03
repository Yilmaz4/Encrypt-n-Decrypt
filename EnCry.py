if __import__("sys").version_info.major == 2:
    from Tkinter import *
    from Tkinter import messagebox
    from Tkinter import ttk
else:
    from tkinter import *
    from tkinter import messagebox
    from tkinter import ttk
    from tkinter.ttk import *
from cryptography.fernet import Fernet
import pyperclip
from pathlib import Path
try:
    appWidth = 385
    appHeight = 255
    version = "v0.3.12 [Beta]"
    EncryptVersion = " Encrypt'n'Decrypt {}".format(version)
    root = Tk()
    root.title("{}".format(EncryptVersion))
    root.resizable(width=FALSE, height=FALSE)
    root.geometry("{}x{}".format(appWidth, appHeight))
    root.attributes("-fullscreen", False)
    root.minsize(appWidth, appHeight)
    root.maxsize(appWidth, appHeight)
    if True:
        MainScreen = ttk.Notebook(root, width=380, height=340)
        LogFrame = Frame(MainScreen)
        logTextWidget = Text(LogFrame, height = 13, width = 56, font = ("Segoe UI", 9), state=DISABLED)
    logTextWidget.config(state=NORMAL)
    logTextWidget.insert(INSERT, "ROOT: Created root, started mainloop.\n")
    logTextWidget.config(state=DISABLED)
    root.iconbitmap('Ico.ico')
    def ShutDown():
        root.destroy()
    showCharState = IntVar(value=0)
    deshowCharState = IntVar(value=0)
    showChar = True
    def toggleHideChar():
        global encryptedTextEntry
        if showCharState.get() == 1:
            showChar = False
            OldText = encryptedTextEntry.get()
            encryptedTextEntry.place_forget()
            encryptedTextEntry = Entry(EncryptFrame, width = 58, show = "*")
            encryptedTextEntry.insert(0,"{}".format(OldText))
            encryptedTextEntry.place(x=10, y=10)
        else:
            showChar = True
            OldText = encryptedTextEntry.get()
            encryptedTextEntry.place_forget()
            encryptedTextEntry = Entry(EncryptFrame, width = 58)
            encryptedTextEntry.insert(0,"{}".format(OldText))
            encryptedTextEntry.place(x=10, y=10)
    def generate_key():
        global key
        key = Fernet.generate_key()
        try:
            with open("Encryption Key.key", "wb") as key_file:
                key_file.write(key)
        except:
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "ERROR: An error occured while trying to create 'Encryption Key.key' file in the root directory. \n")
            logTextWidget.config(state=DISABLED)
            messagebox.showerror("ERR_UNABLE_TO_CREATE_FILE","An error occured while trying to create 'Encryption Key.key' file in the root directory. Please try again, if problem pertists, try to move program files to your desktop or run the program as administrator.")
    def Encrypt():
        global encryptedTextEntry, encryptedTextWidget, key
        try:
            textEncrypt = encryptedTextEntry.get()
            generate_key()
            fernet = Fernet(key)
            encryptedText = fernet.encrypt(textEncrypt.encode())
            decryptedText = fernet.decrypt(encryptedText).decode()
        except:
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "ERROR: An error occured when trying to encrypt.\n")
            logTextWidget.config(state=DISABLED)
            messagebox.showerror(" Hata: ERR_UNABLE_TO_ENCRYPT","An error occured while trying to encrypt. Please restart and try encrypting again.")
            ShutDown()
        if textEncrypt == decryptedText:
            encryptedTextWidget.configure(state=NORMAL)
            encryptedTextWidget.delete('1.0', END)
            encryptedTextWidget.insert(INSERT, encryptedText)
            encryptedTextWidget.configure(state=DISABLED)
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "SUCSESS: Entered text sucsessfully encrypted.\n")
            logTextWidget.config(state=DISABLED)
        else:
            tryText = "abc"
            trykey = Fernet.generate_key()
            tryfernet = Fernet(trykey)
            tryEncryptedText = tryfernet.encrypt(tryText.encode())
            tryDecryptedText = tryfernet.decrypt(tryEncryptedText).decode()
            if tryText == tryDecryptedText:
                logTextWidget.config(state=NORMAL)
                logTextWidget.insert(INSERT, "WARNING: Entered text is not encryptable.\n".format(textEncrypt, decryptedText))
                logTextWidget.config(state=DISABLED)
            else:
                logTextWidget.config(state=NORMAL)
                logTextWidget.insert(INSERT, "ERROR: Encrypter is not working properly.\n".format(textEncrypt, decryptedText))
                logTextWidget.config(state=DISABLED)
                messagebox.showerror(" Hata: ERR_ENCRYPTER_NOT_WORKING_PROPERLY","Encrypter is not working properly. Please report this problem to us. Sended '{}' got '{}'. And than sended '{}' got '{}'.".format(textEncrypt, decryptedText, tryText, tryDecryptedText))
    def Copy():
        global encryptedTextWidget
        pyperclip.copy(encryptedTextWidget.get('1.0', END))
        copyed = pyperclip.paste()
        if copyed == (encryptedTextWidget.get('1.0', END)):
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "SUCSESS: Encrypted text copied to clipboard sucsessfully.\n")
            logTextWidget.config(state=DISABLED)
            messagebox.showinfo(" Copied.","Encrypted text copied to clipboard sucsessfully.")
    def Clear():
        global encryptedTextWidget
        try:
            encryptedTextWidget.configure(state=NORMAL)
            encryptedTextWidget.delete('1.0', END)
            encryptedTextWidget.configure(state=DISABLED)
        except:
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "ERROR: An error occured when trying to clear output text.\n")
            logTextWidget.config(state=DISABLED)
            messagebox.showerror(" Hata: ERR_UNABLE_TO_CLEAR","An error occured in program. Please restart and try again.")
            ShutDown()
    def CheckEncrypt():
        global encryptedTextEntry, decryptedText
        try:
            textEncrypt = encryptedTextEntry.get()
            key = Fernet.generate_key()
            fernet = Fernet(key)
            encryptedText = fernet.encrypt(textEncrypt.encode())
            decryptedText = fernet.decrypt(encryptedText).decode()
        except:
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "ERROR: An unknown error occured while trying to check encryption.\n".format(textEncrypt, decryptedText))
            logTextWidget.config(state=DISABLED)
            messagebox.showerror(" Hata: ERR_UNABLE_TO_ENCRYPT","An error occured in encypter. Please restart the program and try again. If problem persists, please report this problem to me.")
            ShutDown()
        if textEncrypt == decryptedText:
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "SUCSESS: Encrypter checked sucsessfully.\n")
            logTextWidget.config(state=DISABLED)
            messagebox.showinfo(" Sucsess.","Encrypter checked sucsessfully with no errors. That means encrypter and decrypter are working properly. Sended '{}' encrypted, decrypted and got '{}'.".format(textEncrypt, decryptedText))
        else:
            tryText = "abc"
            trykey = Fernet.generate_key()
            tryfernet = Fernet(trykey)
            tryEncryptedText = tryfernet.encrypt(tryText.encode())
            tryDecryptedText = tryfernet.decrypt(tryEncryptedText).decode()
            if tryText == tryDecryptedText:
                logTextWidget.config(state=NORMAL)
                logTextWidget.insert(INSERT, "ERROR: Encrypter working properly but current text cannot be encrypted.\n")
                logTextWidget.config(state=DISABLED)
                messagebox.showwarning("ERR_CURRENT_TEXT_CANNOT_BE_ENCRYPTED","Encyrpter and decrypter is working properly but the text you just entered is not valid for encyption. Please report this unencryptable text to me. Sended '{}', encrypted, decrypted and didn't got a valid plain text. After that, sended '{}', encrypted, decrypted and got '{}'".format(textEncrypt, tryText, tryDecryptedText))
            else:
                logTextWidget.config(state=NORMAL)
                logTextWidget.insert(INSERT, "ERROR: Encrypter is not working properly.\n".format(textEncrypt, decryptedText))
                logTextWidget.config(state=DISABLED)
                messagebox.showwarning("ERR_ENCRYPTER_NOT_WORKING_PROPERLY","Unfortunately encrypter is not working properly. This might happened due to corrupt program files, corrupt program executable or uncompatible Operating System. Please notice that this program is only for Windows Operating Sytems and not tested for Windows XP and older operating systems. Sended '{}', encrypted, decrypted and didn't got a valid plain text. After that sended '{}', encrypted, decrypted and didn't got a valid plain text again.".format(textEncrypt, tryText))
    def CheckDecrypt():
        global decryptedTextWidget
        try:
            textEncryptget = decryptedTextWidget.get('1.0',END)
            textEncrypt = bytes(textEncryptget, 'utf-8')
            key = load_key()
            fernet = Fernet(key)
            decryptedText = fernet.decrypt(textEncrypt).decode()
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "SUCSESS: Checked decrypter sucsessfully.\n".format(textEncrypt, decryptedText))
            logTextWidget.config(state=DISABLED)
            messagebox.showinfo(" Sucsess.","Decrypter checked sucsessfully without any errors. That means decrypter is working properly. Program sucsessfully brought the decryption key from 'Encryption Key.key' and sucsessfully decrypted the entered encoded text.")
        except:
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "WARNING: The right key to decrypt text is not find in 'Encryption Key' file, decryption failed.\n")
            logTextWidget.config(state=DISABLED)
            messagebox.showerror("ERR_WRONG_KEY","The right key to decrypt text is not find in 'Encryption Key' file. Please be sure you copied ")
            ShutDown()
    def load_key():
        try:
            return open("Encryption Key.key", "rb").read()
        except:
            path = Path("/Encryption Key.key")
            if path.is_file(): 
                messagebox.showwarning("ERR_CANNOT_FIND_KEY_FILE","The 'Encryption Key.key' file is not found in the root folder. Please be sure this file is in this program's root folder.")
            else:
                messagebox.showerror("ERR_CANNOT_READ_KEY_FILE","Program failed to read data inside 'Encryption Key.key' file. Maybe this file got corrupt or program has not access to this file. Try to run the program as administrator.")
    def Decrypt():
        global decryptedTextEntry, decryptedTextWidget, decryptedText
        try:
            textEncryptget = decryptedTextWidget.get('1.0',END)
            textEncrypt = bytes(textEncryptget, 'utf-8')
            key = load_key()
            fernet = Fernet(key)
        except:
            print("ERROR: An error occured when trying to decrypt. Program will be terminated.")
            messagebox.showerror("ERR_UNABLE_TO_DECRYPT","An error occured in decrypter. Program will now terminated. Please try again.")
            ShutDown()
        try:
            decryptedText = fernet.decrypt(textEncrypt).decode()
        except:
            print("INFO: There is no valid key file found on root directory for decrypting this code. Please copy the valid key into root direcotry.")
            messagebox.showinfo(" Warning.","The key in 'Encryption Key.key' is not the correcy key to decrypt this encrypted text. Please be sure you put the correct file in the root folder.")
        decryptedTextEntry.configure(state=NORMAL)
        decryptedTextEntry.delete(0, END)
        decryptedTextEntry.insert(0, decryptedText)
        decryptedTextEntry.configure(state=DISABLED)
        print("SUCSESS: Entered code sucsessfully decrypted.")
    def deCopy():
        global decryptedTextEntry
        pyperclip.copy(decryptedTextEntry.get())
        copyed = pyperclip.paste()
        messagebox.showinfo("Copied.","Decrypted text sucsessfully copied to clipboard.")
    def deClear():
        global decryptedTextEntry
        try:
            decryptedTextEntry.configure(state=NORMAL)
            decryptedTextEntry.delete(0, END)
            decryptedTextEntry.configure(state=DISABLED)
        except:
            print("ERROR: An error occured when trying to clear output text. Program will be terminated.")
            messagebox.showerror("ERR_UNABLE_TO_CLEAR","An error occured in program. Program will now terminated. Please try again. Also please report this error to me.")
            ShutDown()
    def dePaste():
        global decryptedTextWidget
        try:
            paste = pyperclip.paste()
            decryptedTextWidget.configure(state=NORMAL)
            decryptedTextWidget.delete('1.0',END)
            textEncrypt = bytes(paste, 'utf-8')
            decryptedTextWidget.insert(INSERT, textEncrypt)
        except:
            print("INFO: There is no copyed text in clipboard.")
            messagebox.showinfo("ERR_NO_VALID_TEXT_IN_CLIPBOARD","There is no any text in clipboard. Did you forgot to copy the encrypted data by clicking 'Copy' button? [Easter Egg]. If you already clicked the 'Copy' button and problem persists, please report this problem to me.")
    def toggledeHideChar():
        global decryptedTextWidget
        if showCharState.get() == 1:
            showChar = False
            OldText = encryptedTextEntry.get()
            decryptedTextWidget.place_forget()
            decryptedTextWidget = Entry(EncryptFrame, width = 58, show = "*")
            decryptedTextWidget.insert(0,"{}".format(OldText))
            decryptedTextWidget.place(x=10, y=10)
        else:
            showChar = True
            OldText = encryptedTextEntry.get()
            decryptedTextWidget.place_forget()
            decryptedTextWidget = Entry(EncryptFrame, width = 58)
            decryptedTextWidget.insert(0,"{}".format(OldText))
            decryptedTextWidget.place(x=10, y=10)
    logTextWidget.config(state=NORMAL)
    logTextWidget.insert(INSERT, "ROOT: Registered define commands.\n")
    logTextWidget.config(state=DISABLED)
    screenWidth = root.winfo_screenwidth()
    screenHeight = root.winfo_screenheight()
    Menu = Menu(root)
    EncryptFrame = Frame(MainScreen)
    DecryptFrame = Frame(MainScreen)
    AboutFrame   = Frame(MainScreen)
    MainScreen.add(EncryptFrame, text="Encryption")
    MainScreen.add(DecryptFrame, text="Decryption")
    MainScreen.add(LogFrame, text="Logs")
    MainScreen.add(AboutFrame, text="Help & About")
    MainScreen.pack(fill=BOTH, expand=1, pady=4, padx=4, side=TOP)
    logTextWidget.config(state=NORMAL)
    logTextWidget.insert(INSERT, "ROOT: Created menu.\n")
    logTextWidget.config(state=DISABLED)
    encryButton = Button(EncryptFrame, text = "Encrypt", width=15, command=Encrypt)
    checkButton = Button(EncryptFrame, text = "Check the encrypter", width=20, command=CheckEncrypt)
    copyButton = Button(EncryptFrame, text = "Copy", width=10, command=Copy)
    clearButton = Button(EncryptFrame, text = "Clear", width=9, command=Clear)
    showCharCheck = Checkbutton(EncryptFrame, text = "Hide characters", variable = showCharState, onvalue = 1, offvalue = 0, command = toggleHideChar)
    encryptedTextWidget = Text(EncryptFrame, height = 6, width = 58, state=DISABLED, font = ("Segoe UI", 9))
    decryButton = Button(DecryptFrame, text = "Decrypt", width=22, command=Decrypt)
    decheckButton = Button(DecryptFrame, text = "Check decrypter", width=20, command=CheckDecrypt)
    decopyButton = Button(DecryptFrame, text = "Copy", width=10, command=deCopy)
    declearButton = Button(DecryptFrame, text = "Clear", width=9, command=deClear)
    depasteButton = Button(DecryptFrame, text = "Paste", width=9, command=dePaste)
    decryptedTextWidget = Text(DecryptFrame, height = 6, width = 58, font = ("Segoe UI", 9))
    scrollbar = Scrollbar(LogFrame)
    logTextWidget.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=logTextWidget.yview)
    about = Text(AboutFrame, height = 13, width = 58, font = ("Segoe UI", 9))
    Text = "This program can encrypt and decrypt using 128-bit encryption standard (AES in CBC mode). Program uses cryptography.fernet library in Python 3.8. Also you need a 128-bit key to decrypt the data. Only one key can decrypt an encrypted data. So you must not lose your key if you want to decrypt the data later. This key is saved to 'Encryption Key.key' file everytime you encrypt a data. You must put this file to this program's root folder before decrypting the data.\nProgram version: {}\nDeveloper: Yılmaz Alpaslan (Github: Yilmaz4)\nPlease notice this version of program is not stable version. So there may some bugs and glitches in this version. Please download the latest version of my program from my GitHub page.".format(version)
    about.insert(INSERT, Text)
    about.configure(state=DISABLED)
    if showChar == False:
        encryptedTextEntry = Entry(EncryptFrame, width = 58, show = "*")
        decryptedTextEntry = Entry(DecryptFrame, width = 58, show = "*", state=DISABLED)
    else:
        encryptedTextEntry = Entry(EncryptFrame, width = 58)
        decryptedTextEntry = Entry(DecryptFrame, width = 58, state=DISABLED)
    scrollbar.place(x=350, y=10, height=200)
    encryptedTextEntry.place(x=10, y=10)
    encryptedTextWidget.place(x=10, y=70)
    checkButton.place(x=117, y=38)
    encryButton.place(x=10, y=38)
    showCharCheck.place(x=260, y=40)
    copyButton.place(x=10, y=178)
    clearButton.place(x=87, y=178)
    about.place(x=10, y=10)
    decryptedTextEntry.place(x=10, y=150)
    decryptedTextWidget.place(x=10, y=10)
    decheckButton.place(x=160, y=117)
    decryButton.place(x=10, y=117)
    decopyButton.place(x=10, y=178)
    declearButton.place(x=87, y=178)
    depasteButton.place(x=300, y=117)
    logTextWidget.place(x=10, y=10)
    logTextWidget.config(state=NORMAL)
    logTextWidget.insert(INSERT, "ROOT: Created and placed all widgets.\n")
    logTextWidget.config(state=DISABLED)
    root.mainloop()
    print("MAINLOOP: Root quited mainloop.")
except:
    print("ERROR: Unexpected error occured. Program terminated.")
    messagebox.showerror("ERR_UNKNOWN_ERROR_OCCURED","An unexpected error occured in program. Program must be terminated. Please try again. If problem pertists, please report this probelm to me.")
