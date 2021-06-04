if __import__("sys").version_info.major == 2:
    print("This script cannot run on Python 2. Please consider using Python 3 instead.")
else:
    from tkinter import *
    from tkinter import messagebox
    from tkinter import ttk
    from tkinter.ttk import *
from cryptography.fernet import Fernet
import pyperclip, os
#try:
if True:
    appWidth = 390
    appHeight = 275
    version = "v1.0"
    EncryptVersion = " Ὲɲcrƴpʈ'n Decrƴpʈ {}".format(version)
    root = Tk()
    root.title("{}".format(EncryptVersion))
    root.resizable(width=FALSE, height=FALSE)
    root.geometry("{}x{}".format(appWidth, appHeight))
    root.attributes("-fullscreen", False)
    root.minsize(appWidth, appHeight)
    if True:
        MainScreen = ttk.Notebook(root, width=380, height=340)
        LogFrame = Frame(MainScreen)
        logTextWidget = Text(LogFrame, height = 14, width = 56, font = ("Segoe UI", 9), state=DISABLED)
    logTextWidget.config(state=NORMAL)
    logTextWidget.insert(INSERT, "ROOT: Created root, started mainloop.\n")
    logTextWidget.config(state=DISABLED)
    menu = Menu(root)
    root.config(menu=menu)
    enterMenu = Menu(menu, tearoff=0)
    viewMenu = Menu(menu, tearoff=0)
    helpMenu = Menu(menu, tearoff=0)
    transMenu = Menu(viewMenu, tearoff=0)
    langMenu = Menu(viewMenu, tearoff=0)
    logTextWidget.config(state=NORMAL)
    logTextWidget.insert(INSERT, "ROOT: Registered menu entries.\n")
    logTextWidget.config(state=DISABLED)
    #root.iconbitmap('Ico.ico')
    def ShutDown():
        root.destroy()
        sys.exit()
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
        with open("Encryption Key.key", "wb") as key_file:
            key_file.write(key)
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
            messagebox.showerror("ERR_UNABLE_TO_ENCRYPT","An unknown error occured in encrypter. Please try again and if problem persists, please report this problem to me.")
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
                logTextWidget.insert(INSERT, "WARNING: Entered text is not encryptable.\n")
                logTextWidget.config(state=DISABLED)
                messagebox.showwarning("ERR_UNENCRYPTABLE_TEXT","Entered text is not encryptable. Please report this text to me.")
            else:
                logTextWidget.config(state=NORMAL)
                logTextWidget.insert(INSERT, "ERROR: An problem occured in encrypter.\n")
                logTextWidget.config(state=DISABLED)
                messagebox.showerror("ERR_ENCRYPTER_NOT_WORKING_PROPERLY","There is a problem occured in encrypter. Both entered text and 'abc' text failed encryption. Please try again and if problem persists, please report this problem to me.")
    def Copy():
        global encryptedTextWidget
        pyperclip.copy(encryptedTextWidget.get('1.0', END))
        copyed = pyperclip.paste()
        if copyed == (encryptedTextWidget.get('1.0', END)):
            messagebox.showinfo(" Copied.","Encrypted text copied to clipboard sucsessfully.")
    def Clear():
        global encryptedTextWidget
        try:
            encryptedTextWidget.configure(state=NORMAL)
            encryptedTextWidget.delete('1.0', END)
            encryptedTextWidget.configure(state=DISABLED)
        except:
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "ERROR: An unknown error occured when trying to clear output text.\n")
            logTextWidget.config(state=DISABLED)
            messagebox.showerror("ERR_UNABLE_TO_CLEAR","An unknown error occured while trying to clear output. Please try again and if problem persists, please report this problem to me.")
    def CheckEncrypt():
        global encryptedTextEntry
        try:
            textEncrypt = encryptedTextEntry.get()
            key = Fernet.generate_key()
            fernet = Fernet(key)
            encryptedText = fernet.encrypt(textEncrypt.encode())
            decryptedText = fernet.decrypt(encryptedText).decode()
        except:
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "ERROR: An error occured when trying to check encrypter.\n")
            logTextWidget.config(state=DISABLED)
            messagebox.showerror("ERR_UNABLE_TO_ENCRYPT","An unknown error occured while trying to check encrypter. Please try again and if problem persists, please report this problem to me.")
            ShutDown()
        if textEncrypt == decryptedText:
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "SUCSESS: Checked encrypter sucsessfully.\n")
            logTextWidget.config(state=DISABLED)
            messagebox.showinfo("Sucsess","Checked encrypter sucsessfully. Encrypter is working properly.")
        else:
            tryText = "abc"
            trykey = Fernet.generate_key()
            tryfernet = Fernet(trykey)
            tryEncryptedText = tryfernet.encrypt(tryText.encode())
            tryDecryptedText = tryfernet.decrypt(tryEncryptedText).decode()
            if tryText == tryDecryptedText:
                logTextWidget.config(state=NORMAL)
                logTextWidget.insert(INSERT, "WARNING: Entered text is not encryptable.\n")
                logTextWidget.config(state=DISABLED)
                messagebox.showwarning("ERR_UNENCRYPTABLE_TEXT","Entered text is not encryptable. Please report this text to me.")
            else:
                logTextWidget.config(state=NORMAL)
                logTextWidget.insert(INSERT, "ERROR: An problem occured in encrypter.\n")
                logTextWidget.config(state=DISABLED)
                messagebox.showwarning("ERR_ENCRYPTER_NOT_WORKING_PROPERLY","")
    def CheckDecrypt():
        global decryptedTextWidget
        try:
            textEncryptget = decryptedTextWidget.get('1.0',END)
            textEncrypt = bytes(textEncryptget, 'utf-8')
            key = load_key()
            fernet = Fernet(key)
            try:
                decryptedText = fernet.decrypt(textEncrypt).decode()
                logTextWidget.config(state=NORMAL)
                logTextWidget.insert(INSERT, "SUCSESS: Checked decrypter sucsessfully. Decrypter is working properly.\n")
                logTextWidget.config(state=DISABLED)
                messagebox.showinfo("Sucsess.","Checked decrypter sucsessfully. Decrypter is working properly.")
            except:
                logTextWidget.config(state=NORMAL)
                logTextWidget.insert(INSERT, "ERROR: Checked decrypter. Decrypter is not working properly.\n")
                logTextWidget.config(state=DISABLED)
                messagebox.showerror("ERR_UNABLE_TO_DECRYPT","Şifre çözücüde bir hata meydana geldi. Lütfen programı yeniden başlatıp tekrar deneyin.")
        except:
            print("ERROR: An error occured when trying to decrypt. Program will be terminated.")
            messagebox.showerror(" Hata: ERR_UNABLE_TO_DECRYPT","Şifre çözücüde bir hata meydana geldi. Lütfen programı yeniden başlatıp tekrar deneyin.")
    def load_key():
        try:
            return open("Encryption Key.key", "rb").read()
        except:
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "ERROR: An error occured while trying to get the key from 'Encryption Key.key' file.\n")
            logTextWidget.config(state=DISABLED)
            messagebox.showerror("ERR_UNABLE_TO_GET_DATA_FROM_FILE","An error occured while trying to get the key from 'Encryption Key.key' file. The file may be missing, corrupt or inaccessable. Please try again; if problem persists, try to run the program as administrator.")
    def Decrypt():
        global decryptedTextEntry, decryptedTextWidget, decryptedText
        try:
            textEncryptget = decryptedTextWidget.get('1.0',END)
            textEncrypt = bytes(textEncryptget, 'utf-8')
            key = load_key()
            fernet = Fernet(key)
        except:
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "ERROR: An error occured while trying to use the key inside file.\n")
            logTextWidget.config(state=DISABLED)
            messagebox.showerror("ERR_UNABLE_TO_DECRYPT","An error occured while trying to load the key inside 'Encryption Key.key'. Please try again.")
            Fail = True
        try:
            decryptedText = fernet.decrypt(textEncrypt).decode()
        except:
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "ERROR: Decryption failed probably because of wrong key.\n")
            logTextWidget.config(state=DISABLED)
            messagebox.showinfo("ERR_WRONG_KEY","The key inside 'Encryption Key.key' is not the right key to decrypt this data.")
            Fail = True
        #if decryptedText != "":
        if True:
            try:
                decryptedTextEntry.configure(state=NORMAL)
                decryptedTextEntry.delete(0, END)
                decryptedTextEntry.insert(0, decryptedText)
                decryptedTextEntry.configure(state=DISABLED)
            except NameError:
                decryptedTextEntry.configure(state=DISABLED)
        #else:
            #decryptedTextEntry.configure(state=NORMAL)
            #decryptedTextEntry.delete(0, END)
            #decryptedTextEntry.insert(0, decryptedText+"(Blank)")
            #decryptedTextEntry.configure(state=DISABLED)
        if Fail != True:
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "SUCSESS: Entered encrypted text sucsessfully decrypted.\n")
            logTextWidget.config(state=DISABLED)
    def deCopy():
        global decryptedTextEntry
        pyperclip.copy(decryptedTextEntry.get())
        messagebox.showinfo(" Kopyalandı.","Şifresi çözülmüş yazı başarıyla panoya kopyalandı.")
    def deClear():
        global decryptedTextEntry
        try:
            decryptedTextEntry.configure(state=NORMAL)
            decryptedTextEntry.delete(0, END)
            decryptedTextEntry.configure(state=DISABLED)
        except:
            print("ERROR: An error occured when trying to clear output text. Program will be terminated.")
            messagebox.showerror(" Hata: ERR_UNABLE_TO_CLEAR","Programda bir hata meydana geldi. Lütfen programı yeniden başlatıp tekrar deneyin.")
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
            messagebox.showinfo(" Kopyalanmış yazı yok.","Şu anda kopyaladığınız bir yazı ya da şifre yok. Lütfen tekrar kopyalamayı deneyin.")
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
    def EncryptPage():
        MainScreen.select(0)
    def DecryptPage():
        MainScreen.select(1)
    def HelpPage():
        MainScreen.select(3)
    Alpha = IntVar()
    Alpha.set(100)
    def changeAlpha(alpha):
        if alpha != 100:
            alpha = '0.{}'.format(alpha)
        else:
            alpha = 1
        root.attributes("-alpha", float(alpha))
    logTextWidget.config(state=NORMAL)
    logTextWidget.insert(INSERT, "ROOT: Registered define commands.\n")
    logTextWidget.config(state=DISABLED)
    screenWidth = root.winfo_screenwidth()
    screenHeight = root.winfo_screenheight()
    logTextWidget.config(state=NORMAL)
    logTextWidget.insert(INSERT, "ROOT: Created main menu.\n")
    logTextWidget.config(state=DISABLED)
    Menu = Menu(root)
    EncryptFrame = Frame(MainScreen)
    DecryptFrame = Frame(MainScreen)
    AboutFrame   = Frame(MainScreen)
    EncryptFrameLabel = LabelFrame(EncryptFrame, text="Output", height=165, width=355)
    MainScreen.add(EncryptFrame, text="Encryption")
    MainScreen.add(DecryptFrame, text="Decryption")
    #MainScreen.add(LogFrame, text="Logs")
    MainScreen.add(AboutFrame, text="Help & About")
    MainScreen.pack(fill=BOTH, expand=1, pady=4, padx=4, side=TOP)
    EncryptFrameLabel.place(x=10, y=67)
    if True: #Sub-Menus
        enterMenu.add_command(label = "Encrypt", command=EncryptPage)
        enterMenu.add_command(label = "Decrypt", command=DecryptPage)
        enterMenu.add_separator()
        enterMenu.add_command(label = "Exit", accelerator="Alt+F4")
        viewMenu.add_checkbutton(label = "Show info message dialogs")
        viewMenu.add_checkbutton(label = "Show warning message dialogs")
        viewMenu.add_checkbutton(label = "Show error message dialogs")
        viewMenu.add_separator()
        if True: #Transparency sub-menu
            transMenu.add_radiobutton(label = "%20", value=20, variable=Alpha, command=lambda:changeAlpha(20))
            transMenu.add_radiobutton(label = "%40", value=40, variable=Alpha, command=lambda:changeAlpha(40))
            transMenu.add_radiobutton(label = "%60", value=60, variable=Alpha, command=lambda:changeAlpha(60))
            transMenu.add_radiobutton(label = "%80", value=80, variable=Alpha, command=lambda:changeAlpha(80))
            transMenu.add_radiobutton(label = "%90", value=90, variable=Alpha, command=lambda:changeAlpha(90))
            transMenu.add_radiobutton(label = "Opaque", value=100, variable=Alpha, command=lambda:changeAlpha(100))
            transMenu.add_separator()
            transMenu.add_command(label = "Reset opacity", command=lambda:changeAlpha(100))
            viewMenu.add_cascade(menu=transMenu, label = "Window opacity")
        viewMenu.add_separator()
        if True: #Language sub-menu
            langMenu.add_radiobutton(label = "English [Coming Soon]")
            langMenu.add_radiobutton(label = "Türkçe [Yakında Geliyor]", state=DISABLED)
            langMenu.add_radiobutton(label = "Deutsche [Kommt Bald]", state=DISABLED)
            langMenu.add_radiobutton(label = "中国人 [即将推出]", state=DISABLED)
            langMenu.add_separator()
            langMenu.add_command(label = "Reset language to default")
            viewMenu.add_cascade(menu=langMenu, label ="Language")
        menu.add_cascade(label = "Main", menu=enterMenu)
        menu.add_cascade(label = "View", menu=viewMenu)
        menu.add_command(label = "Help", command=HelpPage)
    logTextWidget.config(state=NORMAL)
    logTextWidget.insert(INSERT, "ROOT: Created menu.\n")
    logTextWidget.config(state=DISABLED)
    encryButton = Button(EncryptFrame, text = "Encrypt", width=15, command=Encrypt)
    checkButton = Button(EncryptFrame, text = "Check encryption", width=20, command=CheckEncrypt)
    copyButton = Button(EncryptFrameLabel, text = "Copy", width=10, command=Copy)
    clearButton = Button(EncryptFrameLabel, text = "Clear", width=9, command=Clear)
    showCharCheck = Checkbutton(EncryptFrame, text = "Hide characters", variable = showCharState, onvalue = 1, offvalue = 0, command = toggleHideChar)
    encryptedTextWidget = Text(EncryptFrameLabel, height = 6, width = 47, state=DISABLED, font = ("Consolas", 9))
    decryButton = Button(DecryptFrame, text = "Decrypt", width=22, command=Decrypt)
    decheckButton = Button(DecryptFrame, text = "Check decryption", width=20, command=CheckDecrypt)
    decopyButton = Button(DecryptFrame, text = "Copy", width=10, command=deCopy)
    declearButton = Button(DecryptFrame, text = "Clear", width=9, command=deClear)
    depasteButton = Button(DecryptFrame, text = "Paste", width=9, command=dePaste)
    #howItWorks = Button(EncryptFrameLabel, text="How encryption works?", width=25)
    #enClearButton = Button(EncryptFrame, text="Temizle", width=13)
    #enCopyButton = Button(EncryptFrame, text="Kopyala", width=13)
    decryptedTextWidget = Text(DecryptFrame, height = 6, width = 58, font = ("Segoe UI", 9))
    scrollbar = Scrollbar(LogFrame)
    logTextWidget.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=logTextWidget.yview)
    about = Text(AboutFrame, height = 13, width = 58, font = ("Segoe UI", 9))
    Text = "Bu program, 44-bit'lik şifreleme standardında girdiğiniz harf, kelime ya da cümleleri şifreler. Her yeni bir şifrelemede bu programın bulunduğu dizindeki 'Encryption Key.key' dosyasını yenileyerek en son şifrelediğiniz terimin şifresinin çözülmesi gereken anahtarı içerisine yazar. En son şifrelediğiniz terimin şifresini paylaşmak ve bir başkasının bu şifreyi çözebilmesini sağlamak için 'Encryption Key.key' dosyasını paylaşmalısınız. İsterseniz şifrelediğiniz terimi şifre çözme bölümüne yazıp gerekli şifre çözme anahtarı dosyasını gerekli konuma koyarak şifrenizi de çözebilirsiniz.\n\nVersiyon: {}\nYapımcı: Yılmaz Alpaslan\n© YLMZ Yazılımcılık™ Ltd.".format(version)
    about.insert(INSERT, Text)
    about.configure(state=DISABLED)
    if showChar == False:
        encryptedTextEntry = Entry(EncryptFrame, width = 58, show = "*")
        decryptedTextEntry = Entry(DecryptFrame, width = 58, show = "*", state=DISABLED)
    else:
        encryptedTextEntry = Entry(EncryptFrame, width = 58)
        decryptedTextEntry = Entry(DecryptFrame, width = 58, state=DISABLED)
    scrollbar.place(x=350, y=10, height=214)
    #enCopyButton.place(x=105, y=70)
    #enClearButton.place(x=10, y=70)
    encryptedTextEntry.place(x=10, y=10)
    encryptedTextWidget.place(x=9, y=5)
    checkButton.place(x=117, y=38)
    encryButton.place(x=10, y=38)
    showCharCheck.place(x=261, y=40)
    copyButton.place(x=8, y=110)
    clearButton.place(x=85, y=110)
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
    #howItWorks.place(x=179, y=110)
    logTextWidget.insert(INSERT, "ROOT: Created and placed all widgets.\n")
    logTextWidget.config(state=DISABLED)
    root.mainloop()
    print("MAINLOOP: Root quited mainloop.")
#except:
    #print("ERROR: Unexpected error occured. 0xu0000001a")
    #messagebox.showerror(" Hata.","Uygulamada bilinmeyen beklenmedik bir hata oluştu. Hata örtbas edilmeye çalışılacak, başarısız olunursa program kapatılacak.\n\n0xu0000001a")