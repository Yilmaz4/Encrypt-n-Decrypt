from cryptography.fernet import Fernet
from time import sleep
from ctypes import windll
from tkinter.filedialog import asksaveasfilename
from tkinter import Tk
from platform import release, system, platform
from platform import version as platversion
from traceback import format_exc
from datetime import datetime
from sys import exit as System
from webbrowser import open
try:
    while True:
        try:
            version = "v0.2.3"
            build = "Build 14"
            windll.kernel32.SetConsoleTitleW("Encrypt'n'Decrypt {}".format(version))
            exit = False
            def Exit():
                exit()
            while True:
                print("██████████████████████████████████████████████████████████████████████████")
                if system() == "Windows":
                    if int(release()) == 10 or float(platversion()[:3]) == 6.3 or float(platversion()[:2]) == 6.2:
                        print("█████████████████████▓▒░ Encrypt'n'Decrypt {} ░▒▓█████████████████████".format(version))
                        print("██████████████████████████████████████████████████████████████████████████")
                        print("██████████████▓▒░ Write exit or quit to exit the program ░▒▓██████████████")
                    elif float(platversion()[:3]) == 6.1 or float(platversion()[:3]) == 6.0:
                        print("█████████████████████▓▒░ Encrypt'n'Decrypt {} ░▒▓█████████████████████".format(version))
                        print("██████████████████████████████████████████████████████████████████████████")
                        print("██████████████▓▒░ Write exit or quit to exit the program ░▒▓██████████████")
                    else:
                        print("████████████████████████ Encrypt'n'Decrypt {} ████████████████████████".format(version))
                        print("██████████████████████████████████████████████████████████████████████████")
                        print("█████████████████ Write exit or quit to exit the program █████████████████")
                else:
                    print("████████████████████████ Encrypt'n'Decrypt {} ████████████████████████".format(version))
                    print("██████████████████████████████████████████████████████████████████████████")
                    print("█████████████████ Write exit or quit to exit the program █████████████████")
                print("██████████████████████████████████████████████████████████████████████████")
                print("█                                  █ Version {} {} █ Main Menu █".format(version, build))
                while True:
                    print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
                    print("█ [1] Encryption                                                         █")
                    print("█ [2] Decryption                                                         █")
                    print("█ [3] About                                                              █")
                    print("█ [4] Exit                                                               █")
                    print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
                    while True:
                        try:
                            choice = input("Your choice: ")
                            choice = int(choice)
                            if choice == 1 or choice == 2 or choice == 3 or choice == 4:
                                break
                            else:
                                print("ERROR: Your choice must 1, 2, 3 or 4. Numbers are shown in top.")
                        except:
                            if choice == "exit" or choice == "quit" or choice == "q" or choice == "e":
                                exit = True
                                restart = False
                                restart2 = False
                                print("Quitting the program... Take care of yourself!")
                                break
                            elif choice == "":
                                print("ERROR: Please enter something.")
                            else:
                                print("ERROR: Your choice must be a number. Numbers are shown in top.")
                            restart2 = False
                        try:
                            if restart2 == True:
                                continue
                        except NameError:
                            continue
                    if exit == True:
                        exit = True
                        break
                    if choice == 1:
                        encryptText = input("Text: ")
                        print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
                        print("█ [1] Generate a random Fernet key                                       █") 
                        print("█ [2] Enter a Fernet key                                                 █")
                        print("█ [3] Back to Main Menu                                                  █")
                        print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
                        while True:
                            keychoice = input("Your choice: ")
                            try:
                                keychoice = int(keychoice)
                                if keychoice == 1 or keychoice == 2 or keychoice == 3:
                                    ItsInt = True
                                    break
                                else:
                                    print("ERROR: Your choice must 1, 2 or 3. Numbers are shown in top.")
                                    ItsInt = False
                            except:
                                ItsInt = False
                                if keychoice == "exit" or keychoice == "quit" or keychoice == "e" or keychoice == "q":
                                    restart = False
                                    restart2 = False
                                    exit = True
                                    break
                                elif keychoice == "":
                                    print("ERROR: Please enter a number.")
                                else:
                                    print("ERROR: Your choice must be a number. Numbers are shown in top.")
                        if ItsInt == True:
                            def EncryptionOutput():
                                if EncryptSucsess == True:
                                    print("  Encrypted text: ", encryptedText.decode())
                                    print("             Key: ", key.decode())
                                    print("")
                                    print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
                                    print("█ [1] Save the key to a file                                             █")
                                    print("█ [2] Back to Main Menu                                                  █")
                                    print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
                                    while True:
                                        choice2 = input("Your choice: ")
                                        try:
                                            try:
                                                choice2 = int(choice2)
                                                ItsInt = True
                                            except:
                                                ItsInt = False
                                                if choice2 == "exit" or choice2 == "quit" or choice2 == "e" or choice2 == "q":
                                                    restart = False
                                                    restart2 = False
                                                    exit = True
                                                    break
                                                elif choice2 == "Lmao":
                                                    print(coice2)
                                                else:
                                                    print("ERROR: Your choice must be a number. Numbers are shown in top.")
                                            if ItsInt == True:
                                                if choice2 == 1:
                                                    print("")
                                                    print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
                                                    print("█ [1] Save to 'Encryption Key.key' file                                  █")
                                                    print("█ [2] Save to 'Encryption Key.txt' file                                  █")
                                                    print("█ [3] Save as...                                                         █")
                                                    print("█ [4] Back to Main Menu                                                  █")
                                                    print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
                                                    while True:
                                                        choice3 = input("Your choice: ")
                                                        try:
                                                            choice3 = int(choice3)
                                                            if choice3 == 1:
                                                                with open("Encryption Key.key", "wb") as key_file:
                                                                    key_file.write(key)
                                                                    print("INFO: The key saved to 'Encryption Key.key' file sucsessfully.")
                                                                    exitLoop = False
                                                                    exitLoop2 = True
                                                                    break
                                                            elif choice3 == 2:
                                                                with open("Encryption Key.txt", "wb") as key_file:
                                                                    key_file.write(key)
                                                                    print("INFO: The key saved to 'Encryption Key.txt' file sucsessfully.")
                                                                    exitLoop = False
                                                                    exitLoop2 = True
                                                                    break
                                                            elif choice3 == 3:
                                                                try:
                                                                    root = Tk()
                                                                    files = [("Encrypt'n'Decrypt key file","*.key"),("Text document","*.txt"),("All files","*.*")]
                                                                    file = asksaveasfilename(initialfile="Encryption Key.key", filetypes=files, defaultextension="*.key")
                                                                    root.destroy()
                                                                except Exception as e:
                                                                    print(e)
                                                                if file == "":
                                                                    print("INFO: Canceled save as...")
                                                                    exitLoop = False
                                                                    exitLoop2 = True
                                                                    break
                                                                else:
                                                                    with open(file, "wb") as key_file:
                                                                        key_file.write(key)
                                                                        print("INFO: The key saved to '{}' file sucsessfully.".format(file))
                                                                        exitLoop = False
                                                                        exitLoop2 = True
                                                                        break
                                                            elif choice3 == 4:exitLoop = False;exitLoop2 = False;exit = False;break
                                                            else:print("ERROR: Your choice must be 1, 2, 3 or 4. Numbers are shown in top.")
                                                        except ValueError:
                                                            if choice3 == "exit" or choice3 == "quit" or choice3 == "e" or choice3 == "q":restart = False;restart2 = False;exit = True;Exit()
                                                            else:print("ERROR: Your choice must be a number. Numbers are shown in top.")
                                                    if exitLoop == True:exit = True;restart = False;restart2 = False;break
                                                    elif exitLoop2 == True:exit = False;restart = False;restart2 = False;break
                                                    else:exit = False;restart = False;restart2 = False;break
                                                elif choice2 == 2:break
                                                else:print("ERROR: Your choice must be 1 or 2. Numbers are shown in top.")
                                        except:
                                            if choice == "exit" or choice == "e" or choice == "quit" or choice == "q":exit = True;restart = False;restart2 = False;Exit()
                                            else:print("ERROR: Your choice must be a number. Numbers are shown in top.")
                                    try:
                                        if exit == True:restart = False;restart2 = False;print("Quitting the program... Take care of yourself!");Exit()
                                    except UnboundLocalError:pass
                            if keychoice == 1:
                                key = Fernet.generate_key();fernet = Fernet(key)
                                try:encryptedText = fernet.encrypt(encryptText.encode())
                                except:print("ERROR: An error occured while trying to encrypt the entered data. Entered text might not encryptable. Please report this problem to me.")
                                if fernet.decrypt(encryptedText).decode() == encryptText:EncryptSucsess = True;EncryptionOutput()
                                else:print("ERROR: Encryption check failed. Entered plain text and the output that was encrypted and then decrypted are not same. Please try again, if problem persists, report this problem to me.");EncryptSucsess = False
                            elif keychoice == 2:
                                while True:
                                    keyinput = input("Enter key: ")
                                    if keyinput == "reenter":break
                                    elif keyinput == "exit" or keyinput == "quit" or keyinput == "e" or keyinput == "q":Exit()
                                    try:key = bytes(keyinput, 'utf-8')
                                    except:print("ERROR: An error occured while trying to convert entered key into bytes. Please check the key.");continue
                                    try:fernet = Fernet(key)
                                    except:print("ERROR: An error occured while trying to define entered key into Fernet. Please check your key is 44 characters long and base64.urlsafe encoded.");continue
                                    try:encryptedText = fernet.encrypt(encryptText.encode())
                                    except:print("ERROR: An error occured while trying to encrypt the entered data. Entered text might not encryptable. Please report this problem to me.");continue
                                    if fernet.decrypt(encryptedText).decode() == encryptText:EncryptSucsess = True;EncryptionOutput();break
                                    else:print("ERROR: Encryption check failed. Entered plain text and the output that was encrypted and then decrypted are not same. Please try again, if problem persists, report this problem to me.");EncryptSucsess = False
                            elif keychoice == 3:break
                    elif choice == 2:
                        while True:
                            decryptText = input("Encrypted text: ")
                            if decryptText == "quit" or decryptText == "exit" or decryptText == "q" or decryptText == "e":exit = True;Exit()
                            elif decryptText == "no":exit = False;restart = False;restart2 = False;break
                            else:
                                try:key_file = open("Encryption Key.key",mode="r",encoding="utf-8");KeyFileExists = True;key_in_Key = key_file.read()
                                except:KeyFileExists = False
                                try:key_file2 = open("Encryption Key.txt",mode="r",encoding="utf-8");TxtFileExists = True;key_in_Txt = key_file2.read()
                                except:TxtFileExists = False
                                while True:
                                    try:
                                        if TxtFileExists == True and KeyFileExists == False:
                                            try:key = bytes(key_in_Txt, 'utf-8')
                                            except:print("ERROR: An error occured while trying to convert entered key to bytes.");continue
                                            try:fernet = Fernet(key)
                                            except:print("ERROR: An error occured while trying to use entered key. Key might invalid. If you entered Encrypted Text wrong, write 'reenter'.");continue
                                            try:decryptThis = bytes(decryptText, 'utf-8')
                                            except:print("ERROR: An error occured while trying to convert entered encrypted text to bytes.");continue
                                            try:decryptedText = fernet.decrypt(decryptThis).decode()
                                            except:
                                                fernet = Fernet(key2);decryptThis = bytes(decryptText, 'utf-8')
                                                try:decryptedText = fernet.decrypt(decryptThis).decode()
                                                except:TxtFileExists = False;continue
                                            print("INFO: Automatically used the key inside 'Encryption Key.txt' file.");print("Decrypted text: ", decryptedText);exit = True;main = True;break
                                        elif TxtFileExists == False and KeyFileExists == True:
                                            try:key = bytes(key_in_Key, 'utf-8')
                                            except:print("ERROR: An error occured while trying to convert entered key to bytes.");continue
                                            try:fernet = Fernet(key)
                                            except:print("ERROR: An error occured while trying to use entered key. Key might invalid. If you entered Encrypted Text wrong, write 'reenter'.");continue
                                            try:decryptThis = bytes(decryptText, 'utf-8')
                                            except:print("ERROR: An error occured while trying to convert entered encrypted text to bytes.");continue
                                            try:decryptedText = fernet.decrypt(decryptThis).decode()
                                            except:
                                                fernet = Fernet(key2);decryptThis = bytes(decryptText, 'utf-8')
                                                try:decryptedText = fernet.decrypt(decryptThis).decode()
                                                except:KeyFileExists = False;continue
                                            print("INFO: Automatically used the key inside 'Encryption Key.key' file.");print("Decrypted text: ", decryptedText);exit = True;main = True;break
                                        elif TxtFileExists == True and KeyFileExists == True:
                                            try:key = bytes(key_in_Key, 'utf-8');key2 = bytes(key_in_Txt, 'utf-8')
                                            except:print("ERROR: An error occured while trying to convert entered key to bytes.");continue
                                            try:fernet = Fernet(key);KeyFileUsed = True;TxtFileUsed = True
                                            except:
                                                try:fernet = Fernet(key2);KeyFileUsed = False;TxtFileUsed = True
                                                except:KeyFileExists = FalseTxtFileExists = False;continue
                                            try:decryptThis = bytes(decryptText, 'utf-8')
                                            except:print("ERROR: An error occured while trying to convert entered encrypted text to bytes.");continue
                                            try:decryptedText = fernet.decrypt(decryptThis).decode()
                                            except:
                                                fernet = Fernet(key2);decryptThis = bytes(decryptText, 'utf-8')
                                                try:decryptedText = fernet.decrypt(decryptThis).decode();print("INFO: Automatically used the key inside 'Encryption Key.txt' file.");print("Decrypted text: ", decryptedText);exit = True;main = True;break
                                                except:KeyFileExists = False;continue
                                            if KeyFileUsed == True:print("INFO: Automatically used the key inside 'Encryption Key.key' file.")
                                            elif TxtFileUsed == True:print("INFO: Automatically used the key inside 'Encryption Key.txt' file.")
                                            print("Decrypted text: ", decryptedText);exit = True;main = True;break
                                        elif KeyFileExists == False and TxtFileExists == False:
                                            if TxtFileExists == False and KeyFileExists == False:
                                                keyInput = input("Key: ")
                                                if keyInput == "reenter":main = True;break
                                                elif keyInput == "quit" or keyInput == "exit" or keyInput == "q" or keyInput == "e":exit = False;break
                                                try:key = bytes(keyInput, 'utf-8')
                                                except:print("ERROR: An error occured while trying to convert entered key to bytes.");continue
                                                try:fernet = Fernet(key)
                                                except:print("ERROR: An error occured while trying to use entered key. Key might invalid. If you entered Encrypted Text wrong, write 'reenter'.");continue
                                                try:decryptThis = bytes(decryptText, 'utf-8')
                                                except:print("ERROR: An error occured while trying to convert entered encrypted text to bytes.");continue
                                                try:decryptedText = fernet.decrypt(decryptThis).decode()
                                                except:print("ERROR: An error occured while trying to decrypt data. Entered encrypted text might entered wrong or entered key is not the right key to decrypt this data. If you entered Encrypted Text wrong, write 'reenter'.");continue
                                                print("Decrypted text: ", decryptedText);exit = True;main = True;break
                                    except:
                                        if TxtFileExists == False and KeyFileExists == False:
                                            keyInput = input("Key: ")
                                            if keyInput == "reenter":main = True;break
                                            elif keyInput == "quit" or keyInput == "exit" or keyInput == "q" or keyInput == "e":exit = False;Exit()
                                            try:key = bytes(keyInput, 'utf-8')
                                            except:print("ERROR: An error occured while trying to convert entered key to bytes.");continue
                                            try:fernet = Fernet(key)
                                            except:print("ERROR: An error occured while trying to use entered key. Key might invalid. If you entered Encrypted Text wrong, write 'reenter'.");continue
                                            try:decryptThis = bytes(decryptText, 'utf-8')
                                            except:print("ERROR: An error occured while trying to convert entered encrypted text to bytes.");continue
                                            try:decryptedText = fernet.decrypt(decryptThis).decode()
                                            except:print("ERROR: An error occured while trying to decrypt data. Entered encrypted text might entered wrong or entered key is not the right key to decrypt this data. If you entered Encrypted Text wrong, write 'reenter'.");continue
                                            print("Decrypted text: ", decryptedText);exit = True;main = True;break
                                if exit == True:
                                    if main == True:exit = False
                                    break
                        if exit == True:
                            restart = False;restart2 = False
                            print("Quitting the program... Take care of yourself!");Exit()
                    elif choice == 3:
                        print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
                        print("█ About Encrypt'n'Decrypt                                                █")
                        print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
                        print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
                        print("█ Hello everyone, this project is my second Python project and first     █")
                        print("█ project that I published in GitHub. This program can encrypt and       █")
                        print("█ decrypt plain texts with cryptography.fernet symmetric key encryption. █")
                        print("█ Program uses Python 3.7.9. First version of program (v0.1) is          █")
                        print("█ compatible with all OS's including Linux and MacOS except Windows XP   █")
                        print("█ and below but later versions currently only compatible with Windows    █")
                        print("█ OS's except Windows XP and below. Windows XP and below is not          █")
                        print("█ compatible with program due to Python 3.4 (Last python compatible      █")
                        print("█ with Windows XP) end-of-life.                                          █")
                        print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
                        print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
                        print("█ About encryption standart that program uses:                           █")
                        print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
                        print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
                        print("█ cryptography.fernet encryption is a symmetric key encryption standart  █")
                        print("█ which uses 44-characters long encryption key. Encryption key must be a █")
                        print("█ base64.urlsafe_b64encode encoded key. In fact this cryptography.fernet █")
                        print("█ key is 32 characters long AES-256 key but after encoding, key turns    █")
                        print("█ into 44-characters long key because cryptography.fernet only supports  █")
                        print("█ base64.urlsafe_b64encode encoded 44-characters long keys.              █")
                        print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
                        print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
                        print("█ For developers:                                                        █")
                        print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
                        print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
                        print("█ This project uses some libraries that must be installed using pip      █")
                        print("█ order to use them. Here are the all libraries must be installed using  █")
                        print("█ pip in order to run the source code:                                   █")
                        print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
                        print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
                        print("█ pip install cryptography                                               █")
                        print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
                        print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
                        print("█ All libraries used in this project are listed below:                   █")
                        print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
                        print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
                        print("█ from cryptography.fernet import Fernet                                 █")
                        print("█ from time import sleep                                                 █")
                        print("█ from ctypes import windll                                              █")
                        print("█ from tkinter.filedialog import asksaveasfilename                       █")
                        print("█ from tkinter import Tk                                                 █")
                        print("█ from platform import release, system, platform                         █")
                        print("█ from platform import version as platversion                            █")
                        print("█ import sys as System                                                   █")
                        print("█ import webbrowser                                                      █")
                        print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
                        print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
                        print("█ Version information                                                    █")
                        print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
                        print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
                        print("█ Version {} ({})                                              █".format(version, build))
                        print("█ github.com/Yilmaz4/Encrypt-n-Decrypt/releases                          █")
                        print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
                        print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
                        print("█ [1] Back to main menu                                                  █")
                        print("█ [2] Go to Encrypt'n'Decrypt GitHub page                                █")
                        print("█ [3] Show source code of Encrypt'n'Decrypt v0.2.3                       █")
                        print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
                        while True:
                            choiceabout = input("Your choice: ")
                            try:
                                choiceabout = int(choiceabout)
                                if choiceabout == 1 or choiceabout == 2 or choiceabout == 3:ItsInt = True;break
                                else:print("ERROR: Your choice must 1, 2 or 3. Numbers are shown in top.");ItsInt = False;continue
                            except:
                                if choiceabout == "exit" or choiceabout == "quit" or choiceabout == "e" or choiceabout == "q":restart = False;restart2 = False;exit = True;Exit()
                                else:print("ERROR: Your choice must be a number. Numbers are shown in top.");continue
                        if ItsInt == True:
                            if choiceabout == 1:pass
                            elif choiceabout == 2:webbrowser.open("https://github.com/Yilmaz4/Encrypt-n-Decrypt")
                            elif choiceabout == 3:print(open('tk/source.tcl',mode='r',encoding="utf-8").read())
                    elif choice == 4:
                        exit = True;restart = False;restart2 = False
                        print("Quitting the program... Take care of yourself!");Exit()
                    if exit == True:break
                try:
                    if exit == True:break
                    elif restart == True:continue
                    else:break
                except NameError:
                    try:
                        if exit == True:break
                        else:continue
                    except NameError:continue
        except Exception as e:
            print("")
            print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█") 
            print("█ ERROR: An unknown & unhandled error occured. Restarting program...     █")
            print("█                                                                        █")
            if len(str(e)) > 54:
                print("█ Error details:",str(e)[:54]+"  "+"█")
                print("█",str(e)[54:]+" "*(70-(len(str(e)[54:]))),"█")
            elif len(str(e)) <= 54:
                print("█ Error details:",e," "*(54-(len(str(e))))+" █")
            else:
                print("█ Error details:",str(e)[:54]+"  "+"█")
                print("█",(str(e)[54:])[:70]+" "*(70-(len(str(e)[54:]))),"█")
            print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
            print("")
            print("More details: [For technical users]")
            print(format_exc())
            with open("Encrypt.log",mode="w",encoding="utf-8") as LogFile:
                LogFile.write("Encrypt'n'Decrypt"+" "+version+" "+build+" Log File\n"+"Time: "+datetime.now().strftime("%H:%M:%S - %d/%m/%Y")+"\n\n");LogFile.write(format_exc())
            print("All details have been saved to 'Encrypt.log' file in the root folder.");sleep(4);continue
except KeyboardInterrupt:
    print("")
    print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█") 
    print("█ ERROR: KeyboardInterrupt occured! Do not press Ctrl+C or Ctrl+V unless █")
    print("█ you selected some text or copied a text.                               █")
    print("█                                                                        █")
    print("█ This exception is unhandable. Restarting in 2 seconds...               █")
    print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
    print("")
    sleep(2)
    try:exec("Encrypt.exe")
    except:pass
    pass