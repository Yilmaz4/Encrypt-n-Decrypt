from cryptography.fernet import Fernet
from time import sleep
from sys import exit
from ctypes import windll
from tkinter.filedialog import asksaveasfilename
from tkinter import Tk
version = "v0.2.2"
windll.kernel32.SetConsoleTitleW("Encrypt'n'Decrypt {}".format(version))
exit = False
while True:
    print("██████████████████████████████████████████████████████████")
    print("█████████████▓▒░ Ὲɲcrƴpʈ'n'Decrƴpʈ {} ░▒▓█████████████".format(version))
    print("██████████████████████████████████████████████████████████")
    print("██████▓▒░ Write exit or quit to exit the program ░▒▓██████")
    print("██████████████████████████████████████████████████████████")
    print("█                  █ Version v0.2.2 Build 13 █ Main Menu █")
    while True:
        print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
        print("█ [1] Encryption                                         █")
        print("█ [2] Decryption                                         █")
        print("█ [3] Exit                                               █")
        print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
        while True:
            try:
                choice = input("Your choice: ")
                choice = int(choice)
                if choice == 1 or choice == 2 or choice == 3:
                    break
                elif choice == 31:
                    print("Hey! Stop it.")
                else:
                    print("ERROR: Your choice must 1, 2 or 3. Numbers are shown in top.")
            except:
                if choice == "exit" or choice == "quit" or choice == "q" or choice == "e":
                    exit = True
                    restart = False
                    restart2 = False
                    print("Quitting the program... Take care of yourself!")
                    break
                elif choice == "rs" or choice == "re":
                    exit == False
                    restart = True
                    print("Hey! You just found an easter egg.")
                    sleep(2)
                    print("Please don't share this secret easter egg, let others fing this themselves! :)")
                    sleep(5)
                    print("Restarting the program... Please wait.")
                    break
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
            key = Fernet.generate_key()
            fernet = Fernet(key)
            try:
                encryptedText = fernet.encrypt(encryptText.encode())
            except:
                print("ERROR: An error occured while trying to encrypt the entered data. Entered text might not encryptable. Please report this problem to me.")
            print("  Encrypted text: ", encryptedText.decode())
            print("             Key: ", key.decode())
            print("")
            print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
            print("█ [1] Save the key to a file                             █") 
            print("█ [2] Back to Main Menu                                  █")
            print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
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
                        else:
                            print("ERROR: Your choice must be a number. Numbers are shown in top.")
                    if ItsInt == True:
                        if choice2 == 1:
                            print("")
                            print("█▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀█")
                            print("█ [1] Save to 'Encryption Key.key' file                  █")
                            print("█ [2] Save to 'Encryption Key.txt' file                  █")
                            print("█ [3] Save as...                                         █")
                            print("█ [4] Back to Main Menu                                  █")
                            print("█▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄█")
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
                                        root = Tk()
                                        files = [("Encrypt'n'Decrypt key file","*.key"),("Text document","*.txt"),("All files","*.*")]
                                        file = asksaveasfilename(initialfile="Encryption Key.key", filetypes=files, defaultextension="*.key")
                                        if file == "":
                                            print("INFO: Canceled save as...")
                                            root.destroy()
                                            exitLoop = False
                                            exitLoop2 = True
                                            break
                                        else:
                                            with open(file, "wb") as key_file:
                                                key_file.write(key)
                                                print("INFO: The key saved to '{}' file sucsessfully.".format(file))
                                                root.destroy()
                                                exitLoop = False
                                                exitLoop2 = True
                                                break
                                    elif choice3 == 4:
                                        exitLoop = False
                                        exitLoop2 = False
                                        exit = False
                                        break
                                    else:
                                        print("ERROR: Your choice must be 1, 2, 3 or 4. Numbers are shown in top.")
                                except ValueError:
                                    if choice3 == "exit" or choice3 == "quit" or choice3 == "e" or choice3 == "q":
                                        restart = False
                                        restart2 = False
                                        exit = True
                                        break
                                    else:
                                        print("ERROR: Your choice must be a number. Numbers are shown in top.")
                            if exitLoop == True:
                                exit = True
                                restart = False
                                restart2 = False
                                break
                            elif exitLoop2 == True:
                                exit = False
                                restart = False
                                restart2 = False
                                break
                            else:
                                exit = False
                                restart = False
                                restart2 = False
                                break
                        elif choice2 == 2:
                            break
                        else:
                            print("ERROR: Your choice must be 1 or 2. Numbers are shown in top.")
                except:
                    if choice == "exit" or choice == "e" or choice == "quit" or choice == "q":
                        exit = True
                        restart = False
                        restart2 = False
                        break
                    else:
                        print("ERROR: Your choice must be a number. Numbers are shown in top.")
            if exit == True:
                restart = False
                restart2 = False
                print("Quitting the program... Take care of yourself!")
                break
        elif choice == 2:
            while True:
                decryptText = input("Encrypted text: ")
                if decryptText == "quit" or decryptText == "exit" or decryptText == "q" or decryptText == "e":
                    exit = True
                    break
                elif decryptText == "no":
                    exit = False
                    restart = False
                    restart2 = False
                    break
                else:
                    try:
                        key_file = open("Encryption Key.key",mode="r",encoding="utf-8")
                        KeyFileExists = True
                        key_in_Key = key_file.read()
                    except:
                        KeyFileExists = False
                    try:
                        key_file2 = open("Encryption Key.txt",mode="r",encoding="utf-8")
                        TxtFileExists = True
                        key_in_Txt = key_file2.read()
                    except:
                        TxtFileExists = False
                    while True:
                        try:
                            if TxtFileExists == True and KeyFileExists == False:
                                try:
                                    key = bytes(key_in_Txt, 'utf-8')
                                except:
                                    print("ERROR: An error occured while trying to convert entered key to bytes.")
                                    continue
                                try:
                                    fernet = Fernet(key)
                                except:
                                    print("ERROR: An error occured while trying to use entered key. Key might invalid. If you entered Encrypted Text wrong, write 'reenter'.")
                                    continue
                                try:
                                    decryptThis = bytes(decryptText, 'utf-8')
                                except:
                                    print("ERROR: An error occured while trying to convert entered encrypted text to bytes.")
                                    continue
                                try:
                                    decryptedText = fernet.decrypt(decryptThis).decode()
                                except:
                                    fernet = Fernet(key2)
                                    decryptThis = bytes(decryptText, 'utf-8')
                                    try:
                                        decryptedText = fernet.decrypt(decryptThis).decode()
                                    except:
                                        TxtFileExists = False
                                        continue
                                print("INFO: Automatically used the key inside 'Encryption Key.txt' file.")
                                print("Decrypted text: ", decryptedText)
                                exit = True
                                main = True
                                break
                            elif TxtFileExists == False and KeyFileExists == True:
                                try:
                                    key = bytes(key_in_Key, 'utf-8')
                                except:
                                    print("ERROR: An error occured while trying to convert entered key to bytes.")
                                    continue
                                try:
                                    fernet = Fernet(key)
                                except:
                                    print("ERROR: An error occured while trying to use entered key. Key might invalid. If you entered Encrypted Text wrong, write 'reenter'.")
                                    continue
                                try:
                                    decryptThis = bytes(decryptText, 'utf-8')
                                except:
                                    print("ERROR: An error occured while trying to convert entered encrypted text to bytes.")
                                    continue
                                try:
                                    decryptedText = fernet.decrypt(decryptThis).decode()
                                except:
                                    fernet = Fernet(key2)
                                    decryptThis = bytes(decryptText, 'utf-8')
                                    try:
                                        decryptedText = fernet.decrypt(decryptThis).decode()
                                    except:
                                        KeyFileExists = False
                                        continue
                                print("INFO: Automatically used the key inside 'Encryption Key.key' file.")
                                print("Decrypted text: ", decryptedText)
                                exit = True
                                main = True
                                break
                            elif TxtFileExists == True and KeyFileExists == True:
                                try:
                                    key = bytes(key_in_Key, 'utf-8')
                                    key2 = bytes(key_in_Txt, 'utf-8')
                                except:
                                    print("ERROR: An error occured while trying to convert entered key to bytes.")
                                    continue
                                try:
                                    fernet = Fernet(key)
                                except:
                                    print("ERROR: An error occured while trying to use entered key. Key might invalid. If you entered Encrypted Text wrong, write 'reenter'.")
                                    continue
                                try:
                                    decryptThis = bytes(decryptText, 'utf-8')
                                except:
                                    print("ERROR: An error occured while trying to convert entered encrypted text to bytes.")
                                    continue
                                try:
                                    decryptedText = fernet.decrypt(decryptThis).decode()
                                except:
                                    fernet = Fernet(key2)
                                    decryptThis = bytes(decryptText, 'utf-8')
                                    try:
                                        decryptedText = fernet.decrypt(decryptThis).decode()
                                        print("INFO: Automatically used the key inside 'Encryption Key.txt' file.")
                                        print("Decrypted text: ", decryptedText)
                                        exit = True
                                        main = True
                                        break
                                    except:
                                        KeyFileExists = False
                                        continue
                                print("INFO: Automatically used the key inside 'Encryption Key.key' file.")
                                print("Decrypted text: ", decryptedText)
                                exit = True
                                main = True
                                break
                            elif KeyFileExists == False and TxtFileExists == False:
                                if TxtFileExists == False and KeyFileExists == False:
                                    keyInput = input("Key: ")
                                    if keyInput == "reenter":
                                        main = True
                                        break
                                    elif keyInput == "quit" or keyInput == "exit" or keyInput == "q" or keyInput == "e":
                                        exit = False
                                        break
                                    try:
                                        key = bytes(keyInput, 'utf-8')
                                    except:
                                        print("ERROR: An error occured while trying to convert entered key to bytes.")
                                        continue
                                    try:
                                        fernet = Fernet(key)
                                    except:
                                        print("ERROR: An error occured while trying to use entered key. Key might invalid. If you entered Encrypted Text wrong, write 'reenter'.")
                                        continue
                                    try:
                                        decryptThis = bytes(decryptText, 'utf-8')
                                    except:
                                        print("ERROR: An error occured while trying to convert entered encrypted text to bytes.")
                                        continue
                                    try:
                                        decryptedText = fernet.decrypt(decryptThis).decode()
                                    except:
                                        print("ERROR: An error occured while trying to decrypt data. Entered encrypted text might entered wrong or entered key is not the right key to decrypt this data. If you entered Encrypted Text wrong, write 'reenter'.")
                                        continue
                                    print("Decrypted text: ", decryptedText)
                                    exit = True
                                    main = True
                                    break
                        except:
                            if TxtFileExists == False and KeyFileExists == False:
                                keyInput = input("Key: ")
                                if keyInput == "reenter":
                                    main = True
                                    break
                                elif keyInput == "quit" or keyInput == "exit" or keyInput == "q" or keyInput == "e":
                                    exit = False
                                    break
                                try:
                                    key = bytes(keyInput, 'utf-8')
                                except:
                                    print("ERROR: An error occured while trying to convert entered key to bytes.")
                                    continue
                                try:
                                    fernet = Fernet(key)
                                except:
                                    print("ERROR: An error occured while trying to use entered key. Key might invalid. If you entered Encrypted Text wrong, write 'reenter'.")
                                    continue
                                try:
                                    decryptThis = bytes(decryptText, 'utf-8')
                                except:
                                    print("ERROR: An error occured while trying to convert entered encrypted text to bytes.")
                                    continue
                                try:
                                    decryptedText = fernet.decrypt(decryptThis).decode()
                                except:
                                    print("ERROR: An error occured while trying to decrypt data. Entered encrypted text might entered wrong or entered key is not the right key to decrypt this data. If you entered Encrypted Text wrong, write 'reenter'.")
                                    continue
                                print("Decrypted text: ", decryptedText)
                                exit = True
                                main = True
                                break
                    if exit == True:
                        if main == True:
                            exit = False
                        break
            if exit == True:
                restart = False
                restart2 = False
                print("Quitting the program... Take care of yourself!")
                break
        elif choice == 3:
            exit == True
            restart = False
            restart2 = False
            print("Quitting the program... Take care of yourself!")
            break
        if exit == True:
            break
    try:
        if exit == True:
            break
        elif restart == True:
            continue
        else:
            break
    except NameError:
        try:
            if exit == True:
                break
            else:
                continue
        except NameError:
            continue