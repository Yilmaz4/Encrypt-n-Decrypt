from cryptography.fernet import Fernet
from time import sleep
exit = False
while True:
    print("**********************************************************")
    print("********* Encrypt'n'Decrypt v0.1 [First release] *********")
    print("**********************************************************")
    print("********* Write exit or quit to exit the program *********")
    while True:
        print("______________")
        print("[1] Encryption")
        print("[2] Decryption")
        while True:
            try:
                choice = input("Your choice: ")
                choice = int(choice)
                if choice == 1 or choice == 2:
                    break
                elif choice == 31:
                    print("Hey! Stop it.")
                else:
                    print("ERROR: Your choice must 1 or 2. Numbers are shown in top.")
            except:
                if choice == "exit" or choice == "quit" or choice == "q" or choice == "e":
                    exit = True
                    restart = False
                    restart2 = False
                    print("Quitting the program... Take care of yourself!")
                    break
                elif choice == "Fuck" or choice == "fuck":
                    print("What did you say? Not funny.")
                    restart2 = True
                    break
                elif choice == "fuck u" or choice == "fuck you" or choice == "Fuck u" or choice == "Fuck you":
                    print("Why don't you try to be more respectful?")
                    restart2 = True
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
            if restart2 == True:
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
            print("Encrypted text: ", encryptedText.decode())
            print("Key: ", key.decode())
        elif choice == 2:
            while True:
                decryptText = input("Encrypted text: ")
                if decryptText == "quit" or decryptText == "exit" or decryptText == "q" or decryptText == "e":
                    exit = True
                    print("Quitting the program... Take care of yourself!")
                    break
                elif decryptText == "no":
                    exit = False
                    restart = False
                    restart2 = False
                    break
                while True:
                    keyInput = input("Key: ")
                    if keyInput == "reenter":
                        break
                    elif keyInput == "quit" or keyInput == "exit" or keyInput == "q" or keyInput == "e":
                        exit = True
                        print("Quitting the program... Take care of yourself!")
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
