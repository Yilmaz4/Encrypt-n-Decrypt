from tkinter import *
from tkinter.ttk import *

special_chars = [' ','`','~','!','@','#','$','%','^','&','*','(',')','_','-','+','=','{','[','}','}','|','\\',':',';','"','\'','<',',','>','.','?','/']

class Entry(Entry):
    def replace(self, chars: str) -> None:
        self.delete(0, END)
        self.insert(0, chars)

    def clear(self):
        self.delete(0, END)

class Interface(Tk):
    def __init__(self):
        super().__init__()

        self.title("tExT cOnVeRtEr")
        self.geometry("300x200")

        self.label1 = Label(self, text="Input")
        self.entry = Entry(self, width=45)
        self.button = Button(self, text="cOnVeRt!", width=15, command=self.buttonCallback)
        self.output = Entry(self, width=20, state=DISABLED)

        self.label1.pack(side=TOP, pady=2, padx=8, anchor=NW)
        self.entry.pack(pady=0, padx=10, expand=False, fill=X)
        self.button.pack(pady=10, padx=10)
        self.output.pack(pady=0, padx=10, expand=False, fill=X)

        self.bind("<Return>", self.buttonCallback)

        self.mainloop()

    def buttonCallback(self):
        self.output.configure(state=NORMAL)
        self.output.clear()
        self.output.replace(self.convert(self.entry.get()))
        self.output.configure(state=DISABLED)

    @staticmethod
    def convert(text: str) -> str:
        new_text = str()
        for char, index in zip(text, range(1, len(text) + 1)):
            if new_text == "":
                new_text += char.lower()
            else:
                new_text += char.upper() if not bool(index % 2) else char.lower()

        return new_text

if __name__ == "__main__":
    root = Interface()
