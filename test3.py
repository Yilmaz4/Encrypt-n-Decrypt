import tqdm
import time
import msvcrt

LENGTH = 100 # Number of iterations required to fill pbar

pbar = tqdm.tqdm(total=LENGTH) # Init pbar
for i in range(LENGTH):
    pbar.update(n=1) # Increments counter
    time.sleep(0.1)
print("\nPress Enter to continue . . . ", end="")
msvcrt.getch()