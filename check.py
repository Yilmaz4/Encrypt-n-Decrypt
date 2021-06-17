import os;import sys;import requests;import json;from io import StringIO;from msvcrt import getch
def dict_to_object(d):
    if '__class__' in d:
        class_name = d.pop('__class__');module_name = d.pop('__module__');module = __import__(module_name)
        class_ = getattr(module, class_name);args = dict((key.encode('ascii'), value) for key, value in d.items());inst = class_(**args)
    else:inst = d
    return inst
def ensure_str(s):
    try:
        if isinstance(s, unicode):s = s.encode('utf-8')
    except:pass
    return s
full_names = [];headers = {}
if "GITHUB_TOKEN" in os.environ:headers["Authorization"] = "token %s" % os.environ["GITHUB_TOKEN"]
try:buf = StringIO();r = requests.get('https://api.github.com/users/' + "Yilmaz4" + '/repos', headers=headers);myobj = r.json()
except Exception as e:
    print("ERROR: Failed to connect to the GitHub API server. Please check your network connection and try again.")
    while True:
        choice = str(input("Error details? [Y,N]: "))
        if choice == "Y" or choice == "y":
            print(e)
            print("Press any key to continue . . . ", end=""),
            getch()
            sys.exit()
        elif choice == "N" or choice == "n":
            print("Press any key to continue . . . ", end=""),
            getch()
            sys.exit()
        else:print("ERROR: Invalid choice. Type 'Y' for 'Yes' and 'N' for 'No'.")
try:
    for rep in myobj:full_names.insert(0, ensure_str(rep['full_name']))
except TypeError:
    print("ERROR: GitHub API limit exceed. Please try again 1 hours later.")
    print("Press any key to continue . . . ",end="")
    print(" ", end="")
    getch()
    sys.exit()
for full_name in full_names:
    buf = StringIO();total_count = 0
    try:
        r = requests.get('https://api.github.com/repos/' + full_name + '/releases', headers=headers);myobj = r.json()
        for p in myobj:
            if "assets" in p:
                for asset in p['assets']:total_count += asset['download_count'];date = asset['updated_at'].split('T')[0];print('Repository: %s\tDate: %s\tAsset: %s\tCount: %d'%(full_name,date,asset['name'],asset['download_count']))
            else:print ("No data")
    except:pass
    print('%d\tTotal Downloads for repo %s' % (total_count, full_name))
    print('════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════')
print("Press any key to continue . . . ", end=""),
getch()
sys.exit()