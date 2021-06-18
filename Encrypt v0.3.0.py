if __import__("sys").version_info.major == 2:
    from sys import exit
    print("Python 2.x is not supported due to incompatible syntax. Please use Python 3.x instead.")
    choice = str(input("Do you still want to run the code? [Y|N]: "))
    if choice == "Y":
        from Tkinter import *
        from Tkinter.commondialog import Dialog
        from ttk import *
    else:
        exit()
else:
    from tkinter import *
    from tkinter.commondialog import Dialog
    from tkinter import ttk
    from tkinter.ttk import *

from ttkthemes import ThemedStyle
import pyperclip, os, base64, binascii, struct, time, typing, collections, warnings
from sys import exit, path, platform

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Counter
from Crypto import Random
from Crypto.PublicKey import RSA

from cryptography import utils

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import _get_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

from requests import get, head
from urllib.request import urlretrieve
from webbrowser import open as openweb
from random import randint, choice
from string import ascii_letters, digits
from markdown import markdown
from tkinterweb import HtmlFrame
from PIL import Image, ImageTk
from getpass import getuser
def is_admin():
    try:return windll.shell32.IsUserAnAdmin()
    except:return False
_MAX_CLOCK_SKEW = 60
ERROR = "error";INFO = "info";QUESTION = "question";WARNING = "warning";ABORTRETRYIGNORE = "abortretryignore";OK = "ok";OKCANCEL = "okcancel";RETRYCANCEL = "retrycancel";YESNO = "yesno";YESNOCANCEL = "yesnocancel";ABORT = "abort";RETRY = "retry";IGNORE = "ignore";OK = "ok";CANCEL = "cancel";YES = "yes";NO = "no";_UNIXCONFDIR = '/etc';_ver_stages={'dev':10,'alpha':20,'a':20,'beta':30,'b':30,'c':40,'RC':50,'rc':50,'pl': 200, 'p': 200,};uname_result = collections.namedtuple("uname_result","system node release version machine processor");_uname_cache = None;_WIN32_CLIENT_RELEASES = {(5, 0): "2000",(5, 1): "XP",(5, 2): "2003Server",(5, None): "post2003",(6, 0): "Vista",(6, 1): "7",(6, 2): "8",(6, 3): "8.1",(6, None): "post8.1",(10, 0): "10",(10, None): "post10",}
class Message(Dialog):command  = "tk_messageBox"
try:DEV_NULL = os.devnull
except AttributeError:
    if platform in ('dos', 'win32', 'win16'):DEV_NULL = 'NUL'
    else:DEV_NULL = '/dev/null'
def _node(default=''):
    try:import socket
    except ImportError:return default
    try:return socket.gethostname()
    except OSError:return default
def win32_ver(release='', version='', csd='', ptype=''):
    try:from sys import getwindowsversion
    except ImportError:return release, version, csd, ptype
    winver = getwindowsversion();maj, min, build = winver.platform_version or winver[:3];version = '{0}.{1}.{2}'.format(maj, min, build);release = (_WIN32_CLIENT_RELEASES.get((maj, min)) or _WIN32_CLIENT_RELEASES.get((maj, None)) or release)
    if winver[:2] == (maj, min):
        try:csd = 'SP{}'.format(winver.service_pack_major)
        except AttributeError:
            if csd[:13] == 'Service Pack ':csd = 'SP' + csd[13:]
    try:
        import winreg
    except ImportError:pass
    else:
        try:
            cvkey = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            with winreg.OpenKeyEx(winreg.HKEY_LOCAL_MACHINE, cvkey) as key:ptype = winreg.QueryValueEx(key, 'CurrentType')[0]
        except OSError:pass
    return release, version, csd, ptype
def uname():
    global _uname_cache;no_os_uname=0
    if _uname_cache is not None:return _uname_cache
    processor=''
    try:system, node, release, version, machine = os.uname()
    except AttributeError:no_os_uname=1
    if no_os_uname or not list(filter(None,(system,node,release,version,machine))):
        if no_os_uname:system = platform;release='';version='';node=_node();machine=''
        use_syscmd_ver=1
        if system=='win32':
            release,version,csd,ptype=win32_ver()
            if release and version:use_syscmd_ver=0
            if not machine:
                if "PROCESSOR_ARCHITEW6432" in os.environ:machine = os.environ.get("PROCESSOR_ARCHITEW6432",'')
                else:machine = os.environ.get('PROCESSOR_ARCHITECTURE','')
            if not processor:processor = os.environ.get('PROCESSOR_IDENTIFIER',machine)
        if system in ('win32', 'win16'):
            if not version:
                if system=='win32':version='32bit'
                else:version='16bit'
            system='Windows'
    if system=='unknown':system=''
    if node=='unknown':node=''
    if release=='unknown':release=''
    if version=='unknown':version=''
    if machine=='unknown':machine=''
    if processor=='unknown':processor=''
    if system=='Microsoft' and release=='Windows':system='Windows';release='Vista'
    _uname_cache=uname_result(system,node,release,version,machine,processor)
    return _uname_cache
def _show(title=None, message=None, _icon=None, _type=None, **options):
    if _icon and "icon" not in options:    options["icon"] = _icon
    if _type and "type" not in options:    options["type"] = _type
    if title:   options["title"] = title
    if message: options["message"] = message
    res = Message(**options).show()
    if isinstance(res, bool):
        if res:return YES
        return NO
    return str(res)
class InvalidToken(Exception):pass
class messagebox():
    def showinfo(title=None, message=None, **options):
        if InfoVar.get() == 1:return _show(title, message, INFO, OK, **options)
    def showwarning(title=None, message=None, **options):
        if WarningVar.get() == 1:return _show(title, message, WARNING, OK, **options)
    def showerror(title=None, message=None, **options):
        if ErrorVar.get() == 1:return _show(title, message, ERROR, OK, **options)
    def askquestion(title=None, message=None, **options):return _show(title, message, QUESTION, YESNO, **options)
    def askokcancel(title=None, message=None, **options):s = _show(title, message, QUESTION, OKCANCEL, **options);return s == OK
    def askyesno(title=None, message=None, **options):
        s = _show(title, message, QUESTION, YESNO, **options)
        if s == YES:return True
        else:return False
    def askyesnocancel(title=None, message=None, **options):
        s = _show(title, message, QUESTION, YESNOCANCEL, **options)
        s = str(s)
        if s == CANCEL:return None
        return s == YES
    def askretrycancel(title=None, message=None, **options):s = _show(title, message, WARNING, RETRYCANCEL, **options);return s == RETRY
    def abortretryignore(title=None, message=None, **options):
        s = _show(title, message, WARNING, ABORTRETRYIGNORE, **options)
        if s == ABORT:return False
        elif s == RETRY:return True
        elif s == IGNORE:return None
class Fernet(object):
    def __init__(self, key: bytes, backend=None):
        backend = _get_backend(backend);key = base64.urlsafe_b64decode(key)
        if len(key) != 32:raise ValueError("Fernet key must be 32 url-safe base64-encoded bytes.")
        self._signing_key = key[:16];self._encryption_key = key[16:];self._backend = backend
    @classmethod
    def generate_key(cls) -> bytes:return base64.urlsafe_b64encode(os.urandom(32))
    def encrypt(self, data: bytes) -> bytes:return self.encrypt_at_time(data, int(time.time()))
    def encrypt_at_time(self, data: bytes, current_time: int) -> bytes:iv = os.urandom(16);return self._encrypt_from_parts(data, current_time, iv)
    def _encrypt_from_parts(self, data: bytes, current_time: int, iv: bytes) -> bytes:utils._check_bytes("data", data);padder = padding.PKCS7(algorithms.AES.block_size).padder();padded_data = padder.update(data) + padder.finalize();encryptor = Cipher(algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend).encryptor();ciphertext = encryptor.update(padded_data) + encryptor.finalize();basic_parts = (b"\x80" + struct.pack(">Q", current_time) + iv + ciphertext);h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend);h.update(basic_parts);hmac = h.finalize();return base64.urlsafe_b64encode(basic_parts + hmac)
    def decrypt(self, token: bytes, ttl: typing.Optional[int] = None) -> bytes:
        timestamp, data = Fernet._get_unverified_token_data(token)
        if ttl is None:time_info = None
        else:time_info = (ttl, int(time.time()))
        return self._decrypt_data(data, timestamp, time_info)
    def decrypt_at_time(
        self, token: bytes, ttl: int, current_time: int) -> bytes:
        if ttl is None:raise ValueError("decrypt_at_time() can only be used with a non-None ttl")
        timestamp, data = Fernet._get_unverified_token_data(token);return self._decrypt_data(data, timestamp, (ttl, current_time))
    def extract_timestamp(self, token: bytes) -> int:timestamp, data = Fernet._get_unverified_token_data(token);self._verify_signature(data);return timestamp
    @staticmethod
    def _get_unverified_token_data(token: bytes) -> typing.Tuple[int, bytes]:
        utils._check_bytes("token", token)
        try:data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):raise InvalidToken
        if not data or data[0] != 0x80:raise InvalidToken
        try:(timestamp,) = struct.unpack(">Q", data[1:9])
        except struct.error:raise InvalidToken
        return timestamp, data
    def _verify_signature(self, data: bytes) -> None:
        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend);h.update(data[:-32])
        try:h.verify(data[-32:])
        except InvalidSignature:raise InvalidToken
    def _decrypt_data(
        self,
        data: bytes,
        timestamp: int,
        time_info: typing.Optional[typing.Tuple[int, int]],) -> bytes:
        if time_info is not None:
            ttl, current_time = time_info
            if timestamp + ttl < current_time:raise InvalidToken
            if current_time + _MAX_CLOCK_SKEW < timestamp:raise InvalidToken
        self._verify_signature(data);iv = data[9:25];ciphertext = data[25:-32];decryptor = Cipher(algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend).decryptor();plaintext_padded = decryptor.update(ciphertext)
        try:plaintext_padded += decryptor.finalize()
        except ValueError:raise InvalidToken
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder();unpadded = unpadder.update(plaintext_padded)
        try:unpadded += unpadder.finalize()
        except ValueError:raise InvalidToken
        return unpadded
appWidth=800;appHeight=550;version="v0.2.0";build="Build 15";root=Tk();root.title("Eɲcrƴpʈ'n'Decrƴpʈ {}".format(version)+" - {}".format(time.strftime("%H"+":"+"%M"+":"+"%S"+" - "+"%d"+"/"+"%m"+"/"+"%Y")));root.resizable(width=FALSE, height=FALSE);root.geometry("{}x{}".format(appWidth, appHeight));root.attributes("-fullscreen", False);root.minsize(appWidth, appHeight)
"""style = ThemedStyle(root)
style.set_theme("vista")"""
MainScreen=ttk.Notebook(root,width=380,height=340);LogFrame=Frame(MainScreen);logTextWidget=Text(LogFrame,height=22,width=107,font=("Consolas",9),state=DISABLED)
logTextWidget.config(state=NORMAL);logTextWidget.insert(INSERT, "ROOT: Created root, started mainloop.\n");logTextWidget.config(state=DISABLED)
menu=Menu(root);root.config(menu=menu);enterMenu=Menu(menu,tearoff=0);viewMenu=Menu(menu,tearoff=0);helpMenu=Menu(menu,tearoff=0);transMenu=Menu(viewMenu,tearoff=0);langMenu=Menu(viewMenu,tearoff=0);logTextWidget.config(state=NORMAL);logTextWidget.insert(INSERT,"ROOT: Registered menu entries.\n");logTextWidget.config(state=DISABLED);root.wm_iconbitmap("Ico.ico")
def CheckUpdates():
    def Asset0DownloadBrowser():openweb(Version.json()["assets"][0]["browser_download_url"])
    def Asset1DownloadBrowser():openweb(Version.json()["assets"][1]["browser_download_url"])
    def AssetDownload(downloadPath, ProgressBar, downloadProgress, ProgressLabel, size, Asset=0, chunkSize=2097152):
        startTime = time.time()
        size = int(size)
        MBFACTOR = float(1 << 20)
        try:os.remove(downloadPath)
        except:pass
        ProgressBar.configure(maximum=int(chunkSize))
        downloadProgress.set(0)
        downloadedSize = 0
        try:
            file = open(downloadPath, mode='wb')
            for chunk in range(0, int(size), int(chunkSize)):
                try:
                    downloadURL = get(Version.json()["assets"][int(Asset)]["browser_download_url"], headers={"Range":"bytes={}-{}".format(chunk, chunk+chunkSize-1)})
                except:
                    messagebox.showerror("ERR_UNABLE_TO_CONNECT","An error occured while trying to connect to the GitHub servers. Please check your internet connection and firewall settings.\n\nError details: {}".format(e));logTextWidget.config(state=NORMAL);logTextWidget.insert(INSERT, "ERROR: GitHub server connection failed ({})\n".format(e));logTextWidget.config(state=DISABLED)
                    try:os.remove(downloadPath)
                    except:pass
                    break
                downloadedSize = downloadedSize + len(downloadURL.content)
                downloadProgress.set(downloadProgress.get()+len(downloadURL.content))
                ProgressLabel.configure(text="Download progress: {:.1f} MB {:.1f}%) out of {:.1f} MB downloaded".format(int(downloadedSize)/MBFACTOR, (100/size)*(downloadedSize/1024)/1024, int(size)/MBFACTOR))
                try:
                    file.write(downloadURL.content)
                except:
                    if not is_admin():
                        messagebox.showerror("ERR_DESTINATION_ACCESS_DENIED","An error occured while trying to write downloaded data to '{}' path. Please try again; if problem persists, try to run the program as administrator or change the download path.\n\nError details: {}".format(downloadPath,e));logTextWidget.config(state=NORMAL);logTextWidget.insert(INSERT, "ERROR: File write operation failed ({})\n".format(e));logTextWidget.config(state=DISABLED)
                        try:os.remove(downloadPath)
                        except:pass
                        break
                    else:
                        messagebox.showerror("ERR_INVALID_PATH","An error occured while trying to write downloaded data to '{}' path. Path may be invalid or inaccessible. Please select another path.")
                        try:os.remove(downloadPath)
                        except:pass
                        break
        except Exception as e:
            if not is_admin():
                messagebox.showerror("ERR_DESTINATION_ACCESS_DENIED","An error occured while trying to write downloaded data to '{}' path. Please try again; if problem persists, try to run the program as administrator or change the download path.\n\nError details: {}".format(downloadPath,e));logTextWidget.config(state=NORMAL);logTextWidget.insert(INSERT, "ERROR: File write operation failed ({})\n".format(e));logTextWidget.config(state=DISABLED)
                try:os.remove(downloadPath)
                except:pass
            else:
                messagebox.showerror("ERR_INVALID_PATH","An error occured while trying to write downloaded data to '{}' path. Path may be invalid or inaccessible. Please select another path.")
                try:os.remove(downloadPath)
                except:pass
        else:ProgressLabel.configure(text="Download progress:");downloadProgress.set(0);finishTime = time.time();messagebox.showinfo("Download complete","Downloading '{}' file from 'github.com' completed sucsessfully. File has been saved to '{}'.\n\nDownload time: {}\nDownload Speed: {} MB/s\nFile size: {:.2f} MB".format(str(Version.json()["assets"][0]["name"]),("C:/Users/{}/Downloads/{}".format(getuser(), Version.json()["assets"][0]["name"])),str(finishTime-startTime)[:4]+" "+"Seconds",str(int(size) / MBFACTOR / float(str(finishTime-startTime)[:4]))[:4],int(size) / MBFACTOR))
    def Asset0Download():
        if DownloadPathEntry.get()[1:] == "\\":AssetDownload(downloadPath=("{}{}".format(str(DownloadPathEntry.get()).replace("\\","/"),Version.json()["assets"][0]["name"])), Asset=0, ProgressBar=ProgressBar, downloadProgress=downloadProgress, ProgressLabel=ProgressLabel, size=size)
        else:AssetDownload(downloadPath=("{}/{}".format(str(DownloadPathEntry.get()).replace("\\","/"),Version.json()["assets"][0]["name"])), Asset=0, ProgressBar=ProgressBar, downloadProgress=downloadProgress, ProgressLabel=ProgressLabel, size=size)
    def Asset1Download():
        if DownloadPathEntry.get()[1:] == "\\":AssetDownload(downloadPath=("{}{}".format(str(DownloadPathEntry.get()).replace("\\","/"),Version.json()["assets"][1]["name"])), Asset=1, ProgressBar=ProgressBar, downloadProgress=downloadProgress, ProgressLabel=ProgressLabel, size=siz2)
        else:AssetDownload(downloadPath=("{}/{}".format(str(DownloadPathEntry.get()).replace("\\","/"),Version.json()["assets"][1]["name"])), Asset=1, ProgressBar=ProgressBar, downloadProgress=downloadProgress, ProgressLabel=ProgressLabel, size=size2)
    try:Version = get("https://api.github.com/repos/Yilmaz4/Encrypt-n-Decrypt/releases/latest")
    except Exception as e:messagebox.showerror("ERR_UNABLE_TO_CONNECT","An error occured while trying to connect to the GitHub API. Please check your internet connection and firewall settings.\n\nError details: {}".format(e));logTextWidget.config(state=NORMAL);logTextWidget.insert(INSERT, "ERROR: GitHub API connection failed ({})\n".format(e));logTextWidget.config(state=DISABLED)
    else:
        MBFACTOR = float(1 << 20)
        try:
            response = head(Version.json()["assets"][0]["browser_download_url"], allow_redirects=True)
        except KeyError as e:
            messagebox.showerror("ERR_API_SERVER_LIMIT_EXCEED","An error occured while trying to connect to the GitHub API servers. GitHub API limit may be exceed as servers has only 5000 connections limit per hour and per IP adress. Please try again after 1 hours.");logTextWidget.config(state=NORMAL);logTextWidget.insert(INSERT, "ERROR: GitHub API limit exceed, connection failed. ({})\n".format(e));logTextWidget.config(state=DISABLED)
        else:
            size = response.headers.get('content-length', 0)
            response2 = head(Version.json()["assets"][1]["browser_download_url"], allow_redirects=True)
            size2 = response2.headers.get('content-length', 0)
            if Version.json()["tag_name"] == version:messagebox.showinfo("No updates available","There are currently no updates available. Please check again later.\n\nYour version: {}\nLatest version: {}".format(version, Version.json()["tag_name"]))
            else:
                if version.replace("b","").replace("v","").replace(".","") > (Version.json()["tag_name"]).replace("b","").replace("v","").replace(".",""):messagebox.showinfo("Interesting.","It looks like you're using a newer version than official GitHub page. Your version may be a beta, or you're the author of this program :)\n\nYour version: {}\nLatest version: {}".format(version, Version.json()["tag_name"]))
                else:
                    update = Toplevel(root)
                    update.grab_set()
                    update.title("Eɲcrƴpʈ'n'Decrƴpʈ Updater")
                    update.resizable(height=False, width=False)
                    update.attributes("-fullscreen", False)
                    update.geometry("669x558")
                    update.maxsize("669","558")
                    update.minsize("669","558")
                    update.iconbitmap("Ico.ico")
                    HTML = markdown(Version.json()["body"]).replace("<h2>Screenshot:</h2>","")
                    frame = HtmlFrame(update, height=558, width=300, messages_enabled=False, vertical_scrollbar=True)
                    frame.load_html(HTML);frame.set_zoom(0.8);frame.grid_propagate(0);frame.enable_images(0);frame.place(x=0, y=0)
                    UpdateAvailableLabel = Label(update, text="An update is available!", font=('Segoe UI', 22), foreground="#189200")
                    LatestVersionLabel = Label(update, text="Latest version: {}".format(Version.json()["name"], font=('Segoe UI', 11)))
                    YourVersionLabel = Label(update, text="Current version: Encrypt'n'Decrypt {} ({})".format(version,build), font=('Segoe UI', 9))
                    DownloadLabel = Label(update, text="Download page for more information and asset files:")
                    DownloadLinks = LabelFrame(update, text="Download links", height=248, width=349)
                    OtherOptions = LabelFrame(update, text="Other options", height=128, width=349)
                    DownloadLinkLabel = Label(DownloadLinks, text=Version.json()["assets"][0]["name"])
                    DownloadLinkLabel2 = Label(DownloadLinks, text=Version.json()["assets"][1]["name"])
                    Separator1 = Separator(update, orient='horizontal')
                    Separator2 = Separator(DownloadLinks, orient='horizontal')
                    Separator3 = Separator(DownloadLinks, orient='horizontal')
                    Separator4 = Separator(OtherOptions, orient='horizontal')
                    CopyDownloadPage = Button(update, text="Copy", width=10)
                    OpenDownloadLink = Button(update, text="Open in browser", width=17)
                    CopyDownloadLink = Button(DownloadLinks, text="Copy", width=10)
                    DownloadTheLinkBrowser = Button(DownloadLinks, text="Download from browser", width=25, command=Asset0DownloadBrowser)
                    DownloadTheLinkBuiltin = Button(DownloadLinks, text="Download", width=13, command=Asset0Download)
                    CopyDownloadLink2 = Button(DownloadLinks, text="Copy", width=10)
                    DownloadTheLinkBrowser2 = Button(DownloadLinks, text="Download from browser", width=25, command=Asset1DownloadBrowser)
                    DownloadTheLinkBuiltin2 = Button(DownloadLinks, text="Download", width=13, command=Asset1Download)
                    DownloadPage = Entry(update, width=57)
                    DownloadPage.insert(0, str(Version.json()["html_url"]))
                    DownloadPage.configure(state=DISABLED)
                    DownloadLink = Entry(DownloadLinks, width=54)
                    DownloadLink.insert(0, str(Version.json()["assets"][0]["browser_download_url"]))
                    DownloadLink.configure(state=DISABLED)
                    DownloadLink2 = Entry(DownloadLinks, width=54)
                    DownloadLink2.insert(0, str(Version.json()["assets"][1]["browser_download_url"]))
                    DownloadLink2.configure(state=DISABLED)
                    AssetSize = Label(DownloadLinks, text=("{:.2f} MB".format(int(size) / MBFACTOR)), foreground="#474747")
                    AssetSize2 = Label(DownloadLinks, text=("{:.2f} MB".format(int(size2) / MBFACTOR)), foreground="#474747")
                    if response.headers.get('Last-Modified', 0)[:17][16] == " ":DateVariable = response.headers.get('Last-Modified', 0)[:16]
                    else:DateVariable = response.headers.get('Last-Modified', 0)[:17]
                    Date = Label(DownloadLinks, text=DateVariable, foreground="gray")
                    Date2 = Label(DownloadLinks, text=DateVariable, foreground="gray")
                    downloadProgress = IntVar();downloadProgress.set(0)
                    ProgressBar = Progressbar(DownloadLinks, length=329, mode='determinate', orient=HORIZONTAL, variable=downloadProgress, maximum=int(size))
                    ProgressLabel = Label(DownloadLinks, text="Download progress:")
                    DownloadPathLabel = Label(OtherOptions, text="Download directory:")
                    DownloadPathEntry = Entry(OtherOptions, width=54)
                    DownloadPathEntry.insert(0, r"C:\Users\{}\Downloads".format(getuser()))
                    DownloadPathStatus = Label(OtherOptions, text="Status: OK", foreground="green")
                    def directoryRevert():
                        DownloadPathEntry.delete(0,'end')
                        DownloadPathEntry.insert(0, r"C:\Users\{}\Downloads".format(getuser()))
                    DownloadPathReset = Button(OtherOptions, text="Revert to default directory", width=24, command=directoryRevert)
                    DownloadPathTest = Button(OtherOptions, text="Check directory", width=14)
                    DownloadPathBrowse = Button(OtherOptions, text="Browse", width=10)
                    ExtractContent = IntVar();ExtractContent.set(0)
                    ExtractContentsCheck = Checkbutton(OtherOptions, text="Extract downloaded files", onvalue=1, offvalue=0, variable=ExtractContent)
                    DownloadPathLabel.place(x=5, y=0)
                    DownloadPathEntry.place(x=7, y=21)
                    DownloadPathStatus.place(x=116, y=0)
                    DownloadPathReset.place(x=6, y=47)
                    DownloadPathTest.place(x=166, y=47)
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
                    if len(DateVariable) == 16:
                        Date.place(x=240, y=0)
                        Date2.place(x=240, y=86)
                    elif len(DateVariable) == 17:
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
                    OtherOptions.place(x=310, y=420)
                    update.focus_force()
                    update.mainloop()
def GenerateAES(Length):
    key = ""
    for i in range(Length):
        random = randint(1,32)
        if random<25:key+=str(choice(ascii_letters))
        elif random>=25 and random<30:key+=str(choice(digits))
        elif random>=30:key+=str(choice("!'^+%&/()=?_<>#${[]}\|__--$__--"))
    return key
try:
    def ShutDown():root.destroy()
    showCharState = IntVar(value=0);deshowCharState = IntVar(value=0);showChar = True;genPassword = IntVar();genPassword.set(16);Base64Check = IntVar();Base64Check.set(0);ToolTipActive = False
    class ToolTip(object):
        def __init__(self,widget):self.widget=widget;self.tipwindow=None;self.id=None;self.x=self.y = 0
        def showtip(self, text, widget, event):
            global tw;self.text = text
            if self.tipwindow or not self.text:return
            x, y, cx, cy = self.widget.bbox("insert");x = x + root.winfo_pointerx() + 2;y = y + cy + root.winfo_pointery() + 15;self.tipwindow = tw = Toplevel(self.widget);tw.wm_overrideredirect(1);tw.wm_geometry("+%d+%d" % (x, y));tw.attributes("-alpha", 0);label = Label(tw, text=self.text, justify=LEFT, relief=SOLID, borderwidth=1, foreground="#6f6f6f", background="white");label.pack(ipadx=1);tw.attributes("-alpha", root.attributes("-alpha"))
            try:tw.tk.call("::tk::unsupported::MacWindowStyle", "style", tw._w, "help", "noActivates")
            except TclError:pass
        def hidetip(self, widget):
            try:
                tw = self.tipwindow
                tw.title("Tooltip")
                self.tipwindow = None
                def fade_away():
                    alpha = tw.attributes("-alpha")
                    if alpha > 0:
                        alpha -= .1;tw.attributes("-alpha", alpha);tw.after(10, fade_away)
                    else:tw.destroy()
                fade_away()
            except:root.after_cancel(task)
    def createToolTip(widget, text):
        global task;toolTip = ToolTip(widget)
        def enter(event):global task;task = root.after(1000, toolTip.showtip, text, widget, event)
        def leave(event):toolTip.hidetip(widget)
        def press(event):toolTip.hidetip(widget)
        widget.bind('<Enter>',enter);widget.bind('<Leave>',leave);widget.bind('<Button-1>',press)
    def toggleHideChar():
        global encryptedTextEntry
        if showCharState.get()==1:showChar=False;OldText = encryptedTextEntry.get();encryptedTextEntry.place_forget();encryptedTextEntry = Entry(EncryptFrame, width = 50, show = "●", font=("Consolas",9));encryptedTextEntry.insert(0,"{}".format(OldText));encryptedTextEntry.place(x=10, y=22)
        else:showChar=True;OldText=encryptedTextEntry.get();encryptedTextEntry.place_forget();encryptedTextEntry=Entry(EncryptFrame,width=50,font=("Consolas",9));encryptedTextEntry.insert(0,"{}".format(OldText));encryptedTextEntry.place(x=10, y=22)
    def GeneratePassword():
        global key;keylength=int(genPassword.get())
        if keylength>=8196:
            choice=messagebox.askyesno("Entered key length is longer than 8196.","Entered key length is longer than 8196. Longer than 8196 key generations can cause program to stop responding. Are you sure want to continute?")
            if choice==True:keylength=keylength/1024;keylength=(96*8)*keylength;key=base64.urlsafe_b64encode(os.urandom(int(keylength)));return key
        else:keylength=keylength/128;keylength=keylength*96;key=base64.urlsafe_b64encode(os.urandom(int(keylength)));return key
    def Encrypt():
        global encryptedTextEntry, encryptedTextWidget, key, KeySelectVar
        def FernetEncryption(key):
            try:fernet = Fernet(key)
            except:logTextWidget.config(state=NORMAL);logTextWidget.insert(INSERT, "ERROR: An error occured while trying to define entered key into Fernet.\n");logTextWidget.config(state=DISABLED);messagebox.showerror("ERR_UNABLE_TO_DEFINE_KEY","An error occured while trying to define entered key into Fernet. Key might invalid for Fernet. Please write a valid AES-128, AES-192, AES-256 or legacy Fernet. If key is already one of them, please check you entered right.")
            textEncrypt = encryptedTextEntry.get();encryptedText = fernet.encrypt(textEncrypt.encode())
            if Mode.get() == 2:
                decryptedText = fernet.decrypt(encryptedText).decode()
                if textEncrypt == decryptedText:encryptedTextWidget.configure(state=NORMAL, fg="black");encryptedTextWidget.delete('1.0', END);encryptedTextWidget.insert(INSERT, encryptedText);encryptedTextWidget.configure(state=DISABLED);AESkeyEntry.configure(state=NORMAL);AESkeyEntry.delete('1.0', END);AESkeyEntry.insert('1.0', key);AESkeyEntry.configure(state=DISABLED);RSApublicKeyWidget.configure(state=NORMAL);RSApublicKeyWidget.delete('1.0', END);RSApublicKeyWidget.configure(state=DISABLED);RSAprivateKeyWidget.configure(state=NORMAL);RSAprivateKeyWidget.delete('1.0', END);RSAprivateKeyWidget.configure(state=DISABLED);logTextWidget.config(state=NORMAL);logTextWidget.insert(INSERT, "SUCSESS: Entered text sucsessfully encrypted using legacy Fernet key.\n");logTextWidget.config(state=DISABLED)
                else:
                    tryText="abc";trykey=Fernet.generate_key();tryfernet=Fernet(trykey);tryEncryptedText = tryfernet.encrypt(tryText.encode());tryDecryptedText = tryfernet.decrypt(tryEncryptedText).decode()
                    if tryText == tryDecryptedText:logTextWidget.config(state=NORMAL);logTextWidget.insert(INSERT, "WARNING: Entered text is not encryptable.\n");logTextWidget.config(state=DISABLED);messagebox.showwarning("ERR_UNENCRYPTABLE_TEXT","Entered text is not encryptable. Please report this text to me.")
                    else:logTextWidget.config(state=NORMAL);logTextWidget.insert(INSERT, "ERROR: An problem occured in encrypter.\n");logTextWidget.config(state=DISABLED);messagebox.showerror("ERR_ENCRYPTER_NOT_WORKING_PROPERLY","There is a problem occured in encrypter. Both entered text and 'abc' text failed encryption. Please try again and if problem persists, please report this problem to me.")
            elif Mode.get() == 1:encryptedTextWidget.configure(state=NORMAL, fg="black");encryptedTextWidget.delete('1.0', END);encryptedTextWidget.insert(INSERT, encryptedText);encryptedTextWidget.configure(state=DISABLED);AESkeyEntry.configure(state=NORMAL);AESkeyEntry.delete('1.0', END);AESkeyEntry.insert('1.0', key);AESkeyEntry.configure(state=DISABLED);logTextWidget.config(state=NORMAL);logTextWidget.insert(INSERT, "SUCSESS: Entered text sucsessfully encrypted using legacy Fernet key without checking.\n");logTextWidget.config(state=DISABLED)
        def RSAEncryption(public, private, plaintext):
            try:ciphertext=PKCS1_OAEP.new(public).encrypt(bytes(plaintext,encoding.get()))
            except ValueError:messagebox.showwarning("ERR_PLAIN_TEXT_IS_TOO_LONG","The text you entered to encrypt is too long with {} encoding for RSA-{} asymmetric encryption. Please select a longer RSA key to encrypt this data like RSA-{} or RSA-{} or select another encoding.".format(encoding.get(), RSAkeyVar.get(), RSAkeyVar.get()*2, RSAkeyVar.get()*4))
            cipher=base64.urlsafe_b64encode(ciphertext).decode()
            if cipher=="":cipher="[Blank]"
            if Mode.get()==2:
                output=PKCS1_OAEP.new(RSA.import_key(private)).decrypt(ciphertext).decode(encoding.get())
                if output == encryptedTextEntry.get():encryptedTextWidget.configure(state=NORMAL, fg="black");encryptedTextWidget.delete('1.0', END);encryptedTextWidget.insert(INSERT, cipher);encryptedTextWidget.configure(state=DISABLED);RSApublicKeyWidget.configure(state=NORMAL);RSApublicKeyWidget.delete('1.0', END);RSApublicKeyWidget.insert(INSERT, base64.urlsafe_b64encode(public.exportKey()).decode());RSApublicKeyWidget.configure(state=DISABLED);RSAprivateKeyWidget.configure(state=NORMAL);RSAprivateKeyWidget.delete('1.0', END);RSAprivateKeyWidget.insert(INSERT, base64.urlsafe_b64encode(private).decode());RSAprivateKeyWidget.configure(state=DISABLED);AESkeyEntry.configure(state=NORMAL);AESkeyEntry.delete('1.0', END);AESkeyEntry.configure(state=DISABLED);logTextWidget.config(state=NORMAL);logTextWidget.insert(INSERT, "SUCSESS: Entered text sucsessfully encrypted using RSA-{} symmetric key encryption.\n".format(RSAkeyVar.get()));logTextWidget.config(state=DISABLED)
                else:pass
            elif Mode.get()==1:encryptedTextWidget.configure(state=NORMAL);encryptedTextWidget.delete('1.0',END);encryptedTextWidget.insert(INSERT, cipher);encryptedTextWidget.configure(state=DISABLED);RSApublicKeyWidget.configure(state=NORMAL);RSApublicKeyWidget.delete('1.0', END);RSApublicKeyWidget.insert(INSERT, base64.urlsafe_b64encode(public.exportKey()).decode());RSApublicKeyWidget.configure(state=DISABLED);RSAprivateKeyWidget.configure(state=NORMAL);RSAprivateKeyWidget.delete('1.0', END);RSAprivateKeyWidget.insert(INSERT, base64.urlsafe_b64encode(private).decode());RSAprivateKeyWidget.configure(state=DISABLED);AESkeyEntry.configure(state=NORMAL);AESkeyEntry.delete('1.0', END);AESkeyEntry.configure(state=DISABLED);logTextWidget.config(state=NORMAL);logTextWidget.insert(INSERT, "SUCSESS: Entered text sucsessfully encrypted using RSA-{} symmetric key encryption without checking.\n".format(RSAkeyVar.get()));logTextWidget.config(state=DISABLED)
        def AESencryption(key,plaintext=encryptedTextEntry.get()):
            global cipher,Mode,encryptedTextWidget
            plaintext = bytes(plaintext, encoding.get())
            iv = Random.new().read(AES.block_size)
            iv_int = int(binascii.hexlify(iv), 16) 
            ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
            try:
                aes = AES.new(key, AES.MODE_CTR, counter=ctr)
                ciphertext = aes.encrypt(plaintext)
                cipher = base64.urlsafe_b64encode(ciphertext).decode()
            except:
                logTextWidget.config(state=NORMAL)
                logTextWidget.insert(INSERT, "ERROR: An error occured while trying to define entered key into AES.\n")
                logTextWidget.config(state=DISABLED)
                messagebox.showerror("ERR_UNABLE_TO_DEFINE_KEY","An error occured while trying to define entered key into AES. Key might invalid for AES (Advanced Encryption Standard). Please write a valid AES-128, AES-192, AES-256 or legacy Fernet. If key is already one of them, please check you entered right.")
            if cipher == "":
                cipher = "[Blank]"
            if Mode.get() == 2:
                iv_int = int(binascii.hexlify(iv), 16)
                ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
                aes = AES.new(key, AES.MODE_CTR, counter=ctr)
                plaintext = aes.decrypt(ciphertext)
                if plaintext.decode(encoding.get()) == encryptedTextEntry.get():
                    encryptedTextWidget.configure(state=NORMAL)
                    encryptedTextWidget.delete('1.0', END)
                    encryptedTextWidget.insert(INSERT, cipher)
                    if cipher == "[Blank]":
                        encryptedTextWidget.configure(state=DISABLED, fg="gray")
                    else:
                        encryptedTextWidget.configure(state=DISABLED, fg="black")
                    AESkeyEntry.configure(state=NORMAL)
                    AESkeyEntry.delete('1.0', END)
                    AESkeyEntry.insert('1.0', key)
                    AESkeyEntry.configure(state=DISABLED)
                    RSApublicKeyWidget.configure(state=NORMAL)
                    RSApublicKeyWidget.delete('1.0', END)
                    RSApublicKeyWidget.configure(state=DISABLED)
                    RSAprivateKeyWidget.configure(state=NORMAL)
                    RSAprivateKeyWidget.delete('1.0', END)
                    RSAprivateKeyWidget.configure(state=DISABLED)
                    logTextWidget.config(state=NORMAL)
                    logTextWidget.insert(INSERT, "SUCSESS: Entered text sucsessfully encrypted using AES-{} symmetric key encryption.\n".format(len(key)*8))
                    logTextWidget.config(state=DISABLED)
                else:
                    AESencryption(key, "abc")
                    if plaintext.decode(encoding.get()) == encryptedTextEntry.get():
                        logTextWidget.config(state=NORMAL)
                        logTextWidget.insert(INSERT, "WARNING: Entered text is not encryptable.\n")
                        logTextWidget.config(state=DISABLED)
                        messagebox.showwarning("ERR_UNENCRYPTABLE_TEXT","Entered text is not encryptable. Please report this text to me.")
                    else:
                        logTextWidget.config(state=NORMAL)
                        logTextWidget.insert(INSERT, "ERROR: An problem occured in encrypter.\n")
                        logTextWidget.config(state=DISABLED)
                        messagebox.showerror("ERR_ENCRYPTER_NOT_WORKING_PROPERLY","There is a problem occured in encrypter. Both entered text and 'abc' text failed encryption. Please try again and if problem persists, please report this problem to me.")
            elif Mode.get() == 1:
                encryptedTextWidget.configure(state=NORMAL)
                encryptedTextWidget.delete('1.0', END)
                encryptedTextWidget.insert(INSERT, cipher)
                encryptedTextWidget.configure(state=DISABLED)
                AESkeyEntry.configure(state=NORMAL)
                AESkeyEntry.delete('1.0', END)
                AESkeyEntry.insert('1.0', key)
                AESkeyEntry.configure(state=DISABLED)
                logTextWidget.config(state=NORMAL)
                logTextWidget.insert(INSERT, "SUCSESS: Entered text sucsessfully encrypted using AES-{} symmetric key encryption without checking.\n".format(len(key)*8))
                logTextWidget.config(state=DISABLED)
        if Encryption.index(Encryption.select()) == 0:
            if KeySelectVar.get() == 1:
                if RandomKeyVar.get() < 352:
                    AESencryption(bytes(GenerateAES(int(RandomKeyVar.get()/8)), 'utf-8'))
                elif RandomKeyVar.get() == 352:
                    key = Fernet.generate_key()
                    FernetEncryption(key)
            elif KeySelectVar.get() == 2:
                key = bytes(SelectKeyEntry.get(), "utf-8")
                if len(key.decode()) == 16 or len(key.decode()) == 24 or len(key.decode()) == 32:
                    AESencryption(key, encryptedTextEntry.get())
                elif len(key.decode()) == 44:
                    FernetEncryption(key)
                else:
                    logTextWidget.config(state=NORMAL)
                    logTextWidget.insert(INSERT, "ERROR: Invalid key for encryption. Encryption key must be url_safe base64 encoded AES-128, AES-192, AES-256 or legacy Fernet key.\n")
                    logTextWidget.config(state=DISABLED)
                    messagebox.showwarning("ERR_INVALID_ENCRYPTION_KEY","This key is invalid for AES (Advanced Encryption Standard) encryption. Please write a url_safe base64 encoded AES-128, AES-192, AES-256 or legacy Fernet key. If key is already one of them, please check you entered right.")
        elif Encryption.index(Encryption.select()) == 1:
            if RSAkeyVar.get() != 0:
                if RSAkeyVar.get() > 4096:
                    if messagebox.askyesno("Selected key size is too big!","Selected RSA key size is too big. This size of RSA key generation can cause program to stop working. Are you sure want to continue?"):
                        privateKey = RSA.generate(int(RSAkeyVar.get()))
                else:
                    privateKey = RSA.generate(int(RSAkeyVar.get()))
            else:
                if RSAkeyVar.get() > 4096:
                    if messagebox.showwarning("Selected key size is too big!","Selected RSA key size is too big. This size of RSA key generation can cause program to stop working. Are you sure want to continue?"):
                        privateKey = RSA.generate(int(RSAkeylength.get()))
                else:
                    privateKey = RSA.generate(int(RSAkeylength.get()))
            try:
                publicKey = privateKey.publickey()
                RSAEncryption(publicKey, privateKey.exportKey(), encryptedTextEntry.get())
            except UnboundLocalError:
                pass
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
                try:
                    decryptedText = fernet.decrypt(textEncrypt).decode()
                    logTextWidget.config(state=NORMAL)
                    logTextWidget.insert(INSERT, "SUCSESS: Checked decrypter sucsessfully. Decrypter is working properly.\n")
                    logTextWidget.config(state=DISABLED)
                    messagebox.showinfo("Sucsess.","Checked decrypter sucsessfully. Decrypter is working properly.")
                except:
                    logTextWidget.config(state=NORMAL)
                    logTextWidget.insert(INSERT, "ERROR: Decryption failed probably because of wrong key.\n")
                    logTextWidget.config(state=DISABLED)
                    messagebox.showinfo("ERR_WRONG_KEY","The key inside 'Encryption Key.key' is not the right key to decrypt this data.")
            except:
                logTextWidget.config(state=NORMAL)
                logTextWidget.insert(INSERT, "ERROR: Checked decrypter. Decrypter is not working properly.\n")
                logTextWidget.config(state=DISABLED)
                messagebox.showerror("ERR_UNABLE_TO_DECRYPT","An unknown error occured in decrypter. Please try again.")
        except:
            print("ERROR: An error occured when trying to decrypt.")
            messagebox.showerror("ERR_UNABLE_TO_DECRYPT","Şifre çözücüde bir hata meydana geldi. Lütfen programı yeniden başlatıp tekrar deneyin.")
    def load_key():
        try:
            return open("Encryption Key.key", "rb").read()
        except:
            logTextWidget.config(state=NORMAL)
            logTextWidget.insert(INSERT, "ERROR: An error occured while trying to get the key from 'Encryption Key.key' file.\n")
            logTextWidget.config(state=DISABLED)
            messagebox.showerror("ERR_UNABLE_TO_READ_FILE","An error occured while trying to get the key from 'Encryption Key.key' file. The file may be missing, corrupt or inaccessable. Please try again; if problem persists, try to run the program as administrator.")
    def FileEncrypt(file, key):
        fernet = Fernet(bytes(key, 'utf-8'))
        with open(file, "rb") as file:
            file_data = file.read()
        encrypted_data = fernet.encrypt(file_data)
        with open(file, "wb") as file:
            file.write(encrypted_data)
    def Decrypt():
        global decryptedTextEntry, decryptedTextWidget, decryptedText, Fail
        Fail = False
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
        if decryptedText != "":
            try:
                decryptedTextEntry.configure(state=NORMAL)
                decryptedTextEntry.delete(0, END)
                decryptedTextEntry.insert(0, decryptedText)
                decryptedTextEntry.configure(state=DISABLED)
            except NameError:
                decryptedTextEntry.configure(state=DISABLED)
        else:
            decryptedTextEntry.configure(state=NORMAL)
            decryptedTextEntry.delete(0, END)
            decryptedTextEntry.insert(0, decryptedText+"(Blank)")
            decryptedTextEntry.configure(state=DISABLED)
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
        MainScreen.select(2)
    def HelpPage():
        MainScreen.select(5)
    Alpha = IntVar()
    Alpha.set(100)
    def changeAlpha(alpha):
        if alpha != 100:
            alpha = '0.{}'.format(alpha)
        else:
            alpha = 1
            Alpha.set(100)
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
    AboutFrame = Frame(MainScreen)
    FileEncryptFrame = Frame(MainScreen)
    PasswordGeneration = Frame(MainScreen)
    if True: #Variables
        RandomKeyVar = IntVar()
        RandomKeyVar.set(256)
        KeySelectVar = IntVar()
        KeySelectVar.set(1)
        OverrideTimeVar = IntVar()
        OverrideTimeVar.set(0)
    def ChangeKeySelection():
        global KeySelectVar, value
        try:
            value = value # For understaning which time is this code running. First key selection or after user writes something into key selection box.
        except:
            value = "TemporaryValue"
        if KeySelectVar.get() == 2:
            AES128Check.config(state=DISABLED)
            AES192Check.config(state=DISABLED)
            AES256Check.config(state=DISABLED)
            SelectKeyEntry.config(state=NORMAL)
            AES352Check.config(state=DISABLED)
            KeyEntryHideChar.config(state=NORMAL)
            if len(value) == 44:
                CheckBase64Encoding.config(state=DISABLED)
            else:
                CheckBase64Encoding.config(state=NORMAL)
        elif KeySelectVar.get() == 1:
            SelectKeyEntry.config(state=DISABLED)
            AES128Check.config(state=NORMAL)
            AES192Check.config(state=NORMAL)
            AES256Check.config(state=NORMAL)
            AES352Check.config(state=NORMAL)
            KeyEntryHideChar.config(state=DISABLED)
            if len(value) == 44:
                CheckBase64Encoding.config(state=DISABLED)
            else:
                CheckBase64Encoding.config(state=DISABLED)
        elif KeySelectVar.get() == 3:
            AES128Check.config(state=DISABLED)
            AES192Check.config(state=DISABLED)
            AES256Check.config(state=DISABLED)
            SelectKeyEntry.config(state=DISABLED)
            AES352Check.config(state=DISABLED)
            KeyEntryHideChar.config(state=DISABLED)
            if len(value) == 44:
                CheckBase64Encoding.config(state=DISABLED)
            else:
                CheckBase64Encoding.config(state=DISABLED)
    def OverrideTime():
        if OverrideTimeVar.get() == 1:
            HourEntry.config(state=NORMAL)
            MinuteEntry.config(state=NORMAL)
            SecondEntry.config(state=NORMAL)
            DayEntry.config(state=NORMAL)
            MonthEntry.config(state=NORMAL)
            YearEntry.config(state=NORMAL)
            DateSeparator.config(state=NORMAL)
            DateSeparator2.config(state=NORMAL)
            HourSeparator.config(state=NORMAL)
            HourSeparator2.config(state=NORMAL)
        elif OverrideTimeVar.get() == 0:
            HourEntry.config(state=DISABLED)
            MinuteEntry.config(state=DISABLED)
            SecondEntry.config(state=DISABLED)
            DayEntry.config(state=DISABLED)
            MonthEntry.config(state=DISABLED)
            YearEntry.config(state=DISABLED)
            DateSeparator.config(state=DISABLED)
            DateSeparator2.config(state=DISABLED)
            HourSeparator.config(state=DISABLED)
            HourSeparator2.config(state=DISABLED)
    if True: #Lenght limit
        def limitKeyEntry(*args):
            global value
            value = KeyValue.get()
            if len(value) > 44: 
                KeyValue.set(value[:44])
            iv = Random.new().read(AES.block_size)
            iv_int = int(binascii.hexlify(iv), 16) 
            ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
            if len(value) == 0:
                StatusLabelAES.configure(foreground="gray", text="Validity: [Blank]")
            elif len(value) == 16:
                try:
                    AES.new(bytes(value, 'utf-8'), AES.MODE_CTR, counter=ctr)
                except:
                    StatusLabelAES.configure(foreground="red", text="Validity: Invalid AES-256 Key")
                else:
                    StatusLabelAES.configure(foreground="green", text="Validity: Valid AES-256 Key")
            elif len(value) == 24:
                try:
                    AES.new(bytes(value, 'utf-8'), AES.MODE_CTR, counter=ctr)
                except:
                    StatusLabelAES.configure(foreground="red", text="Validity: Invalid AES-256 Key")
                else:
                    StatusLabelAES.configure(foreground="green", text="Validity: Valid AES-256 Key")
            elif len(value) == 32:
                try:
                    AES.new(bytes(value, 'utf-8'), AES.MODE_CTR, counter=ctr)
                except:
                    StatusLabelAES.configure(foreground="red", text="Validity: Invalid AES-256 Key")
                else:
                    StatusLabelAES.configure(foreground="green", text="Validity: Valid AES-256 Key")
            elif len(value) >= 44:
                CheckBase64Encoding.configure(state=DISABLED)
                try:
                    fernet = Fernet(bytes(value, 'utf-8'))
                    fernet.encrypt(b"abc")
                    StatusLabelAES.configure(foreground="green", text="Validity: Valid Fernet key")
                except:
                    StatusLabelAES.configure(foreground="red", text="Validity: Invalid Fernet key")
            else:
                CheckBase64Encoding.configure(state=NORMAL)
                StatusLabelAES.configure(foreground="red", text="Validity: Invalid")
        def limitRSAEntry(*args):
            if int(RSAkeylength.get()) % 1024 == 0:
                ToleranceLabel.configure(foreground="green", text="±0")
            elif int(RSAkeylength.get()) % 1024 > 0 and int(RSAkeylength.get()) % 1024 < 150:
                ToleranceLabel.configure(foreground="#ff7400", text="±{}".format(int(RSAkeylength.get()) % 1024))
            elif int(RSAkeylength.get()) % 1024 > 150:
                ToleranceLabel.configure(foreground="red", text="±{}".format(int(RSAkeylength.get()) % 1024))
            elif int(RSAkeylength.get()) == "":
                ToleranceLabel.configure(foreground="gray", text="±0")
        KeyValue = StringVar()
        KeyValue.trace('w', limitKeyEntry)
        RSAValue2 = StringVar()
        RSAValue2.trace('w', limitRSAEntry)
        def limitHourEntry(*args):
            value = Hour.get()
            if len(value) > 2: 
                Hour.set(value[:2])
            if len(value) > 1:
                MinuteEntry.focus()
        Hour = StringVar()
        Hour.trace('w', limitHourEntry)
        def limitMinuteEntry(*args):
            value = Minute.get()
            if len(value) > 2: 
                Minute.set(value[:2])
            if len(value) > 1:
                SecondEntry.focus()
        Minute = StringVar()
        Minute.trace('w', limitMinuteEntry)
        def limitSecondEntry(*args):
            value = Second.get()
            if len(value) > 2: 
                Second.set(value[:2])
            if len(value) > 1:
                DayEntry.focus()
        Second = StringVar()
        Second.trace('w', limitSecondEntry)
        def limitDayEntry(*args):
            value = Day.get()
            if len(value) > 2: 
                Day.set(value[:2])
            if len(value) > 1:
                MonthEntry.focus()
        Day = StringVar()
        Day.trace('w', limitDayEntry)
        def limitMonthEntry(*args):
            value = Month.get()
            if len(value) > 2: 
                Month.set(value[:2])
            if len(value) > 1:
                YearEntry.focus()
        Month = StringVar()
        Month.trace('w', limitMonthEntry)
        def limitYearEntry(*args):
            value = Year.get()
            if len(value) > 4: Year.set(value[:4])
        Year = StringVar()
        Year.trace('w', limitYearEntry)
    Mode = IntVar()
    Mode.set(2)
    Encryption = ttk.Notebook(EncryptFrame, width=355, height=220)
    KeySelectFrame = Frame(Encryption)
    Asymmetric = Frame(Encryption)
    Encryption.add(KeySelectFrame, text="Symmetric Key Encryption")
    Encryption.add(Asymmetric, text="Asymmetric Key Encryption")
    EncryptFrameLabel = LabelFrame(EncryptFrame, text="Output", height=506, width=403)
    MainScreen.add(EncryptFrame, text="Text Encryption")
    MainScreen.add(FileEncryptFrame, text="File Encryption")
    MainScreen.add(DecryptFrame, text="Decryption")
    MainScreen.add(PasswordGeneration, text="Key Generator")
    MainScreen.add(LogFrame, text="Logs")
    MainScreen.add(AboutFrame, text="Help & About")
    MainScreen.pack(fill=BOTH, expand=1, pady=4, padx=4, side=TOP)
    EncryptFrameLabel.place(x=377, y=4)
    KeyHideCharVar = IntVar()
    KeyHideCharVar.set(0)
    OtherOptionsFrame = LabelFrame(EncryptFrame, text="Other options", height=100, width=357)
    OverrideCheck = Checkbutton(OtherOptionsFrame, text="Override encryption time:", onvalue=1, offvalue=0, variable=OverrideTimeVar, command=OverrideTime)
    if True: #Override time entries
        HourEntry = Entry(OtherOptionsFrame, width=2, font=("Consolas",9), state=DISABLED, textvariable=Hour)
        MinuteEntry = Entry(OtherOptionsFrame, width=2, font=("Consolas",9), state=DISABLED, textvariable=Minute)
        SecondEntry = Entry(OtherOptionsFrame, width=2, font=("Consolas",9), state=DISABLED, textvariable=Second)
        DayEntry = Entry(OtherOptionsFrame, width=2, font=("Consolas",9), state=DISABLED, textvariable=Day)
        MonthEntry = Entry(OtherOptionsFrame, width=2, font=("Consolas",9), state=DISABLED, textvariable=Month)
        YearEntry = Entry(OtherOptionsFrame, width=4, font=("Consolas",9), state=DISABLED, textvariable=Year)
        HourSeparator = Label(OtherOptionsFrame, text=":", state=DISABLED)
        HourSeparator2 = Label(OtherOptionsFrame, text=":", state=DISABLED)
        DateSeparator = Label(OtherOptionsFrame, text="/", state=DISABLED)
        DateSeparator2 = Label(OtherOptionsFrame, text="/", state=DISABLED)
        BenchVar = IntVar();BenchVar.set(0)
        BenchmarkCheck = Checkbutton(OtherOptionsFrame, text="Benchmark", onvalue=1, offvalue=0, variable=BenchVar)
        HourEntry.place(x=165, y=0)
        MinuteEntry.place(x=192, y=0)
        SecondEntry.place(x=219, y=0)
        DayEntry.place(x=252, y=0)
        MonthEntry.place(x=281, y=0)
        YearEntry.place(x=312, y=0)
        HourSeparator.place(x=185, y=0)
        HourSeparator2.place(x=212, y=0)
        DateSeparator.place(x=272, y=0)
        DateSeparator2.place(x=301, y=0)
        BenchmarkCheck.place(x=5, y=44)
    if True:
        RandomKeyCheck = Radiobutton(KeySelectFrame, text="Generate a random key", value=1, variable=KeySelectVar, command=ChangeKeySelection)
        SelectKeyCheck = Radiobutton(KeySelectFrame, text="Use this key:", value=2, variable=KeySelectVar, command=ChangeKeySelection)
        SelectFileCheck = Radiobutton(KeySelectFrame, text="Use this key file:", value=3, variable= KeySelectVar, command=ChangeKeySelection)
        SelectKeyEntry = Entry(KeySelectFrame, width=46, font=("Consolas",9), state=DISABLED, textvariable=KeyValue)
        AES128Check = Radiobutton(KeySelectFrame, text="AES-128 Key (16 characters long)", value=128, variable=RandomKeyVar)
        AES192Check = Radiobutton(KeySelectFrame, text="AES-192 Key (24 characters long)", value=192, variable=RandomKeyVar)
        AES256Check = Radiobutton(KeySelectFrame, text="AES-256 Key (32 characters long)", value=256, variable=RandomKeyVar)
        AES352Check = Radiobutton(KeySelectFrame, text="Legacy Fernet Key (44 characters long)", value=352, variable=RandomKeyVar)
        KeyEntryHideChar = Checkbutton(KeySelectFrame, text="Hide characters", onvalue=1, offvalue=0, variable=KeyHideCharVar, state=DISABLED)
        FastModeCheck = Radiobutton(OtherOptionsFrame, text="Fast mode (Bypass check)", value=1, variable=Mode)
        SecureModeCheck = Radiobutton(OtherOptionsFrame, text="Secure mode (Check)", value=2, variable=Mode)
        KeyEntryHideChar.place(x=244, y=102)
        FastModeCheck.place(x=5, y=22)
        SecureModeCheck.place(x=214, y=22)
        OverrideCheck.place(x=5, y=0)
        OtherOptionsFrame.place(x=10, y=350)
        SelectKeyCheck.place(x=5, y=101)
        RandomKeyCheck.place(x=5, y=5)
        SelectFileCheck.place(x=5, y=163)
        SelectKeyEntry.place(x=18, y=123)
        Encryption.place(x=10, y=77)
        AES128Check.place(x=16, y=25)
        AES192Check.place(x=16, y=44)
        AES256Check.place(x=16, y=63)
        AES352Check.place(x=16, y=82)
    if True:
        RSAkeyVar = IntVar()
        RSAkeyVar.set(1024)
        def validate(action, index, value_if_allowed, prior_value, text, validation_type, trigger_type, widget_name):
            if value_if_allowed:
                try:int(value_if_allowed);return True
                except ValueError:
                    if text == "":return True
                    else:return False
            else:return True
        def ChangeRSASelection():
            if int(RSAkeyVar.get()) == 0:
                RSAkeylength.configure(state=NORMAL)
            else:
                RSAkeylength.configure(state=DISABLED)
        vcmd = (root.register(validate),'%d', '%i', '%P', '%s', '%S', '%v', '%V', '%W')
        RSAChangeSelection = IntVar()
        RSAChangeSelection.set(1)
        RandomRSAKeyCheck = Radiobutton(Asymmetric, text="Generate a random RSA key", value=1, variable=KeySelectVar, command=RSAChangeSelection)
        RSA1024Check = Radiobutton(Asymmetric, text="RSA-1024 Key", value=1024, variable=RSAkeyVar, command=ChangeRSASelection)
        RSA2048Check = Radiobutton(Asymmetric, text="RSA-2048 Key", value=2048, variable=RSAkeyVar, command=ChangeRSASelection)
        RSA3072Check = Radiobutton(Asymmetric, text="RSA-3072 Key", value=3072, variable=RSAkeyVar, command=ChangeRSASelection)
        RSA4096Check = Radiobutton(Asymmetric, text="RSA-4096 Key", value=4096, variable=RSAkeyVar, command=ChangeRSASelection)
        RSA8192Check = Radiobutton(Asymmetric, text="RSA-8192 Key", value=8192, variable=RSAkeyVar, command=ChangeRSASelection)
        RSA16384Check = Radiobutton(Asymmetric, text="RSA-16384 Key", value=16384, variable=RSAkeyVar, command=ChangeRSASelection)
        RSAcustomCheck = Radiobutton(Asymmetric, text="Custom RSA key length:", value=0, variable=RSAkeyVar, command=ChangeRSASelection) 
        SelectRSAKeyCheck = Radiobutton(Asymmetric, text="Use this RSA key:", value=2, variable=KeySelectVar, command=RSAChangeSelection)
        RSAkeyEntry = Text(Asymmetric, height=2, width=45, font=("Consolas",9), state=DISABLED)
        RSAkeylength = Entry(Asymmetric, width=6, font=("Consolas",9), validate = 'key', validatecommand = vcmd, textvariable=RSAValue2, state=DISABLED)

        RandomRSAKeyCheck.place(x=5, y=5)
        RSA1024Check.place(x=16, y=25)
        RSA2048Check.place(x=16, y=44)
        RSA3072Check.place(x=16, y=63)
        RSAcustomCheck.place(x=16, y=82)
        RSA4096Check.place(x=125, y=25)
        RSA8192Check.place(x=125, y=44)
        RSA16384Check.place(x=125, y=63)
        RSAkeylength.place(x=170, y=83)
        SelectRSAKeyCheck.place(x=5, y=101)
    if True: #Sub-Menus
        enterMenu.add_command(label = "Encryption", command=EncryptPage, accelerator="Ctrl+E", underline=0)
        enterMenu.add_command(label = "File Encryption", accelerator="Ctrl+F", underline=0)
        enterMenu.add_command(label = "Decryption", command=DecryptPage, accelerator="Ctrl+D", underline=0)
        enterMenu.add_command(label = "Key Generator", accelerator="Ctrl+K", underline=0)
        enterMenu.add_command(label = "Logs", accelerator="Ctrl+L", underline=0)
        enterMenu.add_separator()
        enterMenu.add_command(label = "Check for updates", accelerator="Ctrl+Alt+U", command=CheckUpdates, underline=10)
        enterMenu.add_separator()
        enterMenu.add_command(label = "Exit", accelerator="Alt+F4", command=lambda:root.destroy())
        InfoVar = IntVar(); WarningVar = IntVar(); ErrorVar = IntVar(); InfoVar.set(1); WarningVar.set(1); ErrorVar.set(1)
        viewMenu.add_checkbutton(label = "Show info message dialogs", accelerator="Ctrl+Alt+I", onvalue=1, offvalue=0, variable=InfoVar, underline=5)
        viewMenu.add_checkbutton(label = "Show warning message dialogs", accelerator="Ctrl+Alt+W", onvalue=1, offvalue=0, variable=WarningVar, underline=5)
        viewMenu.add_checkbutton(label = "Show error message dialogs", accelerator="Ctrl+Alt+E", onvalue=1, offvalue=0, variable=ErrorVar, underline=5)
        viewMenu.add_separator()
        if True: #Transparency sub-menu
            transMenu.add_radiobutton(label = "%20", value=20, variable=Alpha, command=lambda:changeAlpha(20), accelerator="Ctrl+Alt+2")
            transMenu.add_radiobutton(label = "%40", value=40, variable=Alpha, command=lambda:changeAlpha(40), accelerator="Ctrl+Alt+4")
            transMenu.add_radiobutton(label = "%60", value=60, variable=Alpha, command=lambda:changeAlpha(60), accelerator="Ctrl+Alt+6")
            transMenu.add_radiobutton(label = "%80", value=80, variable=Alpha, command=lambda:changeAlpha(80), accelerator="Ctrl+Alt+8")
            transMenu.add_radiobutton(label = "%90", value=90, variable=Alpha, command=lambda:changeAlpha(90), accelerator="Ctrl+Alt+9")
            transMenu.add_radiobutton(label = "Opaque", value=100, variable=Alpha, command=lambda:changeAlpha(100), accelerator="Ctrl+Alt+1")
            transMenu.add_separator()
            transMenu.add_command(label = "Reset opacity", command=lambda:changeAlpha(100), accelerator="Ctrl+Alt+O", underline=6)
            viewMenu.add_cascade(menu=transMenu, label = "Window opacity")
        viewMenu.add_separator()
        if True: #Language sub-menu
            langMenu.add_radiobutton(label = "English [Coming Soon]")
            langMenu.add_radiobutton(label = "Türkçe [Yakında Geliyor]", state=DISABLED)
            langMenu.add_radiobutton(label = "Deutsche [Kommt Bald]", state=DISABLED)
            langMenu.add_radiobutton(label = "中国人 [即将推出]", state=DISABLED)
            langMenu.add_separator()
            langMenu.add_command(label = "Reset language to default", accelerator="Ctrl+Alt+L")
            viewMenu.add_cascade(menu=langMenu, label ="Language")
        menu.add_cascade(label = "Main", menu=enterMenu)
        menu.add_cascade(label = "Preferences", menu=viewMenu)
        menu.add_command(label = "Help", command=HelpPage)
    logTextWidget.config(state=NORMAL)
    logTextWidget.insert(INSERT, "ROOT: Created menu.\n")
    logTextWidget.config(state=DISABLED)
    if True: #File encryption frame
        FileEncryptFileSelect = Button(FileEncryptFrame, text = "Open a file...", width=15)
        FileEncryptPreviewBox = Text(FileEncryptFrame, height=10, width=48, state=DISABLED, font = ("Consolas", 9))
        FileEncryptScrollbar = Scrollbar(FileEncryptFrame, command=FileEncryptPreviewBox.yview)
        FileEncryptPreviewBox.config(yscrollcommand=FileEncryptScrollbar.set)
        FileEncryptPreviewCheck = Checkbutton(FileEncryptFrame, text="Preview file")
        FileEncryptFileEntry = Entry(FileEncryptFrame, width=50, font=("Consolas",9))
        FileEncryptEntryLabel = Label(FileEncryptFrame, text="File location:")
        FileEncryptPreviewLabel = Label(FileEncryptFrame, text="File preview:")
        FileEncryptShowPreview = Checkbutton(FileEncryptFrame, text="Show file preview")
        FileEncryptWarningButton = Button(FileEncryptFrame, text="Warning!", width=18)
        FileEncryptFileStatus = Label(FileEncryptFrame, text="Status: [No file selected]")

        FileEncryptEntryLabel.place(x=8, y=2)
        FileEncryptFileEntry.place(x=10, y=22)
        FileEncryptFileSelect.place(x=9, y=47)
        FileEncryptPreviewBox.place(x=10, y=93)
        FileEncryptPreviewCheck.place(x=10, y=300)
        FileEncryptScrollbar.place(x=349, y=93, height=145)
        FileEncryptPreviewLabel.place(x=8, y=72)
        FileEncryptShowPreview.place(x=252, y=71)
        FileEncryptWarningButton.place(x=249, y=47)
        FileEncryptFileStatus.place(x=113, y=50)
    TextToEncryptLabel = Label(EncryptFrame, text = "Plain text:")
    showCharCheck = Checkbutton(EncryptFrame, text = "Hide characters", variable = showCharState, onvalue = 1, offvalue = 0, command = toggleHideChar)
    if showChar == False:
        encryptedTextEntry = Entry(EncryptFrame, width = 50, show = "●", font=("Consolas",9))
        decryptedTextEntry = Entry(DecryptFrame, width = 50, show = "●", state=DISABLED, font=("Consolas",9))
    else:
        encryptedTextEntry = Entry(EncryptFrame, width = 50, font=("Consolas",9))
        decryptedTextEntry = Entry(DecryptFrame, width = 50, state=DISABLED, font=("Consolas",9))
        TextToEncryptLabel.place(x=8, y=2)
    if True: #Log frame
        LogClearButton = Button(LogFrame, text = "Clear", width=15)
        LogSaveButton = Button(LogFrame, text = "Save as...", width=15)
        LogSavePreset = Button(LogFrame, text = "Save to 'Encrypt-n-Decrypt.log'", width=28)
        LogClearButton.place(x=9, y=330)
        LogSavePreset.place(x=601, y=330)
        LogSaveButton.place(x=494, y=330)
    encryButton = Button(EncryptFrame, text = "Encrypt", width=15, command=Encrypt)
    checkButton = Button(EncryptFrame, text = "Check encryption", width=20, command=CheckEncrypt)
    copyButton = Button(EncryptFrameLabel, text = "Copy", width=10, command=Copy)
    clearButton = Button(EncryptFrameLabel, text = "Clear", width=9, command=Clear)
    encryptedTextWidget = Text(EncryptFrameLabel, height = 6, width = 52, state=DISABLED, font = ("Consolas", 9), bg="white", relief=SUNKEN)
    RSApublicKeyWidget = Text(EncryptFrameLabel, height = 6, width = 52, state=DISABLED, font = ("Consolas", 9), bg="white", relief=SUNKEN)
    RSAprivateKeyWidget = Text(EncryptFrameLabel, height = 6, width = 52, state=DISABLED, font = ("Consolas", 9), bg="white", relief=SUNKEN)
    AESkeyEntry = Text(EncryptFrameLabel, width=54, height=1, state=DISABLED, font=("Consolas",9), relief=SUNKEN)
    decryButton = Button(DecryptFrame, text = "Decrypt", width=22, command=Decrypt)
    decheckButton = Button(DecryptFrame, text = "Check decryption", width=20, command=CheckDecrypt)
    decopyButton = Button(DecryptFrame, text = "Copy", width=10, command=deCopy)
    declearButton = Button(DecryptFrame, text = "Clear", width=9, command=deClear)
    depasteButton = Button(DecryptFrame, text = "Paste", width=9, command=dePaste)
    decryptedTextWidget = Text(DecryptFrame, height = 6, width = 58, font = ("Segoe UI", 9))
    AESkeyLabel = Label(EncryptFrameLabel, text="AES/Fernet Key: (Symmetric Encryption)")
    RSApublicLabel = Label(EncryptFrameLabel, text="RSA Public Key: (Asymmetric Encryption)")
    RSAprivateLabel = Label(EncryptFrameLabel, text="RSA Private Key: (Asymmetric Encryption)")
    StatusLabelAES = Label(KeySelectFrame, text="Validity: [Blank]", foreground="gray")
    ToleranceLabel = Label(Asymmetric, text="±0", foreground="gray")
    CheckBase64Encoding = Checkbutton(KeySelectFrame, text="Allow non-base64.urlsafe encoded keys", onvalue=1, offvalue=0, variable=Base64Check, state=DISABLED, command=limitKeyEntry)
    encoding = StringVar();encoding.set("UTF-8")
    SelectEncoding = Combobox(EncryptFrame, width=7, textvariable=encoding, state="readonly", values=("UTF-8","UTF-16","UTF-32","ANSI"))
    scrollbar = Scrollbar(LogFrame)
    scrollbar2 = Scrollbar(EncryptFrameLabel)
    scrollbar3 = Scrollbar(EncryptFrameLabel)
    scrollbar4 = Scrollbar(EncryptFrameLabel)
    logTextWidget.config(yscrollcommand=scrollbar.set)
    RSApublicKeyWidget.config(yscrollcommand=scrollbar4.set)
    RSAprivateKeyWidget.config(yscrollcommand=scrollbar3.set)
    encryptedTextWidget.config(yscrollcommand=scrollbar2.set)
    scrollbar.config(command=logTextWidget.yview)
    scrollbar2.config(command=encryptedTextWidget.yview)
    scrollbar3.config(command=RSAprivateKeyWidget.yview)
    scrollbar4.config(command=RSApublicKeyWidget.yview)
    about = Text(AboutFrame, height = 28, width = 127, font = ("Segoe UI", 9), wrap=WORD)
    Text = "This program can encrypt and decrypt plain texts and files with AES-128, AES-192, AES-256, Fernet and RSA encryption standarts. AES-128 key is a 16 characters long and base64.urlsafe encoded key, AES-192 key is a 24 characters long and base64.urlsafe encoded key and AES-256 key is a 32 characters long and base64.urlsafe encoded key. RSA keys are base64.urlsafe encoded keys that in any length longer than 128 characters. Program can generate a fresh random AES or RSA key or can use a pre-generated key. In RSA encryption, Public Key is used to encrypt the data and Private Key is required to decrypt the cipher (Encrypted data). Public key can be extracted from Private key. 1024-bit RSA encryption can take 1 second to 10 seconds and 8196-bit RSA encryption can take 1 minute to 12 minutes depending on your computer. AES encryptions are way faster than RSA encryption. Fernet encryption (Legacy Fernet Key) also includes ability to change encryption time. That means you can encrypt your data with a fake date. But AES and RSA doesn't support this. Also you can select Fast mode to encrypt the data faster but bypass encyrption check.\n\nIf you are having problems with program, below information might be helpful to resolve problems:\n\nERR_ENCRYPTER_NOT_WORKING_PROPERLY: This error indicates that encrypter is not working properly even 'abc' text encryption failed. Try encrypting again after restarting the program. If problem persists, please report this problem to me.\n\nERR_INVALID_ENCRYPTION_KEY: This error occures when you selected to enter an encryption key and entered a non-encryption key. Please be sure you entered a AES-128, AES-192, AES-256, Fernet or RSA key that is bigger than 1024-bit; if the key you entered is one of them, be sure it's base64.urlsafe encoded.\n\nERR_UNENCRYPTABLE_TEXT: This error indicates that text you entered to encrypt is not encryptable or includes a illegal character for selected encoding system. Please try another text to encyrpt.\n\nERR_UNABLE_TO_CLEAR: This error pops-up when an unknown error occures while trying to clear the cipher or key from output. Only solution is probably restarting the program. If problem persists, please report this problem to me.\n\nERR_UNABLE_TO_DECRYPT: This errorVersion: {} Build 14\nAuthor: Yılmaz Alpaslan\ngithub.com\Yilmaz4\Encrypt-n-Decrypt".format(version)
    about.insert(INSERT, Text)
    about.configure(state=DISABLED)
    SelectEncoding.place(x=301, y=49)
    scrollbar.place(x=762, y=10, height=312)
    encryptedTextEntry.place(x=10, y=22)
    encryptedTextWidget.place(x=9, y=5)
    RSApublicKeyWidget.place(x=9, y=215)
    RSAprivateKeyWidget.place(x=9, y=355)
    StatusLabelAES.place(x=92, y=102)
    CheckBase64Encoding.place(x=16, y=144)
    AESkeyEntry.place(x=9, y=145)
    AESkeyLabel.place(x=8, y=125)
    RSApublicLabel.place(x=8, y=194)
    RSAprivateLabel.place(x=8, y=334)
    checkButton.place(x=116, y=48)
    encryButton.place(x=9, y=48)
    showCharCheck.place(x=261, y=1)
    copyButton.place(x=8, y=100)
    clearButton.place(x=85, y=100)
    about.place(x=10, y=10)
    decryptedTextEntry.place(x=10, y=150)
    decryptedTextWidget.place(x=10, y=10)
    decheckButton.place(x=160, y=117)
    decryButton.place(x=9, y=117)
    decopyButton.place(x=10, y=178)
    declearButton.place(x=87, y=178)
    depasteButton.place(x=300, y=117)
    logTextWidget.place(x=10, y=10)
    logTextWidget.config(state=NORMAL)
    logTextWidget.insert(INSERT, "ROOT: Created and placed all widgets.\n")
    logTextWidget.config(state=DISABLED)
    scrollbar2.place(x=376, y=5, height=88)
    scrollbar3.place(x=376, y=355, height=88)
    scrollbar4.place(x=376, y=215, height=88)
    if True: # Tooltips
        createToolTip(StatusLabelAES, "This label indicates the validity of the key you entered below.")
        createToolTip(checkButton, "Press this button to check if selected encryption options and key are working.")
        createToolTip(CheckBase64Encoding, "Select this checkbutton to disable base64 encoding requirement if you cannot decrypt encrypted text in another program.")
        createToolTip(ToleranceLabel, "This label indicates the tolerance of length of the RSA key that is going to be generated.")
        createToolTip(encryButton, "Press this button to encrypt entered text with selected options and selected key.")
        createToolTip(copyButton, "Press this button to copy the output (encrypted text) into clipboard.")
        createToolTip(clearButton, "Press this button to clear the output.")
        createToolTip(TextToEncryptLabel, "Write the text you want to encrypt below.")
        createToolTip(SelectKeyCheck, "If you want to use your key that was already generated, select this radiobutton and enter your key below.")
        createToolTip(AES128Check, "AES-128 key is a 16 characters long base64 encoded AES key. Currently secure against normal computers but unsecure against powerful quantum computers.\nAlso AES-128 keys will be unsecure for normal computers too in the future.  An AES-128 key has 2¹²⁸ of possible combinations.")
        createToolTip(AES192Check, "AES-192 key is a 24 characters long base64 encoded AES key. Ideal for most of encryptions and currently secure against super computers and quantum computers.\nBut while quantum computers are being more powerful, AES-192 keys will be unsecure against quantum computers in the future. An AES-192 key has 2¹⁹² of possible combinations.")
        createToolTip(AES256Check, "AES-256 key is a 32 characters long base64 encoded AES key. Impossible to crack with normal computers and highly secure against quantum computers.\nIt will take about billions of years to brute-force an AES-256 key with a normal computer as an AES-256 key has 2²⁵⁶ of possible combinations.\nIn theory, AES-256 key is 2¹²⁸ times stronger than AES-128 key.")
        createToolTip(AES352Check, "Legacy Fernet key is a 44 characters long base64 encoded key. In fact, Fernet key is a 32 characters long AES-256 key but after encoding key turns into 44 characters long key.\nFernet key is as secure as AES-256 key. Also Fernet key allows user to define a diffirent encryption time when encrypting and allows to extract encrypted time when decrypting.")
    def Loop():
        root.title("Eɲcrƴpʈ'n'Decrƴpʈ {}".format(version)+" - {}".format(time.strftime("%H"+":"+"%M"+":"+"%S"+" - "+"%d"+"/"+"%m"+"/"+"%Y")))
        if BenchVar.get() == 1 and KeySelectVar.get() == 1:
            Encrypt()
            root.after(1, Loop)
        elif BenchVar.get() == 1 and KeySelectVar.get() == 2:
            value = KeyValue.get()
            if len(value) == 16 or len(value) == 24 or len(value) == 32 or len(value) == 44:
                plaintext = bytes("TEST", 'utf-8')
                iv = Random.new().read(AES.block_size)
                iv_int = int(binascii.hexlify(iv), 16) 
                ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
                try:
                    aes = AES.new(bytes(value, 'utf-8'), AES.MODE_CTR, counter=ctr)
                    ciphertext = aes.encrypt(plaintext)
                except:
                    root.after(200, Loop)
                else:
                    Encrypt()
                    root.after(1, Loop)
            else:
                root.after(200, Loop)
        else:
            root.after(200, Loop)
    Loop();root.mainloop();exit()
except Exception as e:
    logTextWidget.config(state=NORMAL)
    logTextWidget.insert(INSERT, "ERROR: Unexpected & unknown error occured. {}\n".format(e))
    logTextWidget.config(state=DISABLED)