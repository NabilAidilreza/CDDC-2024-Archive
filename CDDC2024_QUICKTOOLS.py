
#! System #
import sys,os
from pwn import remote,p32

#* Sub Libraries #
# Decoding/Encoding #
import base58
import base64
import binascii

# OSINT #
import webbrowser

# Forensics #
import glob
from PIL import Image
from PIL.ExifTags import TAGS

###! NOTE TO NEW USERS ###
###* EDIT TO CHANGE TO YOUR DEFAULT BROWSER PATH ###
bing_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
webbrowser.register('bing', None,  
                    webbrowser.BackgroundBrowser(bing_path)) 

###! Setup Var !####
flag_format = "CDDC2024{flag_payload}"

def check_OS():
    # CHECKING SYSTEM VERSION #
    op_sys = sys.platform
    if "WIN" in op_sys.upper():
        print("\t\t== Operating System: WINDOWS ===\n")
        print("\t\t== Using Win Quick Functions ===\n")
        return False
    elif ["UBUNTU","LINUX"] in op_sys.upper():
        print("\t\t== Operating System: LINUX   ===\n")
        print("\t\t== Using Lin Quick Functions ===\n")
        return True
    else:
        print("\t\t== Operating System: ------- ===\n")
        print("\t\t== Using   Python  Functions ===\n") 
        return False

def drawmainbanner():
    print(",_,_,_,_,_,_,_,_,_,_|______________________________________________________\n\
|#|#|#|#|#|#|#|#|#|#|_____________________________________________________/\n\
      ___  ___   ___    ___          ___     __      ___    _ _    \n\
     / __||   \ |   \  / __|        |_  )   /  \    |_  )  | | |   \n\
    | (__ | |) || |) || (__          / /   | () |    / /   |_  _|  \n\
     \___||___/ |___/  \___|        /___|   \__/    /___|    |_|  \n\
             _____   ___    ___   _     _  __ ___  _____ \n\
            |_   _| / _ \  / _ \ | |   | |/ /|_ _||_   _|\n\
              | |  | (_) || (_) || |__ |   <  | |   | |  \n\
              |_|   \___/  \___/ |____||_|\_\|___|  |_|  \n\
.______________________________________________________|_._._._._._._._._._.\n\
 \_____________________________________________________|_#_#_#_#_#_#_#_#_#_|\n\
\n\
                        ##################\n\
                        ## BY Stickybit ##\n\
                        ##################\n")

def drawsubbanner():
    print("<===================================================================================>\n\
 _____   ___    ___   _           ___  ___  _     ___   ___  _____  ___   ___   _  _ \n\
|_   _| / _ \  / _ \ | |         / __|| __|| |   | __| / __||_   _||_ _| / _ \ | \| |\n\
  | |  | (_) || (_) || |__       \__ \| _| | |__ | _| | (__   | |   | | | (_) || .  |\n\
  |_|   \___/  \___/ |____|      |___/|___||____||___| \___|  |_|  |___| \___/ |_|\_|\n\
          \n\
<===================================================================================>\n\n")


def displayMenu():
    print("\
<=== Quick ===>\n\
a. Decode (Base)\n\
b. Encode (Base)\n\
c. Search (OSINT)\n\
d. Report (Image)\n\
<== Misc ==>\n\
1. Read file in txt (large)\n\
2. Identify cipher\n\
3. Pwn test offset\n\n\
<== System ==>\n\
cmd: clr\n\
cmd: menu\n")

### ENCODE / DECODE ###

def quickEncode(string_to_encode):
    # Base64 #
    try:
        print("Attempting Base64 Encryption...")
        encoded_string = base64.b64encode(string_to_encode.encode())
        message = encoded_string.decode()
        print("Success!!!\nEncoded String => " + message)
    except (binascii.Error, ValueError):
        print("Failed.") 
    # Base32 #
    try:
        print("Attempting Base32 Encryption...")
        encoded_string = base64.b32encode(string_to_encode.encode())
        message = encoded_string.decode()
        print("Success!!!\nEncoded String => " + message)
    except (binascii.Error, ValueError):
        print("Failed.")
    # Base16 #
    try:
        print("Attempting Base16 Encryption...")
        encoded_string = base64.b16encode(string_to_encode.encode())
        message = encoded_string.decode()
        print("Success!!!\nEncoded String => " + message)
    except (binascii.Error, ValueError):
        print("Failed.")

    # Base58 #
    try:
        print("Attempting Base58 Encryption...")
        encoded_string = base58.b58encode(string_to_encode.encode())
        message = encoded_string.decode()
        print("Success!!!\nEncoded String => " + message)
    except (binascii.Error, ValueError):
        print("Failed.")

def quickDecode(encrypted_string,lst = []):
    base_encoding = lst
    message = ''
    def askRecursive(message,base_encoding):
        if message != "":
            tryRecursive(message,base_encoding)
        else:
            print("Unknown Base Encoding.")
    # Base64 #
    try:
        print("Attempting Base64 Decryption...")
        decrypted_string = base64.b64decode(encrypted_string, validate=True)
        message = decrypted_string.decode()
        base_encoding.append("base64")
        print("Success!!!\nDecrypted String => " + message)
        askRecursive(message,base_encoding)
        return
    except (binascii.Error, ValueError):
        print("Failed.") 
    # Base32 #
    try:
        print("Attempting Base32 Decryption...")
        decrypted_string = base64.b32decode(encrypted_string)
        message = decrypted_string.decode()
        base_encoding.append("base32")
        print("Success!!!\nDecrypted String => " + message)
        askRecursive(message,base_encoding)
        return
    except (binascii.Error, ValueError):
        print("Failed.")
    # Base16 #
    try:
        print("Attempting Base16 Decryption...")
        decrypted_string = base64.b16decode(encrypted_string)
        message = decrypted_string.decode()
        base_encoding.append("base16")
        print("Success!!!\nDecrypted String => " + message)
        askRecursive(message,base_encoding)
        return
    except (binascii.Error, ValueError):
        print("Failed.")
    # Base8 (Hex) #
    try:
        print("Attempting Base8 Decryption...")
        decrypted_string = bytearray.fromhex(encrypted_string)
        message = decrypted_string.decode()
        base_encoding.append("base8")
        print("Success!!!\nDecrypted String => " + message)
        askRecursive(message,base_encoding)
        return
    except ValueError:
        print("Failed.")
    
    # Base58 #
    try:
        print("Attempting Base58 Decryption...")
        decrypted_string = base58.b58decode(encrypted_string)
        message = decrypted_string.decode()
        base_encoding.append("base58")
        print("Success!!!\nDecrypted String => " + message)
        askRecursive(message,base_encoding)
        return
    except (binascii.Error, ValueError):
        print("Failed.")

def tryRecursive(string,lst = []):
    user = input("Try recursive decoding?: ")
    if user.lower() == 'y':
        quickDecode(string,lst)
        return 1
    else:
        print("\nFinal decrypted meesage => ",string)
        print("\nEncoding pattern: ",' => '.join(str(x) for x in lst))
        return 0

### SEARCH ###
def quickSearch(keyword):
    print("Opening relevant sites...")
    normal_search = "https://www.bing.com/search?q="+keyword
    map_search = "https://www.google.com/maps/search/"+keyword
    ip_search = "https://www.shodan.io/host/"+keyword
    web_history_search = "https://web.archive.org/web/20240000000000*/"+keyword
    webbrowser.get('bing').open(normal_search, new = 0, autoraise = True)
    webbrowser.get('bing').open(map_search, new = 0)
    webbrowser.get('bing').open(ip_search, new = 0)
    webbrowser.get('bing').open(web_history_search, new = 0)
    print("Visit 'https://osintframework.com/' for more useful OSINT tools...\n")
    print("Other useful sites: 'https://haveibeenpwned.com/'")
    return 0

### REPORT ###
def report_image():
    image_path = get_first_image_file(os.getcwd())
    if image_path:
        image = Image.open(image_path)
        exif_data = image._getexif()
        if exif_data:
            print("Retrieving EXIF Data...")
            for tag, value in exif_data.items():
                tag_name = TAGS.get(tag, tag)
                print(f"{tag_name}: {value}")
        else:
            print("No EXIF Metadata.")
    else:
        print("No valid image detected.")

def get_first_image_file(directory):
    patterns = ["*.jpg", "*.png", "*.jfif"]
    image_files = []
    for pattern in patterns:
        image_files.extend(glob.glob(os.path.join(directory, pattern)))
    if not image_files:
        return None
    return os.path.basename(image_files[0])

def readFile(filename):
    filesize = os.path.getsize(filename)
    if filesize < 1000000:
        with open(filename,"rb") as file:
            content = file.readlines()
            content = list(content)
            for ele in content:
                print(ele.decode())
    else:
        print("File too large. Splitting to same txts...")
        split = filesize // 300000
        for i in range(split):
            file = open(f"T{i}.txt","wb")
            temp = content[:300000]
            for ele in temp:
                file.write(ele)
            file.close()
            content = content[300000:]
        file = open(f"TFINAL.txt","wb")
        temp = content
        for ele in temp:
            file.write(ele)
        file.close()
        print("Success!!")

def tryOffset(hostport,offset):
    if hostport == "":
        return "Error encountered..."
    HOST, PORT = hostport.split()
    PORT = int(PORT)  # Ensure the port is an integer
    r = remote(HOST, PORT)
    actual_offset = 'A' * int(offset)  # Create the offset with 'A'
    print(r.recv())
    r.sendline(actual_offset)
    print("Payload sent: ",actual_offset)
    print(r.recv())

def main():
    islinux = check_OS()
    drawmainbanner()
    drawsubbanner()
    displayMenu()
    currenthostport=""
    while True:
        user = input("=> ")
        if user:
            if user.isnumeric():
                if user == '1':
                    print("Make sure file in same directory.")
                    filename = input("Filename (with extension) => ")
                    readFile(filename)
                elif user == '2':
                    identify_cipher = "https://www.dcode.fr/cipher-identifier"
                    webbrowser.get('bing').open(identify_cipher, new = 0, autoraise = True)
                elif user == '3':
                    print("Example: 3.1.147.170 10004")
                    if currenthostport != "":
                        print("Last Saved Host Port: ",currenthostport)
                    hostport = input("Host Port => ")
                    currenthostport = hostport
                    offset = input("Offset => ")
                    payload = input("Payload => ")
                    if hostport == "":
                        hostport = currenthostport
                    tryOffset(hostport,offset,payload)
            else:
                if user.lower() == 'a':
                    encrypted_string = input("Enter encrypted string => ")
                    quickDecode(encrypted_string)
                elif user.lower() == 'b':
                    string_to_encode = input("Enter string to encode => ")
                    quickEncode(string_to_encode)
                elif user.lower() == 'c':
                    keyword = input("Keyword => ")
                    quickSearch(keyword)
                elif user.lower() == 'd':
                    print("Make sure file in same directory.")
                    report_image()
                elif user.lower() == 'menu':
                    displayMenu()
                elif user.lower() == 'clr':
                    os.system('cls')
                    main()
                else:
                    continue
        else:
            continue

if __name__ == "__main__":
    main()
