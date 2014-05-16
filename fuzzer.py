"""
HWP Fuzzer
"""

import OleFileIO_PL as OLE
import random

find_list = []
mutate_position = []

ole = OLE.OleFileIO("test.hwp")
ole_list = ole.listdir()

for entry in ole_list:
    if "BinData" in entry and entry[1].find("OLE") != -1 :
        find_list.append((ole.openstream("BinData/"+entry[1]).read(16), ole.get_size("BinData/"+entry[1])))
    if "BodyText" in entry:
        find_list.append((ole.openstream("BodyText/"+entry[1]).read(16), ole.get_size("BodyText/"+entry[1])))
    if "BinOLE" in entry:
        find_list.append((ole.openstream("BinOLE/"+entry[1]).read(16), ole.get_size("BinOLE/"+entry[1])))
ole.close()

with open('test2.hwp','r+b') as f: hwp=f.read()
hwp_write = bytearray(hwp)

for magic, size in find_list:
    if hwp.find(magic) != -1:
        offset = hwp.find(magic)
        mutate_position.append((offset, size))

for offset, offset_end in mutate_position:        
    print random.randint(offset, offset+offset_end)
