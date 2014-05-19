#-*- coding: utf-8 -*-
"""
HWP Fuzzer 
"""

import OleFileIO_PL as OLE
import os
import shutil
from random import sample, uniform, choice

def pick():
    pick_file = choice(os.listdir("seed"))
    shutil.copy(os.getcwd()+"\\seed\\"+pick_file, "tmp")
    return os.getcwd()+"\\tmp\\"+pick_file

def mutation(dest_file):
    """

    :param dest_file: 뮤테이션 할 파일 경로 전달
    """
    find_list = []
    mutate_position = []
    # HWP파일의 OLE구조에서 Bindata, BodyText, BinOLE 스토리지 하위 스트림 분석
    # 해당 스트림의 상위 16바이트를 Magic으로 사용하고 사이즈를 구함
    ole = OLE.OleFileIO(dest_file)
    ole_list = ole.listdir()

    for entry in ole_list:
        if "BinData" in entry and entry[1].find("OLE") != -1 :
            find_list.append((ole.openstream("BinData/"+entry[1]).read(16), ole.get_size("BinData/"+entry[1])))
        if "BodyText" in entry:
            find_list.append((ole.openstream("BodyText/"+entry[1]).read(16), ole.get_size("BodyText/"+entry[1])))
        if "BinOLE" in entry:
            find_list.append((ole.openstream("BinOLE/"+entry[1]).read(16), ole.get_size("BinOLE/"+entry[1])))
        if "Workbook" in entry:
            find_list.append((ole.openstream("Workbook").read(16), ole.get_size("Workbook")))
    ole.close()

    fuzz_offset = []
    fuzz_byte = xrange(256)
    with open(dest_file, 'rb') as f:
        hwp = f.read()

    hwp_write = bytearray(hwp)
    hwp_length = len(hwp)
    # 파일에서 Magic의 오프셋을 검색하여 리스트에 저장
    for magic, size in find_list:
        if hwp.find(magic) != -1:
            offset = hwp.find(magic)
            mutate_position.append((offset, size))

    # 해당 스트림 사이즈의 1 ~ 10% 변조 할 오프셋 선택
    for offset, size in mutate_position:
        fuzz_offset += sample(xrange(offset, offset+size), int(size*uniform(0.01, 0.1)))

    # 변조
    for index in fuzz_offset:
        if index >= hwp_length : continue
        hwp_write[index] = choice(fuzz_byte)
    # 파일로 저장
    try:
        with open(dest_file, 'wb') as f:
            f.write(hwp_write)
        return True
    except IOError as error:
        print error
        return False

target_file = pick()
print mutation(target_file)
