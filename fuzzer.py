#-*- coding: utf-8 -*-
"""
HWP Fuzzer 
"""

import OleFileIO_PL as OLE
import os
import shutil
import time
from random import sample, uniform, choice
import winappdbg
from winappdbg import *
from threading import Thread
from hashlib import md5

def pick():
    pick_file = choice(os.listdir("seed"))
    shutil.copy(os.getcwd()+"\\seed\\"+pick_file, "tmp")
    return pick_file

def mutation(dest_file):
    """

    :param dest_file: 뮤테이션 할 파일 경로 전달
    """
    dest_file = os.getcwd()+"\\tmp\\"+dest_file
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

    # 해당 스트림 사이즈의 0.1 ~ 3% 변조 할 오프셋 선택
    for offset, size in mutate_position:
        fuzz_offset += sample(xrange(offset, offset+size), int(size*uniform(0.001, 0.03)))

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

def handle(event):
    global proc
    global flag
    global crash_count
    code = event.get_event_code()
    proc = event.get_process()
    if ExceptionEvent(event.debug, event.raw).get_exception_code() in exceptions:
        print "[+] w00t!!! Crash!!"
        
        flag = True
        crash = Crash(event)
        crash.fetch_extra_data( event, takeMemorySnapshot = 0 ) 
        # 유니크 크래시 찾는 부분
        unique = crash.signature[3]
        if unique  in unique_list:
            print "[-] Duplicate Crash"
            proc.kill()
        else:
            crash_count += 1
            unique_list.append(unique)
            report = crash.fullReport()
            key = md5(unique).hexdigest()
            try:
                os.mkdir(r"result\%s" % key)
                with open(r"result\%s\log.txt" % key, "w") as f:f.write(report)
                shutil.copy(os.getcwd()+"\\seed\\"+target_file.split('\\')[-1], "result\\%s\\seed.%s" % (key, target_file.split(".")[-1]))
                shutil.copy(os.getcwd()+"\\tmp\\"+target_file.split('\\')[-1], "result\\%s\\mutate.%s" % (key, target_file.split(".")[-1]))
            except:pass
            finally:proc.kill()

def debuggee():
    with Debug(handle, bKillOnExit=True) as dbg:
        dbg.execl('"%s" "%s"' % (program, os.getcwd()+"\\tmp\\"+target_file))
        dbg.loop()

def runloop():
    thread = Thread(target=debuggee)
    thread.start()
    while True:
        if flag:
            thread.join()
            break
        if time.time() > maxTime and not flag:
            try:
                proc.kill()
            except:
                os.system("taskkill /f /im %s" % program.split('\\')[-1])
            thread.join()
            break
        time.sleep(0.5)

def emptyTemp():
    for x in os.listdir("tmp"):
        os.remove(r"tmp\%s" % x)


timeLimit = 4
exceptions = 0x80000002, 0xC0000005, 0xC000001D, 0xC0000025,\
             0xC0000026, 0xC000008C, 0xC000008E, 0xC0000090,\
             0xC0000091, 0xC0000092, 0xC0000093, 0xC0000094,\
             0xC0000095, 0xC0000096, 0xC00000FD, 0xC0000374
unique_list = []

program = r"C:\Program Files (x86)\Hnc\HCell80\HCell.exe"
crash_count = 0
iter=0
while True:
    iter +=1
    flag = False
    target_file = pick()
    mutation(target_file)
    os.system('cls')
    print "Iteration : %d / Crash : %d" % (iter, crash_count)
    maxTime = time.time() + timeLimit
    runloop()
    emptyTemp()
