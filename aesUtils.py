import numpy as np
from Sbox import *
import base64

def b64e(s):
    return base64.b64encode(s.encode()).decode()


def b64d(s):
    return base64.b64decode(s).decode()

    
def mul2(r):
    b = [0 for i in range(4)]
    for c in range(0, 4):
        h = (r[c] >> 7) & 1
        b[c] = r[c] << 1
        b[c] ^= h * 0x1B
    return b

def mul3(r):
    b = mul2(r);
    for c in range(0, 4):
        b[c] = b[c] ^ r[c]
    return b

def mul9(r):
    b = list.copy(r)
    for i in range(0, 3):
        b = mul2(b)
    for c in range(0, 4):
        b[c] ^= r[c]
    return b

def mul11(r):
    b = list.copy(r)
    b = mul2(b)
    b = mul2(b)
    for c in range(0, 4):
        b[c] ^= r[c]
    b = mul2(b)
    for c in range(0, 4):
        b[c] ^= r[c]
    return b

def mul13(r):
    b = list.copy(r)
    b = mul2(b)
    for c in range(0, 4):
        b[c] ^= r[c]
    b = mul2(b)
    b = mul2(b)
    for c in range(0, 4):
        b[c] ^= r[c]
    return b            

def mul14(r):
    b = list.copy(r)
    b = mul2(b)
    for c in range(0, 4):
        b[c] ^= r[c]
    b = mul2(b)
    for c in range(0, 4):
        b[c] ^= r[c]
    b = mul2(b)
    return b

def rotWord(r):
    r[0], r[1], r[2], r[3] = r[1], r[2], r[3], r[0]
    return r

def keyExpansion128(key):
    retkey = []
    retkey.append(list.copy(key))
    for i in range(0, 10):
        newkey = [];
        interkey = list.copy(retkey[-1]) # 4x4 array
        interkey = np.transpose(interkey)
        interkey = interkey.tolist()
        rconarr = [rcon[i], 0, 0, 0]
        workingarr = list.copy(interkey[-1]) # 1x4 array
        workingarr = rotWord(workingarr)
        for q in range(0, 4):
            workingarr[q] = sbox[workingarr[q]]
        for j in range(0, len(workingarr)):
            workingarr[j] = workingarr[j] ^ interkey[0][j] ^ rconarr[j]
        newkey.append(list.copy(workingarr))
        for k in range(1, 4):
            for j in range(0, 4):
                workingarr[j] = workingarr[j] ^ interkey[k][j]
            newkey.append(list.copy(workingarr))
        newkey = np.transpose(newkey)
        newkey = newkey.tolist()
        retkey.append(newkey)
        
        # FOR PRINTING

        # for v in range(0, 4):
        #     for u in range(0, 4):
        #         print("{:0x}".format(newkey[v][u]), end=" ");
        #     print()
        # print("______________________")

    return retkey


def keyExpansion192(key):
    retkey = []

    #key: 6 x 4 array

    for i in key:
        retkey.append(list.copy(i))

    for i in range(0, 8):
        rconarr = [rcon[i], 0, 0, 0]
        index = len(retkey) - 6
        k6n_6 = list.copy(retkey[index])
        workingarr = list.copy(retkey[-1])
        workingarr = rotWord(workingarr)
        for q in range(0, 4):
            workingarr[q] = sbox[workingarr[q]]
        for j in range(0, len(workingarr)):
            workingarr[j] = workingarr[j] ^ k6n_6[j] ^ rconarr[j]
        retkey.append(list.copy(workingarr))
        index += 1
        for k in range(0, 5):
            for j in range(0, 4):
                workingarr[j] = workingarr[j] ^ retkey[index][j]
            retkey.append(list.copy(workingarr))
            index += 1

    expandedKey = []

    for i in range(0, 13):
        interkey = []
        for j in range(0, 4):
            interkey.append(list.copy(retkey.pop(0)))
        interkey = np.transpose(interkey)
        interkey = interkey.tolist()
        expandedKey.append(interkey)

    return expandedKey
    

def keyExpansion256(key):
    retkey = []

    #key: 8 x 4 array

    for i in key:
        retkey.append(list.copy(i))

    for i in range(0, 7):
        rconarr = [rcon[i], 0, 0, 0]
        index = len(retkey) - 8
        k8n_8 = list.copy(retkey[index])
        workingarr = list.copy(retkey[-1])
        workingarr = rotWord(workingarr)
        for q in range(0, 4):
            workingarr[q] = sbox[workingarr[q]]
        for j in range(0, len(workingarr)):
            workingarr[j] = workingarr[j] ^ k8n_8[j] ^ rconarr[j]
        retkey.append(list.copy(workingarr))
        index += 1
        for k in range(0, 3):
            for j in range(0, 4):
                workingarr[j] = workingarr[j] ^ retkey[index][j]
            retkey.append(list.copy(workingarr))
            index += 1

        for q in range(0, 4):
            workingarr[q] = sbox[workingarr[q]]

        for j in range(0, 4):
            workingarr[j] = workingarr[j] ^ retkey[index][j]
        retkey.append(list.copy(workingarr))
        index += 1

        for k in range(0, 3):
            for j in range(0, 4):
                workingarr[j] = workingarr[j] ^ retkey[index][j]
            retkey.append(list.copy(workingarr))
            index += 1

    expandedKey = []

    for i in range(0, 15):
        interkey = []
        for j in range(0, 4):
            interkey.append(list.copy(retkey.pop(0)))
        interkey = np.transpose(interkey)
        interkey = interkey.tolist()
        expandedKey.append(interkey)

    return expandedKey

def stringToMat(s):
    
    ret = []
    interkey = []

    for i in range(0, len(s)):
        interkey.append(ord(s[i]))
        if ((i % 4 == 3)):
            ret.append(interkey)
            interkey = []

    ret = np.transpose(ret)
    ret = ret.tolist()
    return ret

def hexaToMat(s):
    ret = []
    interkey = []

    s = [s[y - 2:y] for y in range(2, len(s) + 2, 2)]

    for i in range(0, len(s)):
        interkey.append(int(s[i], 16))
        if ((i % 4 == 3)):
            ret.append(interkey)
            interkey = []

    ret = np.transpose(ret)
    ret = ret.tolist()
    return ret

def matToString(s):

    s = np.transpose(s)
    s = np.ravel(s)
    s = s.tolist()

    retString = ""

    for i in s:
        retString += chr(i)
    
    return retString

def matToHexa(s):
    s = np.transpose(s)
    s = np.ravel(s)
    s = s.tolist()

    retString = ""

    for i in s:
        if(i == 0):
            retString += "00"
        temp = hex(i).lstrip("0x").rstrip("L")
        if (len(temp) == 1):
            temp = "0" + temp
        retString += temp
    
    return retString

def xorMatrix(a, b):
    ret = [[0 for i in range(len(a[0]))] for k in range(len(a))]
    for i in range(len(a)):
        for j in range(len(a[0])):
            ret[i][j] = a[i][j] ^ b[i][j]
    return ret

def _4x4print(mat):
    for v in range(0, 4):
        for u in range(0, 4):
            print("{:0x}".format(mat[v][u]), end=" ");
        print()
    print("___________________")