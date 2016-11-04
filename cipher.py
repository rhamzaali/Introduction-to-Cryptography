def strToBytes(mStr):
    return mStr.encode()

def bytesToBits(byteStr):
    for b in byteStr:
        for i in range(8):
            yield b & 1
            b >>=1


def bitsToBytes(bitStr):
    s = 0
    i = 0
    for b in bitStr:
        s = (s>>1)|(0,0x80)[b]   # right shift by 1, do OR for 8th bit with b
        i+=1
        if i == 8:
            yield s
            #s = 0
            i = 0

    if(len(bitStr)%8 !=0): # only for when the length isn't a mulitple of 8,
                           # otherwise will repeat last byte again
        s >> (8-i)
        yield s

def bytesToStr(mBytes):
    s = ""
    for i in mBytes:
        s+=chr(i)
    return s


a = bytesToBits(strToBytes("how much wood would a woodchuck chuck?"))
b = list(a)

c = bitsToBytes(b)
d = list(c)

print("Converting bytes to bits")
print(b)
print("Converting bits to bytes")
print(d)
print("Converting back to string input")
print(bytesToStr(d))

