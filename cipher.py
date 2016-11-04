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

    #s >> (8-i)
    #yield s


a = bytesToBits(strToBytes("hello"))

b = list(a)

c = bitsToBytes(b)
d = list(c)

print(b)
print(d)


for i in d:
    print(chr(i))
