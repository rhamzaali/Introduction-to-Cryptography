import random
from copy import copy


nRow = 0

def unpack_state(inp,num_blocks):
    """
    Convert a single int of num_blocks*4 bits into a Rijdael state
    """
    return [list(bitstring_to_kbit_stream(b,4,8))
        for b in bitstring_to_kbit_stream(inp,num_blocks,32)]

def pack_state(state,num_blocks): # check against standard and see if it ordered correctly
    result = 0
    for r in range(num_blocks):
        for c in range(4):
            result <<= 8
            result |= state[-(r+1)][-(c+1)]
    return result

# Rijndael S-box
sbox =  [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
         0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
         0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
         0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
         0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
         0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
         0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
         0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
         0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
         0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
         0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
         0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
         0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
         0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
         0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
         0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
# Rijndael Inverted S-box
rsbox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
            0x9e, 0x81, 0xf3, 0xd7, 0xfb , 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
            0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb , 0x54,
            0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
            0x42, 0xfa, 0xc3, 0x4e , 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
            0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 , 0x72, 0xf8,
            0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
            0x65, 0xb6, 0x92 , 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
            0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 , 0x90, 0xd8, 0xab,
            0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
            0x45, 0x06 , 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
            0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b , 0x3a, 0x91, 0x11, 0x41,
            0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
            0x73 , 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
            0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e , 0x47, 0xf1, 0x1a, 0x71, 0x1d,
            0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
            0xfe, 0x78, 0xcd, 0x5a, 0xf4 , 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
            0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f , 0x60,
            0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
            0x93, 0xc9, 0x9c, 0xef , 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
            0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 , 0x17, 0x2b,
            0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
            0x21, 0x0c, 0x7d]
# Rijndael Rcon
Rcon = [0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
            0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
            0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
            0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
            0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
            0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61,
            0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
            0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
            0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
            0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
            0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4,
            0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08,
            0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
            0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
            0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74,
            0xe8, 0xcb ]


# for mix columns (matrix multiplication)
fixedpoly = [[0x02,0x03,0x01,0x01],[0x01,0x02,0x03,0x01],[0x01,0x01,0x02,0x03],[0x03,0x01,0x01,0x02]]
invfixedpoly = [[0x0e,0x0b,0x0d,0x09],[0x09,0x0e,0x0b,0x0d],[0x0d,0x09,0x0e,0x0b],[0x0b,0x0d,0x09,0x0e]]

#Convert a string of bits (an int) into a stream of kbit blocks
def bitstring_to_kbit_stream(n, num_words, k=8):

    mask = (1<<k)-1
    for i in range(num_words):
        yield n&mask
        n >>= k

#Convert a single int of num_blocks*4 bits into a Rijdael state    
def create_state(inp,num_blocks):
    return [list(bitstring_to_kbit_stream(b,4,8))
        for b in bitstring_to_kbit_stream(inp,num_blocks,32)]

#Convert a Rijndael state into a human readable string for debugging
def state_to_str(state, num_blocks):
    s = ""
    for r in range(4):
        for c in range(num_blocks):
            s += "%02x "%state[r][c]
        s += "\n"
    return s



def subBytes(state,nBlocks,table):
    for c in range(nBlocks):
        for r in range(4):
            state[r][c] = table[state[r][c]]

def getRow(state,nBlocks,row):
    return [state[c][row] for c in range(nBlocks)]


def shiftRows(state,nRows,nBlocks):
    length = len(state)*4
    for i in range(1,nRows):
        temp = getRow(state,nBlocks,i)
        offset = i
        index = offset%length # why the negation?
        temp2 = temp[index:]+temp[:index]
        state[0][i] = temp2[0] 
        state[1][i] = temp2[1]
        state[2][i] = temp2[2]
        state[3][i] = temp2[3]
        
def invShiftRows(state,nRows,nBlocks):
    length = len(state)*4
    for i in range(1,nRows):
        temp = getRow(state,nBlocks,i)
        offset = i
        index = offset%length # why the negation?
        index = 4 - index
        temp2 = temp[index:]+temp[:index]
        state[0][i] = temp2[0] 
        state[1][i] = temp2[1]
        state[2][i] = temp2[2]
        state[3][i] = temp2[3]


def multGF256(p,q):     # p and q are elements of GF(2**8) m = x^8 + x^4 + x^3 + x + 1
    m = 0x11b   # modulus for GF(2**8)
    r = 0
    while q:    # for all coefficients of q
        if q&1: # add p if needed
            r ^= p
        #p = p*x (mod m)
        p <<= 1
        if p&0x100:
            p^= m

        #shift q
        q >>= 1
    return r


def colMult(p,q):    # pass functions plus and mult 
    rows_p = len(p)
    cols_p = len(p[0])
    rows_q = len(q)
    cols_q = 1#len(q[0])

    r = [[0 for row in range(cols_q)] for col in range(rows_p)]
    for i in range(rows_p):
        for j in range(cols_q):
            for k in range(cols_p):
                r[i][j] ^= multGF256(p[i][k],q[k][j])
                #r[i][j] += (p[i][k] * q[k][j])
    return r    

def mixColumns(state):
    i = 0
    for col in state:
        res = colMult(fixedpoly,[[col[0]],[col[1]],[col[2]],[col[3]]])
        state[i] = [res[0][0],res[1][0],res[2][0],res[3][0]]
        i+=1


def invMixColumns(state):
    i = 0
    for col in state:
        res = colMult(invfixedpoly,[[col[0]],[col[1]],[col[2]],[col[3]]])
        state[i] = [res[0][0],res[1][0],res[2][0],res[3][0]]
        i+=1

def keyExpansion(key):
    i = 0
    Nb = 4
    Nr = 10 # number of rounds for 128 bit
    Nk = 4
    w = [0] * (Nb * (Nr+1))
    while i < Nk:
        w[i] = bytesToWord([key[4*i],key[4*i+1],key[4*i+2],key[4*i+3]])
        i = i + 1
    i = Nk
    while i < (Nb * (Nr+1)):
        temp = w[i-1]
        if (i%Nk == 0):
            temp = subWord(rotWord(temp,1)) ^ bytesToWord([Rcon[int(i/Nk)],0x00,0x00,0x00])
        elif (Nk > 6 & i%Nk == 4):
            temp = subWord(temp)
        w[i] =   w[i-Nk] ^ temp
        i += 1
    return w


def bytesToWord(arrBytes):
    arrBytes = arrBytes[::-1]
    i = 3
    word = 0x0
    while i >= 0:
        word |= arrBytes[i] << 8*i
        i-=1
    return word

def wordToBytes(word):
    i = 0
    arrBytes = [0]*4
    while i < 4:
        arrBytes[i] = word & 0xFF
        word >>= 8
        i+=1
    return arrBytes[::-1]
    

def subWord(word):
    arr = wordToBytes(word)
    for i in range(len(arr)):
        arr[i] = sbox[arr[i]]
    word = bytesToWord(arr)
    return word
        
def rotWord(word, n):
    arr = wordToBytes(word)
    word =  bytesToWord(arr[n:]+arr[0:n])
    return word

def showHex(arr): #for debugging
    for i in range(4):
        for j in range(4):
            print(hex(arr[i][j])," ",end="")
        print("")
    print("")
        

def boxifyKey(key):
    a = [key[0],key[1],key[2],key[3]]
    b = [key[4],key[5],key[6],key[7]]
    c = [key[8],key[9],key[10],key[11]]
    d = [key[12],key[13],key[14],key[15]]
    boxKey = [a,b,c,d]
    return boxKey


def addRoundKey(state,w):
    for i in range(4):
        for j in range(4):
            state[i][j] = state[i][j] ^ w[i][j]


def cipher(state,boxKey):
    addRoundKey(state,boxKey) #for first run, round key value is the original key itself
    for i in range(9): # number of rounds -1 because first round done above
        subBytes(state,4,sbox)#
        shiftRows(state,4,4)#
        mixColumns(state)#
        addRoundKey(state,unpackWord(boxifyWord(w[i*4+0],w[i*4+1],w[i*4+2],w[i*4+3])))
    subBytes(state,4,sbox)#
    shiftRows(state,4,4)#
    addRoundKey(state,unpackWord(boxifyWord(w[36],w[37],w[38],w[39]))) # last 4 round word keys

# debug version
##def cipher(state,boxKey):
##    print("round[0].input   ",end="")
##    oneliner(state)
##    addRoundKey(state,boxKey) #for first run, round key value is the original key itself
##    print("round[0].k_sch   ",end="") # round key schedule value
##    oneliner(boxKey)
##    for i in range(9): # number of rounds -1 because first round done above
##        print("round[",(i+1),"].start   ",sep="",end="")
##        oneliner(state)
##        subBytes(state,4,sbox)#
##        print("round[",(i+1),"].s_box   ",sep="",end="")
##        oneliner(state)
##        shiftRows(state,4,4)#
##        print("round[",(i+1),"].s_row   ",sep="",end="")
##        oneliner(state)
##        mixColumns(state)#
##        print("round[",(i+1),"].m_col   ",sep="",end="")
##        oneliner(state)
##        print("round[",(i+1),"].k_sch   ",sep="",end="")
##        oneliner(unpackWord(boxifyWord(w[i*4+0],w[i*4+1],w[i*4+2],w[i*4+3])))
##        addRoundKey(state,unpackWord(boxifyWord(w[i*4+0],w[i*4+1],w[i*4+2],w[i*4+3])))
##    print("round[10].start   ",sep="",end="")
##    oneliner(state)
##    subBytes(state,4,sbox)#
##    print("round[10].s_box   ",sep="",end="")
##    oneliner(state)
##    shiftRows(state,4,4)#
##    print("round[10].s_row   ",sep="",end="")
##    oneliner(state)
##    print("round[10].k_sch   ",sep="",end="")
##    oneliner(unpackWord(boxifyWord(w[36],w[37],w[38],w[39])))           
##    addRoundKey(state,unpackWord(boxifyWord(w[36],w[37],w[38],w[39])))#
##    print("round[10].output   ",sep="",end="")
##    oneliner(state)

def invCipher(state,boxKey):
    addRoundKey(state,unpackWord(boxifyWord(w[36],w[37],w[38],w[39]))) # assuming key goes here again
    k = 0
    for i in range(8,-1,-1): # go in reverse
        invShiftRows(state,4,4)
        subBytes(state,4,rsbox)
        addRoundKey(state,unpackWord(boxifyWord(w[i*4+0],w[i*4+1],w[i*4+2],w[i*4+3])))
        invMixColumns(state)
        k+=1
    invShiftRows(state,4,4)
    subBytes(state,4,rsbox)
    addRoundKey(state,boxKey) # first four
    

# debug version of the inverse cipher
##def invCipher(state,boxKey):
##    print("round[0].iinput   ",end="")
##    oneliner(state)
##    print("round[0].ik_sch   ",end="") # round key schedule value
##    oneliner(unpackWord(boxifyWord(w[36],w[37],w[38],w[39])))
##    addRoundKey(state,unpackWord(boxifyWord(w[36],w[37],w[38],w[39]))) # assuming key goes here again
##    k = 0
##    for i in range(8,-1,-1): # go in reverse
##        print("round[",(k+1),"].istart   ",sep="",end="")
##        oneliner(state)
##        invShiftRows(state,4,4)
##        print("round[",(k+1),"].is_row   ",sep="",end="")
##        oneliner(state)
##        subBytes(state,4,rsbox)
##        print("round[",(k+1),"].is_box   ",sep="",end="")
##        oneliner(state)
##        print("round[",(k+1),"].is_sch   ",sep="",end="")
##        oneliner(unpackWord(boxifyWord(w[i*4+0],w[i*4+1],w[i*4+2],w[i*4+3])))
##        addRoundKey(state,unpackWord(boxifyWord(w[i*4+0],w[i*4+1],w[i*4+2],w[i*4+3])))
##        print("round[",(k+1),"].ik_add   ",sep="",end="")
##        oneliner(state)
##        invMixColumns(state)
##        k+=1
##    print("round[10].istart   ",sep="",end="")
##    oneliner(state)
##    invShiftRows(state,4,4)
##    print("round[10].is_row   ",sep="",end="")
##    oneliner(state)
##    subBytes(state,4,rsbox)
##    print("round[10].is_box   ",sep="",end="")
##    oneliner(state)
##    print("round[10].is_sch   ",sep="",end="")
##    oneliner(boxKey)
##    addRoundKey(state,boxKey) # first four
##    print("round[10].ioutput   ",sep="",end="")
##    oneliner(state)

    
def boxifyWord(w1,w2,w3,w4):    # convert 4 lists into 2d array
    return [[w1],[w2],[w3],[w4]]

def unpackWord(w):
    a = wordToBytes(w[0][0])
    b = wordToBytes(w[1][0])
    c = wordToBytes(w[2][0])
    d = wordToBytes(w[3][0])
    return ([a,b,c,d])


def bytesToWord32(arrBytes): # bytes to word 32 bit version
    arrBytes = arrBytes[::-1]
    i = 3
    word = 0x0
    while i >= 0:
        word |= arrBytes[i] << 32*i
        i-=1
    return word

def oneliner(state): # generate 32 bit hex value for debugging
    a = bytesToWord([state[0][0],state[0][1],state[0][2],state[0][3]])
    b = bytesToWord([state[1][0],state[1][1],state[1][2],state[1][3]])
    c = bytesToWord([state[2][0],state[2][1],state[2][2],state[2][3]])
    d = bytesToWord([state[3][0],state[3][1],state[3][2],state[3][3]])
    print(hex(bytesToWord32([a,b,c,d])))

def getBlock(raw):  # convert raw string to 16 bit block
    if len(raw) == 0:
        return ""
    # container for list of bytes
    block = []
    for c in list(raw):
        block.append(ord(c))
    # if the block is less than 16 bytes, pad the block
    # with the string representing the number of missing bytes
    if len(block) < 16:
        padChar = 16-len(block)
        while len(block) < 16:
            block.append(padChar)
    a = block[:4]
    b = block[4:8]
    c = block[8:12]
    d = block[12:]
    block = [a,b,c,d]
    return block

def getString(block):
    a = [item for sublist in block for item in sublist]
    a = [0 if x in range(1,31) else x for x in a]
    a = [chr(item) for item in a]
    b = ''.join(a)
    b = b.replace("\00", "")
    print(b)
    


key = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f]
w = keyExpansion(key)
w = w[4:] # first four are original key values so slice off
boxKey = boxifyKey(key) # convert key to 2d array

print("A 128-bit encryption")
print("Encrypting string = 'Hello World':")
a = getBlock("Hello World")
state = a
cipher(state,boxKey)
print("Encrypted text:")
getString(state)
invCipher(state,boxKey)
print("Decrypting text..")
print("decryption result string:")
getString(state)

