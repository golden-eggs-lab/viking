import pickle

fileName = 'gk01.bin'

with open(fileName, mode='rb') as file: # b is important -> binary
    fileContent = file.read()

b = pickle.dumps(fileContent)
c = pickle.loads(b)

newFile = open("gk02.bin", "wb")
writeFile = bytearray(c)
newFile.write(c)

