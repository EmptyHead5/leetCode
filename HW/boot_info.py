import hashlib
import os
import csv

#---------------------------------Load MBR Types---------------------------------
MBR_TYPES={}
def loadMbrTypes(path):
    global MBR_TYPES
    with open(path,'r') as f:
        reader=csv.reader(f)
        next(reader)
        for row in reader:
            MBR_TYPES[row[0].lower()]=row[1]
    return MBR_TYPES

MBR_TYPES=loadMbrTypes("PartitionTypes.csv")
def createHashInfoDirectory():
    os.makedirs("hash_info", exist_ok=True)
#---------------------------------Hash Computation---------------------------------
def computeHashes(path):
    md5=hashlib.md5()
    sha256=hashlib.sha256()
    sha512=hashlib.sha512()

    with open(path,'rb') as f:
        while True:
            data=f.read(65536)
            if not data:
                break
            md5.update(data)
            sha256.update(data)
            sha512.update(data)

    md5_hash = md5.hexdigest()
    sha256_hash = sha256.hexdigest()
    sha512_hash = sha512.hexdigest()

    createHashInfoDirectory()
    with open(f"hash_info/MD5-{os.path.basename(path)}.txt",'w') as f1:
        f1.write(md5_hash+'\n')
    with open(f"hash_info/SHA-256-{os.path.basename(path)}.txt",'w') as f2:
        f2.write(sha256_hash+'\n')
    with open(f"hash_info/SHA-512-{os.path.basename(path)}.txt",'w') as f3:
        f3.write(sha512_hash+'\n')


    return {"md5": md5_hash, "sha256": sha256_hash, "sha512": sha512_hash}


SECTION_SIZE = 512

# use offset to detect MBR signature
def detectMbrSignature(first_sector):
    mbrSignatureoffset = 510
    mbrSignature = first_sector[mbrSignatureoffset:mbrSignatureoffset + 2]
    if mbrSignature != b'\x55\xAA':
        return False
    return True

def isProtectiveMbr(firstSector):
    gptOffset = firstSector[446:462]
    if len(gptOffset)==16 and gptOffset[4]== 0xEE:
        return True
    return False

def detectGptHeader(file):
    file.seek(512,os.SEEK_SET)
    headerOffset = file.read(8)
    if headerOffset == b'EFI PART':
        return True
    return False
#---------------------------------Scheme Detection---------------------------------
#1.detect mbr signature
#2.check gpt protective mbr
#3.check gpt header
def detectScheme(path):
    with open(path, 'rb') as f:
        first=f.read(SECTION_SIZE)
        if detectMbrSignature(first)==False:
            return "UNKNOWN"
        if isProtectiveMbr(first) and detectGptHeader(f):
            return "GPT"
        else:
            return "MBR"
#---------------------------------MBR Partition Extraction---------------------------------
def mbrPartitions(path):
    parts=[]
    with open(path,'rb') as f:
        f.seek(446,os.SEEK_SET)
        for i in range(4):
            part=f.read(16)
            partType=part[4]
            if partType !=0x00:
                parts.append({
                    "Partition Number": i+1,
                    "Partition Type": MBR_TYPES.get(f"{partType:02x}","Unknown"),
                    "Starting LBA": int.from_bytes(part[8:12],'little'),
                    "Size in Sectors": int.from_bytes(part[12:16],'little')
                })
    return parts

def gptPartitions(path):
    print("Reading GPT Partitions")
    parts=[]
    with open(path,'rb') as f:
        f.seek(1024,os.SEEK_SET)
        for i in range(128):
            part=f.read(128)
            partTypeGuid=part[0:16]
            if partTypeGuid != b'\x00'*16:
                startingLBA=int.from_bytes(part[32:40],'little')
                endingLBA=int.from_bytes(part[40:48],'little')
                parts.append({
                    "Partition Number": i+1,
                    "Partition Type GUID": partTypeGuid.hex(),
                    "Starting LBA": startingLBA,
                    "Ending LBA": endingLBA,
                    "Size in Sectors": endingLBA - startingLBA + 1
                })
    return parts
#---------------------------------Main Execution---------------------------------
if __name__ == "__main__":
    filename = "mbr_sample.raw" 
    hashes = computeHashes(filename)
    scheme = detectScheme(filename)
    if scheme == "MBR":
        print("MBR Partition Detected")
        partitions = mbrPartitions(filename)
        print("MBR Partitions:")
        for part in partitions:
            print(part)
    elif scheme == "GPT":
        print("GPT Partition Detected")
        partitions = gptPartitions(filename)
        print("GPT Partitions:")
        for part in partitions:
            print(part)

    else:
        partitions = []
        print("UNKNOWN Partition Scheme Detected")
    print("Partition Scheme:", scheme)
    print("MD5:    ", hashes["md5"])
    print("SH-256: ", hashes["sha256"])
    print("SH-512: ", hashes["sha512"])