#!/usr/bin/env python
import sys, struct, os, hashlib, hmac, zlib

#***************************************************************************
#***************************************************************************
#***************************************************************************

CRC16tab = [0]*256
for i in xrange(256):
  r = i << 8
  for j in xrange(8): r = (r << 1) ^ (0x1021 if r & 0x8000 else 0)
  CRC16tab[i] = r & 0xFFFF

def CrcIdx(w, crc=0x3FFF):
  for b in bytearray(struct.pack("<H", w)): crc = (CRC16tab[b ^ (crc >> 8)] ^ (crc << 8)) & 0x3FFF
  return crc

def Crc16(ab, crc=0xFFFF):
  for b in bytearray(ab): crc = (CRC16tab[b ^ (crc >> 8)] ^ (crc << 8)) & 0xFFFF
  return crc

#***************************************************************************
#***************************************************************************
#***************************************************************************

crcTabLo = bytearray([0, 7, 14, 9, 28, 27, 18, 21, 56, 63, 54, 49, 36, 35, 42, 45])
crcTabHi = bytearray([0, 112, 224, 144, 199, 183, 39, 87, 137, 249, 105, 25, 78, 62, 174, 222])
def CSum8(ab):
  csum = 1
  for b in bytearray(ab):
    b ^= csum
    csum = crcTabLo[b & 0xF] ^ crcTabHi[b >> 4]
  return csum

#***************************************************************************
#***************************************************************************
#***************************************************************************

import zipfile, posixpath
class zipStorage(object):
  compression = zipfile.ZIP_STORED
  #compression = zipfile.ZIP_DEFLATED
  def __init__(self, baseName):
    self.fn = baseName + ".zip"
    self.z = zipfile.ZipFile(self.fn, "w", self.compression)
    self.baseDir = None

  def setBaseDir(self, baseDir=None):
    self.baseDir = baseDir
    return self

  def add(self, path, data=None):
    if self.baseDir: path = posixpath.join(self.baseDir, path)
    zi = zipfile.ZipInfo(path)
    if data is None: zi.external_attr = 0x30 # Folder
    self.z.writestr(zi, data or "")
    del zi

  def __del__(self):
    self.z.close()

#***************************************************************************
#***************************************************************************
#***************************************************************************

def sCfgMode(mode):
  assert 0 == (mode & ~0x1FFF) # Only 13 lowest bits used
  typ = " d"
  #      842184218421
  sfl = "AEIrwxrwxrwx" # A for Anti-Replay, E for Encrypton, I for Integrity
  r = []
  for i in xrange(len(sfl)):
    r.append(sfl[i] if mode & (1<<(len(sfl)-1-i)) else "-")
  return typ[mode >> 12] + "".join(r)

def sCfgOpt(mode):
  assert 0 == mode & ~0x001F, "mode == 0x%X" % mode # Only 5 lowest bits used
  sfl = "^?!MF" # M for afterManufacture, F for fromFIT
  r = []
  for i in xrange(len(sfl)):
    r.append(sfl[i] if mode & (1<<(len(sfl)-1-i)) else "-")
  return "".join(r)

#***************************************************************************
#***************************************************************************
#***************************************************************************

VFS_integrity    = 0x0200
VFS_encryption   = 0x0400
VFS_antireplay   = 0x0800
VFS_nonIntel     = 0x2000
VFS_directory    = 0x4000

def sVarMode(mode):
  typ = " d"
  #      21842184218421
  sfl = "N?AEIrwxrwxrwx" # N for Non-intel, A for Anti-Replay, E for Encrypton, I for Integrity
  r = []
  for i in xrange(len(sfl)):
    r.append(sfl[i] if mode & (1<<(len(sfl)-1-i)) else "-")
  return typ[mode >> 14] + "".join(r)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class MFS_Var_Folder_Entry(object):
  fmtRec = struct.Struct("<LHHHH12s")
  def __init__(self, ab, iRec):
    self.iRec = iRec
    self.fileno, self.mode, self.uid, self.gid, self.salt, name = self.fmtRec.unpack_from(ab, iRec * self.fmtRec.size)
    self.name = name.split('\0', 1)[0]
    self.iFile = self.fileno & 0xFFF

  def __str__(self):
    return "iF=%03X m=%s u=%04X g=%04X s=%08X.%04X %s" % (self.iFile, sVarMode(self.mode), self.uid, self.gid, self.fileno, self.salt, self.name)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class MFS_Blob_Security(object):
  fmt = struct.Struct("<32sL16s")
  def __init__(self, blob):
    self.blob = blob

    blob.ab, self.ab = blob.ab[:-self.fmt.size], blob.ab[-self.fmt.size:] # Separate blob and security data
    self.hmac, self.flags, self.nonce = self.fmt.unpack(self.ab)
    self.tail = struct.pack("<32sL16sLL", '\0'*32, self.flags, self.nonce, blob.fileno, blob.salt)

    self.ar  = (self.flags) & 3 # bits 0-1
    self.enc = (self.flags >> 2) & 1 # bit 2
    self.u7  = (self.flags >> 3) & 0x7F # bits 3-9
    self.iAR = (self.flags >> 10) & 0x3FF # bits 10-19
    self.u12 = (self.flags >> 20) # bits 20-31
    if self.ar: self.rnd, self.ctr = struct.unpack_from("<LL", self.nonce)

    assert 0x12 == self.u7
    assert self.enc << 1 == self.u12

    if 0 == (self.flags & 7):
#      if '\0'*16 != self.nonce: print self.nonce.encode("hex")
      assert '\0'*16 == self.nonce # Empty nonce if no AR/Enc

  def __str__(self):
#    return "ar=%d:%03X enc=%d:%s u7=%02X u12=%03X hmac=%s" % (self.ar, self.iAR, self.enc, self.nonce.encode("hex"), self.u7, self.u12, self.hmac.encode("hex"))

    sENC = "iv=%s" % (self.nonce.encode("hex"))
    if not self.enc: sENC = ' '*len(sENC)
    sAR = "ar=%d:%03X:%08X:%08X" % (self.ar, self.iAR, self.rnd, self.ctr) if self.ar else ' '*24
    sU7 = "u7=%02X" % self.u7
    if 0x12 == self.u7: sU7 = ' '*len(sU7)
    sU12 = "u12=%02X" % self.u12
    if self.enc << 1 == self.u12: sU12 = ' '*len(sU12)
    return "%s %s %s %s" % (sENC, sAR, sU7, sU12)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class MFS_Blob(object):
  def __init__(self, mfs, fileno, mode=VFS_integrity|VFS_nonIntel, salt=0):
    self.mfs, self.fileno, self.mode, self.salt = mfs, fileno, mode, salt
    self.ab = mfs.getFileData(self.fileno & 0xFFF) # Read MFS record data
    self.sec = MFS_Blob_Security(self) if self.mode & VFS_integrity else None
    self.typ = 0

  def asFolder(self, path):
    self.typ = 1
    self.path = path
    assert 0x90 == self.sec.flags
    nRec, left = divmod(len(self.ab), MFS_Var_Folder_Entry.fmtRec.size)
    assert 0 == left
    self.aE = [MFS_Var_Folder_Entry(self.ab, iRec) for iRec in xrange(nRec)]

  def __str__(self):
    r = ["%s/[%d]" % (self.path, len(self.aE))]
    for i, e in enumerate(self.aE): r.append("%3d: %s" % (i, e))
    return "\n".join(r + [""])

#***************************************************************************
#***************************************************************************
#***************************************************************************

class MFS_Page(object):
  fmtHdr = struct.Struct("<LLLHHBB")
  fmtChunk = struct.Struct("<64sH")
  def __init__(self, ab, iPage):
    o = iPage * MFS.PAGE_SIZE
    self.iPage = iPage
    self.data = ab[o:o+MFS.PAGE_SIZE]
    self.sign, self.USN, self.nErase, self.iNextErase, self.firstChunk, csum, b0 = self.fmtHdr.unpack_from(self.data)
    self.bData = self.firstChunk > 0
    assert 0xAA557887 == self.sign # Page signature
    assert csum == CSum8(self.data[:16]) # Page Header checksum
    assert 0 == b0
    self.oInfo = self.fmtHdr.size

    if self.bData:
      self.mFree = bytearray(self.data[self.oInfo:self.oInfo + MFS.nDataPageChunks])
      self.oChunks = MFS.oDataChunks
    else:
      assert 0 == self.firstChunk
      self.axIdx = struct.unpack_from("<%dHH" % MFS.nSysPageChunks, self.data, self.oInfo)
      self.oChunks = MFS.oSysChunks

      iChunk, self.aiChunk = 0, []
      for iRec in xrange(MFS.nSysPageChunks): # Enum Sys records
        if self.axIdx[iRec] & 0xC000: break # Stop on first unmaped chunk
        iChunk = CrcIdx(iChunk) ^ self.axIdx[iRec]
        self.aiChunk.append(iChunk)
    return

  def getChunk(self, iRec, iChunk):
    chunk, crc = self.fmtChunk.unpack_from(self.data, self.oChunks + iRec * self.fmtChunk.size)
    assert crc == Crc16(chunk + struct.pack("<H", iChunk))
    return chunk

  def enumChunks(self):
    if self.bData:
      for iRec, bFree in enumerate(self.mFree): # Enum Data records
        if bFree: continue # Skip unmapped chunks
        iChunk = self.firstChunk + iRec # Calculate chunk number
        yield iChunk, self.getChunk(iRec, iChunk)
    else:
      for iRec, iChunk in enumerate(self.aiChunk): # Enum System records
        yield iChunk, self.getChunk(iRec, iChunk)

  def __str__(self):
    if self.bData: data = "".join((" " if free else "*") for free in self.mFree)
    else: data = " ".join("%04X" % x for x in self.aiChunk)
    sChunk = "%04X" % self.firstChunk if self.firstChunk else "----"
    return "%02X: USN=%04X erase=%4X iNext=%4X %s : %s" % (self.iPage, self.USN, self.nErase, self.iNextErase, sChunk, data)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class MFS_Cfg_Record(object):
  fmtRec = struct.Struct("<12sHHHHHHL")
  def __init__(self, data, iRec):
    self.name, unused, self.mode, self.opt, self.cb, self.uid, self.gid, self.offs = self.fmtRec.unpack_from(data, 4+iRec*self.fmtRec.size)
    assert 0 == unused
    self.name = self.name.rstrip('\0')

class MFS_Cfg_Storage(object):
  def __init__(self, data):
    self.data = data
    nRec, = struct.unpack_from("<L", data)
    self.aRec = [MFS_Cfg_Record(self.data, iRec) for iRec in xrange(nRec)]

  def dump(self, stg=None):
    msg = "nRec=%d(0x%X), cb=%d(0x%X)" % (len(self.aRec), len(self.aRec), len(self.data), len(self.data))
    rTxt = [msg]
    rLog = [msg]
    aPath = []
    for i,e in enumerate(self.aRec):
      rLog.append("%4X: m=%04X %04X cb=%04X uid=%04X gid=%04X o=%08X %s" % (i, e.mode, e.opt, e.cb, e.uid, e.gid, e.offs, e.name))
      if e.mode & 0x1000: # Dir
        if ".." == e.name: aPath.pop()
        else:
          aPath.append(e.name)
          path = posixpath.join(*aPath)
          if stg: stg.add(path)
          rTxt.append("%4X: %s %s uid=%04X gid=%04X               %s/" % (i, sCfgMode(e.mode), sCfgOpt(e.opt), e.uid, e.gid, path))
      else:
        path = posixpath.join(posixpath.join(*aPath), e.name)
        rTxt.append("%4X: %s %s uid=%04X gid=%04X @%06X[%4X] %s" % (i, sCfgMode(e.mode), sCfgOpt(e.opt), e.uid, e.gid, e.offs, e.cb, path))
        if stg: stg.add(path, self.data[e.offs:e.offs + e.cb])
    if stg:
      name = os.path.split(stg.baseDir)[1] or "storage"
      stg.add("%s.txt" % name, "\n".join(rTxt + [""]))
      stg.add("%s.log" % name, "\n".join(rLog + [""]))
    else:
      print "\n".join(rTxt)

#***************************************************************************
#***************************************************************************
#***************************************************************************

def packPage(iPage, data="", firstChunk=0):
  hdr = struct.pack("<LLLHH", 0xAA557887, iPage+1, 1, iPage+1, firstChunk)
  return (hdr + chr(CSum8(hdr)) + '\0' + data).ljust(MFS.PAGE_SIZE, '\xFF')

def packChunk(iChunk, chunk):
  chunk = chunk.ljust(64, '\0')
  crc = Crc16(chunk + struct.pack("<H", iChunk))
  return chunk + struct.pack("<H", crc)

#***************************************************************************
#***************************************************************************
#***************************************************************************

def MFSBtoMFS(mfsb):
  fmtHdr = struct.Struct("<4sL24s")
  fmtLen = struct.Struct(">L")
  sign, crc, FFs = fmtHdr.unpack_from(mfsb)
  assert "MFSB" == sign
  o = fmtHdr.size
  assert ~zlib.crc32(mfsb[o:], -1) & 0xFFFFFFFF == crc
  assert '\xFF'*len(FFs) == FFs
  oEnd = mfsb.find('\xFF'*10, o)
  r = []
  while True:
    o1324 = mfsb.find('\1\3\2\4', o, oEnd-8)
    if o1324 < 0: break
    r.append(mfsb[o:o1324])
    r.append('\xFF'*fmtLen.unpack_from(mfsb, o1324+4)[0])
    o = o1324+8
  r.append(mfsb[o:oEnd])
  cb = sum(len(v) for v in r)
  r.append('\xFF'*(-cb % 0x2000))
  return "".join(r)

class MFS(object):
  cbHdr = MFS_Page.fmtHdr.size # 18(0x12) bytes
  PAGE_SIZE = 0x2000 # Page size is 8K
  CHUNK_SIZE = 0x40 # Chunk size is 64(0x40) bytes
  nDataPageChunks = (PAGE_SIZE - cbHdr) / (1 + CHUNK_SIZE + 2) # 122(0x7A) chunks per Data page
  oDataChunks = cbHdr + nDataPageChunks # 140(0x8C)
  nSysPageChunks = (PAGE_SIZE - cbHdr - 2) / (2 + CHUNK_SIZE + 2) # 120(0x78) chunks per System page
  oSysChunks = cbHdr + 2*(nSysPageChunks + 1) # 260(0x104)
  fmtVolHdr = struct.Struct("<LLLH")

  def getFileData(self, iFile):
    iNode = self.aFAT[iFile]
    if 0x0000 == iNode: return None # No file
    if 0xFFFF == iNode: return "" # Empty file

    r = []
    while True:
      assert iNode >= self.nFiles
      chunk = self.dChunks[iNode - self.nFiles + self.nSysChunks]
      iNode = self.aFAT[iNode] # Get next node
      if iNode > 0 and iNode <= self.CHUNK_SIZE: break # Last chunk
      r.append(chunk)
    r.append(chunk[:iNode])
    return "".join(r)

  def enumFiles(self):
    for iFile in xrange(self.nFiles):
      if 0x0000 == self.aFAT[iFile]: continue
      yield iFile, self.getFileData(iFile)

  def __init__(self, ab):
    self.ab = ab
    self.cbPart = len(self.ab) # Find total size of MFS partition
    assert 0 == self.cbPart % self.PAGE_SIZE
    self.nPages = self.cbPart / self.PAGE_SIZE # Total number of pages
    self.nSysPages = self.nPages/12 # Number of System pages
    self.nDataPages = self.nPages - self.nSysPages - 1 # Number of Data pages
    self.nDataChunks = self.nDataPages * self.nDataPageChunks # Number of Data chunks
    self.cbData = self.nDataChunks * self.CHUNK_SIZE # Data area capacity

    self.aSysPages = []
    self.aDataPages = []
    for iPage in xrange(self.nPages): # Process all pages
      if 0 == struct.unpack_from("<L", self.ab, iPage*self.PAGE_SIZE)[0]: continue # Ignore to-be-erased page
      pg = MFS_Page(self.ab, iPage) # Load page
      (self.aDataPages if pg.bData else self.aSysPages).append(pg) # Add to specific list

    assert self.nSysPages == len(self.aSysPages)
    assert self.nDataPages == len(self.aDataPages)

    self.aSysPages.sort(key=lambda pg: pg.USN) # Sort System pages by USN
    self.aDataPages.sort(key=lambda pg: pg.firstChunk) # Sort Data pages by firstChunk

    self.nSysChunks = self.aDataPages[0].firstChunk
    self.dChunks = {}

    for pg in self.aSysPages: # Process all System pages
      for iChunk, chunk in pg.enumChunks(): # Enumerate all chunks in System page
        assert iChunk < self.nSysChunks
        self.dChunks[iChunk] = chunk

    for i, pg in enumerate(self.aDataPages): # Process all Data pages
      assert self.nSysChunks + i * self.nDataPageChunks == pg.firstChunk
      for iChunk, chunk in pg.enumChunks(): # Enumerate all chunks in Data page
        assert iChunk not in self.dChunks # No duplicats in Data chunks permitted
        self.dChunks[iChunk] = chunk

    self.sign, self.ver, self.cbTotal, self.nFiles = self.fmtVolHdr.unpack_from(self.dChunks[0]) # Volume header is in Chunk#0
    assert 0x724F6201 == self.sign # FileSystem signature
    assert 1 == self.ver # FileSystem version
    assert self.nSysChunks == (self.fmtVolHdr.size + 2*self.nDataChunks + 2*self.nFiles + self.CHUNK_SIZE - 1) / self.CHUNK_SIZE
    self.cbSys = self.nSysChunks * self.CHUNK_SIZE
    assert self.cbData + self.cbSys == self.cbTotal

    abSys = bytearray(self.cbSys)
    for iChunk in xrange(self.nSysChunks):
      if iChunk in self.dChunks: abSys[iChunk*self.CHUNK_SIZE:(iChunk+1)*self.CHUNK_SIZE] = bytearray(self.dChunks[iChunk])

    self.aFAT = struct.unpack_from("<%dH" % (self.nFiles + self.nDataChunks), abSys, self.fmtVolHdr.size)
    return

    print str(abSys[:self.fmtVolHdr.size]).encode("hex")
    for i, v in enumerate(self.aFAT):
      if i == self.nFiles: print
      if 0 == i % 16: print "\n%04X:" % i,
      print "%4X" % v,
    print

  def walkFolder(self, path, fileno, mode=VFS_integrity|VFS_nonIntel, salt=0):
    fld = MFS_Blob(self, fileno, mode, salt)
    fld.asFolder(path)

    self.r.append("%s/[%d]" % (path, len(fld.aE)))
    for i,e in enumerate(fld.aE):
      r = ["%3d: %-69s" % (i+1, e)]
      blob = MFS_Blob(self, e.fileno, e.mode, e.salt) if e.fileno else None
      r.append("<dir>" if e.mode & VFS_directory else "%5d" % len(blob.ab))
      if e.mode & VFS_integrity:
        r.append(" %s" % blob.sec) # Integrity enabled -- append Security info
      self.r.append("".join(r).rstrip())
    self.r.append("")

    for e in fld.aE:
      if e.name in (".", ".."): continue # Ignore self/parent references
      fn = posixpath.join(path, e.name)
      if e.mode & VFS_directory: # Directory
        self.stg.add(fn)
        self.walkFolder(fn, e.fileno, e.mode, e.salt)
      else:
        blob = MFS_Blob(self, e.fileno, e.mode, e.salt)
        if blob.sec:
          self.stg.add(fn + ".vfsSecurity", blob.sec.ab) # Security data
        if blob.sec and blob.sec.enc: # Encrypted
          self.stg.add(fn + ".vfsEncrypted", blob.ab)
        else: self.stg.add(fn, blob.ab)

  def dump(self, baseName=None):
    self.stg = zipStorage(baseName)
    self.stg.setBaseDir("chains")
    for iFile, data in self.enumFiles():
      self.stg.add("%03X.bin" % iFile, data)

    for iFile in (6, 7):
      dName = {6:"intel.cfg", 7:"fitc.cfg"}
      data = self.getFileData(iFile)
      if data:
        if False: # Extract intel.cfg / fit.cfg
          h = hashlib.sha256(data).digest()
          fnCfg = "%s_%s" % (h[:8].encode("hex"), dName[iFile])
          if not os.path.exists(fnCfg):
            with open(fnCfg, "wb") as fo: fo.write(data)
        self.stg.setBaseDir(dName[iFile])
        MFS_Cfg_Storage(data).dump(self.stg)

    if self.aFAT[8]:
      self.stg.setBaseDir("varFS")
      self.r = []
      self.walkFolder("home", 0x10000008)
      self.stg.add("varFS.log", "\n".join(self.r + [""]))
      del self.r

  def __str__(self):
    return "Size:%dK, nPages:%d, nSysPg:%d, nDataPg:%d, nDataChunks:%d, nSysChunks:%d, nFiles:%d/%d, cbData:%d, cbSys:%d, cbTotal:%d" % \
    (self.cbPart/1024, self.nPages, self.nSysPages, self.nDataPages, self.nDataChunks, self.nSysChunks, self.nFiles, (self.cbSys-14)/2 - self.nDataChunks, self.cbData, self.cbSys, self.cbTotal)

#***************************************************************************
#***************************************************************************
#***************************************************************************

def main(argv):
  if len(argv) <= 1:
    print "Usage: %s MFS.part {MFS.part}" % os.path.split(argv[0])[1]
    return

  for fn in argv[1:]:
    with open(fn, "rb") as fi: data = fi.read()

    if data.startswith("MFSB"):
      print ". Converting MFSB to MFS for %s" % fn
      data = MFSBtoMFS(data)

    mfs = MFS(data)
    print fn, mfs
    mfs.dump(fn)

if __name__=="__main__": main(sys.argv)
