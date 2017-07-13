import os, sys, struct, zlib

class Error(Exception): pass

def cwDec(w): # Convert 16-bit value to string codeword
  return bin(0x10000 | w).rstrip('0')[3:-1]

def cwEnc(cw): # Convert string codeword to 16-bit value
  return int((cw+'1').ljust(16, '0'), 2)

#***************************************************************************
#***************************************************************************
#***************************************************************************

def HuffTabReader_bin(ab):
  fmtRec = struct.Struct("<HB")
  o = 0
  while o < len(ab):
    w, cb = fmtRec.unpack_from(ab, o)
    o += fmtRec.size
    v = ab[o:o+cb]
    assert len(v) == cb
    o += cb
    yield(cwDec(w), cb, v)

#***************************************************************************
#***************************************************************************
#***************************************************************************

class HuffNode(object):
  def __init__(self, cw, hd):
    self.cw = cw # String codeword value
    self.w = cwEnc(cw) # Encoded codeword value
    if hd:
      self.nBits = len(cw) # Length of codeword in bits
      self.cb = hd.dLen.get(cw, None)
      self.av = [d.get(cw, None) for d in hd.adTab]
    else:
      self.nBits = None # Actual length of codeword is unknown

#***************************************************************************
#***************************************************************************
#***************************************************************************

class HuffDecoder(object):
  NAMES = ("Code", "Data")
  DUMP_KNOWN = 0
  DUMP_LEN = 1
  DUMP_ALL = 2
  fmtInt = struct.Struct("<L")
  baseDir = os.path.split(__file__)[0]
  BLOCK_SIZE = 0x1000 # 4K bytes

  def __init__(self):
    with open(os.path.join(self.baseDir, "huff11.bin"), "rb") as fi: self.unpackTables(zlib.decompress(fi.read(), -15)) # Load from compressed version
    self.prepareMap()

  def loadTable(self, items):
    sv = set() # Set for values
    d = {}
    for cw, cb, v in items:
      if cw in d: raise Error("Codeword %s already defined" % cw)

      if cb is None: continue
      cbKnown = self.dLen.get(cw, None)
      if cbKnown is None: self.dLen[cw] = cb
      elif cb != cbKnown: raise Error("Codeword %s sequence length %d != know %d" % (cw, cb, cbKnown))

      if v is None: continue
      assert len(v) == cb
      d[cw] = v # Remember value
      if v in sv: raise Error("Value %s already present" % v.encode("hex"))
      sv.add(v)

    self.adTab.append(d)

  def unpackTables(self, ab):
    n, = self.fmtInt.unpack_from(ab)
    o = self.fmtInt.size
    self.dLen, self.adTab = {}, []
    for i in xrange(n):
      cb, = self.fmtInt.unpack_from(ab, o)
      o += self.fmtInt.size
      data = ab[o:o+cb]
      assert len(data) == cb
      o += cb
      self.loadTable(HuffTabReader_bin(data))

  def propagateMap(self, node):
    cw = node.cw
    for idx in xrange(int(cw[::-1], 2), len(self.aMap), 1<<len(cw)):
      assert self.aMap[idx] is None
      self.aMap[idx] = node

  def prepareMap(self):
    aCW = sorted(self.dLen.keys())[::-1]
    minBits, maxBits = len(aCW[0]), len(aCW[-1])
    self.aMap = [None]*(1<<maxBits) # 2**maxBits map
    aCW.append('0'*(maxBits+1)) # Longer than max
    nBits = minBits # Current length
    e = int(aCW[0], 2)|1 # End value for current length
    for o in xrange(1, len(aCW)):
      nextBits = len(aCW[o])
      if nextBits == nBits: continue # Run until length change
      assert nextBits > nBits # Length must increase
      s = int(aCW[o-1], 2) # Start value for current length
      for i in xrange(s, e+1):
        cw = bin(i)[2:].zfill(nBits)
        self.propagateMap(HuffNode(cw, self))
      e = int(aCW[o], 2)|1 # End value for next length
      for i in xrange(e/2 + 1, s): # Handle values with unknown codeword length
        cw = bin(i)[2:].zfill(nBits)
        self.propagateMap(HuffNode(cw, None))
      nBits = nextBits
    for v in self.aMap: assert v is not None

  def enumCW(self, ab):
    v = int(bin(int("01"+ab.encode("hex"), 16))[3:][::-1], 2) # Reversed bits
    cb = 0
    while cb < self.BLOCK_SIZE: # Block length
      node = self.aMap[v & 0x7FFF]
      if node.nBits is None: raise Error("Unknown codeword %s* length" % node.cw)
      yield node
      v >>= node.nBits
      if node.cb is not None: cb += node.cb

  def decompressChunk(self, ab, iTab):
    r = []
    cb = 0
    for node in self.enumCW(ab):
      v = node.av[iTab]
      if v is None: raise Error("Unknown sequence for codeword %s in table #%d" % (node.cw, iTab))
      r.append(v)
      cb += len(v)
      if cb >= self.BLOCK_SIZE: break
    return "".join(r)

  def decompress(self, ab, length):
    nChunks, left = divmod(length, self.BLOCK_SIZE)
    assert 0 == left
    aOfs = list(struct.unpack_from("<%dL" % nChunks, ab))
    aOpt = [0]*nChunks
    for i in xrange(nChunks):
      aOpt[i], aOfs[i] = divmod(aOfs[i], 0x40000000)

    base = nChunks*4
    aOfs.append(len(ab) - base)
    r = []
    for i, opt in enumerate(aOpt):
      iTab, bCompr = divmod(opt, 2)
      assert 1 == bCompr
      unpacked = self.decompressChunk(ab[base + aOfs[i]: base + aOfs[i+1]], iTab)
      assert len(unpacked) == self.BLOCK_SIZE
      r.append(unpacked)
    return "".join(r)

