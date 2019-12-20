#!/usr/bin/env python3

import struct
from enum import IntEnum
from pprint import pprint

# ----------------------------------------
# Subsection type
# ----------------------------------------

class SST(IntEnum):
    SST_MODULES   = 0x101
    SST_PUBLICS   = 0x102
    SST_TYPE      = 0x103
    SST_SYMBOLS   = 0x104
    SST_SRCLINES  = 0x105
    SST_LIBRARIES = 0x106
    SST_COMPACTED = 0x108
    SST_SRCLNSEG  = 0x109


# ----------------------------------------
# Subsection -- base class for all Codeview subsections
# ----------------------------------------

class Subsection(object):
    def __init__(self, sst, module, data):
        self.sst = sst
        self.module = module
        self.data = data

    def __repr__(self):
        return '<Subsection sst=%s(0x%X), module=%d, len(data)=%s>' % \
                (self.sst, self.sst, self.module, len(self.data))


# ----------------------------------------
# sstModules -- module definition
# ----------------------------------------

class sstModules(Subsection):
    def __init__(self, sst, module, data):
        super().__init__(sst, module, data)
        self.csBase, self.csOfs, self.csLen, self.ovl, self.libIndx, \
                self.nsegs, _, strlen = struct.unpack_from('<HHHHHBBB', data)
        self.string = data[-strlen:].decode('ascii')

    def __repr__(self):
        return '<sstModules cs(base=%d, ofs=%d, len=%d), ovl=%d, libIndx=%X, nsegs=%d, str=\'%s\'>' % \
                (self.csBase, self.csOfs, self.csLen, self.ovl, self.libIndx,
                        self.nsegs, self.string)


# ----------------------------------------
# sstPublics
# ----------------------------------------


class sstPublics(Subsection):
    def __init__(self, sst, module, data):
        super().__init__(sst, module, data)

        syms = []


        self.csBase, self.csOfs, self.csLen, self.ovl, self.libIndx, \
                self.nsegs, _, strlen = struct.unpack_from('<HHHHHBBB', data)
        self.string = data[-strlen:].decode('ascii')

    def __repr__(self):
        return '<sstModules cs(base=%d, ofs=%d, len=%d), ovl=%d, libIndx=%X, nsegs=%d, str=\'%s\'>' % \
                (self.csBase, self.csOfs, self.csLen, self.ovl, self.libIndx,
                        self.nsegs, self.string)


def findCodeview(fp):
    """
    Find Codeview pointer in the last 256 bytes of the EXE

    fp: file object open in binary mode

    returns -- (signature, start of CodeView data/dlfaBase, start of subsection directory)
    """

    # get filesize -- seek to EOF then 
    fp.seek(0, 2)
    szfile = fp.tell()

    for ofs in range(-8, -256, -1):
        fp.seek(ofs, 2)
        sig, dlfaBase = struct.unpack('<4sL', fp.read(8))
        if sig.startswith(b'NB0'):
            # calculate start of debug data
            dlfaBase = fp.tell()-dlfaBase

            # bounds check
            if dlfaBase < 0 or dlfaBase > szfile:
                continue

            # try to read the debug data and check the signature
            fp.seek(dlfaBase)
            nsig, lfoSubsecDir = struct.unpack('<4sL', fp.read(8))
            if nsig.startswith(b'NB0'):
                return (sig.decode('ascii'), dlfaBase, lfoSubsecDir+dlfaBase)

    # found nothing
    return None


def readSubsectionDirectory(fp, dlfaBase):
    """
    Read the CodeView subsection directory
    """
    # get number of subsections
    cdnt, = struct.unpack('<H', fp.read(2))

    subsecs = []
    print(cdnt)
    for i in range(cdnt):
        # read subsection headers
        sst, module, lfoStart, cb = struct.unpack('<HHLH', fp.read(10))

        # read subsection data
        pos = fp.tell()
        fp.seek(lfoStart + dlfaBase, 0)
        data = fp.read(cb)
        fp.seek(pos, 0)

        sst = SST(sst)

        # mash the subsection into one
        FACTORY = {
                SST.SST_MODULES: sstModules
                }
        if sst in FACTORY:
            subsecs.append(FACTORY[sst](sst, module, data))
        else:
            subsecs.append(Subsection(sst, module, data))

    return subsecs


with open('annexA.exe', 'rb') as fp:
    # read CodeView header
    x = findCodeview(fp)
    if x is None:
        raise IOError("File does not contain Codeview data")
    ver, dlfaBase, subsecBase = x

    # print CodeView header
    print("CodeView version '%s', with dlfaBase=0x%X and subsecBase=%08X" % \
            (ver, dlfaBase, subsecBase))

    # read the subsection directory
    fp.seek(subsecBase)
    pprint(readSubsectionDirectory(fp, dlfaBase))

