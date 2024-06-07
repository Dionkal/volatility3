import logging
import binascii
from typing import Dict, Generator, List, Optional, Tuple

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import conversion, format_hints
from volatility3.framework.symbols import intermed, symbol_table_is_64bit
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins.windows import poolscanner, info

vollog = logging.getLogger(__name__)


class Bitlocker(interfaces.plugins.PluginInterface):
    """Extract Bitlocker FVEK from a windows memory image"""
    
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)


    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="poolscanner", component=poolscanner.PoolScanner, version=(1, 0, 0)
            )
        ]
    
    def _generator(self):
        PoolSize = {
        'Fvec128' : 508,
        'Fvec256' : 1008,
        'Cngb128' : 632,
        'Cngb256' : 672,
        'None128': 1230,
        'None256': 1450
        }

        BLMode = {
        '00' : 'AES 128-bit with Diffuser',
        '01' : 'AES 256-bit with Diffuser',
        '02' : 'AES 128-bit',
        '03' : 'AES 256-bit',
        '10' : 'AES 128-bit (Win 8+)',
        '20' : 'AES 256-bit (Win 8+)',
        '30' : 'AES-XTS 128 bit (Win 10+)',
        '40' : 'AES-XTS 256 bit (Win 10+)'
       }

        kernel = self.context.modules[self.config["kernel"]]
        layer_name = kernel.layer_name
        symbol_table = kernel.symbol_table_name
        layer =  self.context.layers[kernel.layer_name]

        is_64bit = symbol_table_is_64bit(self.context, symbol_table)
        vers = info.Info.get_version_structure(self.context, layer_name, symbol_table)
        winver = (vers.MajorVersion, vers.MinorVersion)

        if winver >= (6, 4, 10241):
            tweak = "Not Applicable"
            constraints = [
                poolscanner.PoolConstraint(
                    b"None",
                    type_name="_POOL_HEADER",
                    page_type= poolscanner.PoolType.NONPAGED,
                    size  = (PoolSize['None128'], PoolSize['None256'])
                )
            ]

            fvek1OffsetRel = 0x8c
            fvek2OffsetRel = 0xd0
            fvek3OffsetRel = 0xb0

            for constraint, mem, header in poolscanner.PoolScanner.generate_pool_scan(
                self.context, layer_name, symbol_table, constraints
            ):
                
                f1 = layer.read(mem.vol.offset + fvek1OffsetRel, 64, True)
                f2 = layer.read(mem.vol.offset + fvek2OffsetRel, 64, True)
                f3 = layer.read(mem.vol.offset + fvek3OffsetRel, 64, True)

                if f1[0:16] == f2[0:16]: # AES-XTS
                    if f1[16:32] == f2[16:32]: 
                        # FIXME: decode() doesn't work directly
                        # Throws error: UnicodeDecodeError: 'ascii' codec can't decode byte 0xa4 in position 0: ordinal not in range(128) 
                        yield (0, (BLMode['40'], binascii.hexlify(bytearray(f1[0:32])).decode(), tweak))    #256-bit
                    else:
                        yield (0, (BLMode['30'], binascii.hexlify(bytearray(f1[0:16])).decode(), tweak))    #128-bit
                if f1[0:16] == f3[0:16]: # AES-CBC
                    if f1[16:32] == f3[16:32]: 
                        yield (0, (BLMode['20'], binascii.hexlify(bytearray(f1[0:32])).decode(), tweak ))   #256-bit
                    else:
                        yield (0, (BLMode['10'], binascii.hexlify(bytearray(f1[0:16])).decode(), tweak))    #128-bit

        ## TODO:Previous versions        
        if winver >= (6,2):
            tweak = "Not Applicable"
            constraints = [
                poolscanner.PoolConstraint(
                    b"Cngb",
                    type_name="_POOL_HEADER",
                    page_type= poolscanner.PoolType.NONPAGED,
                    size  = (PoolSize['Cngb128'], PoolSize['Cngb256'])
                )
            ]

            if is_64bit:
                modeOffsetRel = 0x68
                fvek1OffsetRel = 0x6C
                fvek2OffsetRel = 0x90
            else:
                modeOffsetRel = 0x5C
                fvek1OffsetRel = 0x4C
                fvek2OffsetRel = 0x9C


            for constraint, mem, header in poolscanner.PoolScanner.generate_pool_scan(
                self.context, layer_name, symbol_table, constraints
            ):
                f1 = layer.read(mem.vol.offset + fvek1OffsetRel, 64, True)
                f2 = layer.read(mem.vol.offset + fvek2OffsetRel, 64, True)

                if f1[0:16] == f2[0:16]:
                    if f1[16:32] == f2[16:32]:
                        yield (0, (BLMode['20'], binascii.hexlify(bytearray(f1[0:32])).decode(), tweak))
                    else:
                        yield(0, (BLMode['10'], binascii.hexlify(bytearray(f1[0:16])).decode(), tweak))
                
            

        if winver >= (6,0):
            #TODO: previous version
            pass


    def run(self) -> renderers.TreeGrid:
      
        return renderers.TreeGrid(
            [
                ("Cipher", str),
                ("FVEK", str),
                ("TWEAK Key", str)
            ],
            self._generator()
        )