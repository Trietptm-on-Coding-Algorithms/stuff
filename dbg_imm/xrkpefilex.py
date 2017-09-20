# -*- coding: utf-8 -*-
"""
    wrapper of pefile
"""

import pefile


class XPE(pefile.PE):
    # ---------------------------------------------------------------------------
    # wrapper of pefile.PE
    # ---------------------------------------------------------------------------
    def __init__(self, name):
        """
            @param: name : STRING : pe full path
        """
        pefile.PE.__init__(self, name)

    def get_export_table(self):
        """
            get parsed export table

            @return: obj : obj of ExportDirData
                     None
        """
        return hasattr(self, "DIRECTORY_ENTRY_EXPORT") and self.DIRECTORY_ENTRY_EXPORT or None

    def get_export_dict(self):
        """
            get parsed export table as dict

            @return: DICT: {export_name_1: export_addr_1, export_name_2: export_addr_2}
                     None
        """
        try:
            exports = self.get_export_table()
            if exports is not None and len(exports.symbols) != 0:
                ret = {}
                for export_item in exports.symbols:
                    ret[export_item.name] = export_item.address
                return ret
            return None
        except:
            return None

    def get_export_item_rva(self, export_name):
        """
            get export item rva by export name

            @param: INT
                    None
        """
        exports = self.get_export_table()
        if exports is not None:
            for export_item in exports.symbols:
                if export_item.name == export_name:
                    return export_item.address
        return None
