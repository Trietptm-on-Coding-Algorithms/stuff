# -*- coding: utf-8 -*-

import os
# import sys
import time
import win32con
import win32api
import shutil


# ---------------------------------------------------------------------------
# util
# ---------------------------------------------------------------------------


def __gua_file_exist(file_name):
    """
        create a new file, or replace old one
    """
    if not os.path.exists(file_name):
        f = open(file_name, "w")
        if f is not None:
            f.close()
            return True
        else:
            return False
    else:
        return True


def time_str():
    return time.strftime('%Y%m%d_%H_%M_%S', time.localtime(time.time()))


# ---------------------------------------------------------------------------
# iter files/dirs, to call cbk
# ---------------------------------------------------------------------------


def fuck_dirs(base_dir, cbk):
    """
        recur iter dirs, call cbk for each dir
    """
    files = os.listdir(base_dir)
    for f in files:
        f_pd = os.path.join(base_dir, f)
        if os.path.isdir(f_pd):
            fuck_dirs(f_pd, cbk)
            cbk(f_pd)


def fuck_files(base_dir, cbk):
    """
        recur iter files, call cbk for each file
    """
    files = os.listdir(base_dir)
    for f in files:
        f_pd = os.path.join(base_dir, f)
        if os.path.isdir(f_pd):
            fuck_files(f_pd, cbk)
        else:
            cbk(f_pd)


# ---------------------------------------------------------------------------
# dir cbks
# ---------------------------------------------------------------------------


def cbk_dir_print_name(dir_name):
    """
        print dir name
    """
    print dir_name


def cbk_dir_rename(dir_name, append_fix="_"):
    """
        rename dir untill it endswith append_fix
    """
    if not dir_name.endswith(append_fix):
        print "rename dir: %s" % dir_name
        os.rename(dir_name, dir_name + append_fix)
    else:
        print "ignore rename dir: %s" % dir_name


def cbk_dir_set_attr(dir_name, attr=win32con.FILE_ATTRIBUTE_NORMAL):
    """
        set dir attribute with win32api
    """
    print "set dir attr: " + dir_name
    win32api.SetFileAttributes(dir_name, attr)


# ---------------------------------------------------------------------------
# file cbks
# ---------------------------------------------------------------------------


def cbk_file_print_name(file):
    """
        print file name
    """
    print file


v_collected_files = []


def cbk_collect_file_list(file):
    """
        collect file to list
    """
    v_collected_files.append(file)


def cbk_file_rename(file, append_fix="_"):
    """
        rename file untill it endswith append_fix
    """
    if not file.endswith(append_fix):
        print "rename file: %s" % file
        os.rename(file, file + append_fix)
    else:
        print "ignore rename file: %s" % file


def cbk_file_set_attr(file, attr=win32con.FILE_ATTRIBUTE_NORMAL):
    """
        set file attribute with win32api
    """
    print "set file attr: " + file
    win32api.SetFileAttributes(file, attr)


def cbk_mv_to_new_dir_and_create_note_file(file):
    """
        move some file to new dir(with file base name), then create _NOTES.txt under that new dir
    """
    # filter some files, like txt files
    if file.endswith(".txt"):
        print "ignore process file: " + file
        return
    # decide new dir
    x = os.path.splitext(file)
    new_dir = ""
    if len(x) == 1:
        # no extension
        new_dir = file + "_"
    else:
        assert len(x) == 2
        new_dir = x[0]
    print "new dir for file: ", new_dir
    # create dir and move to new dir
    new_file = os.path.join(new_dir, os.path.basename(file))
    os.mkdir(new_dir)
    shutil.move(file, new_file)
    if len(x) == 1:
        os.rename(new_dir, file)
    print "file: %s, moved to: %s" % (file, new_file)
    # create new txt file
    new_txt = os.path.join(new_dir, "_NOTES.txt")
    __gua_file_exist(new_txt)
    print "creating txt file: " + new_txt


files_md5 = []
files_sha256 = []
file_md5s = []
file_sha256s = []


def cbk_theZoo_files_create_md5_sha256_files(file):
    """
        suck this
    """
    if file.endswith(".md5"):
        files_md5.append(file)
        f = open(file)
        if f is not None:
            for line in f.readlines():
                line = line.strip("\\")
                md5 = line.split(" ")[0].strip("\n")
                file_md5s.append(md5)
                # print "file " + file
                # print "MD5 " + md5
                new_file = os.path.join(os.path.dirname(file), "MD5 " + md5 + ".txt")
                if not __gua_file_exist(new_file):
                    print "create file fail: %s" % new_file
                else:
                    # print "create file: %s" % new_file
                    pass
        f.close()
    elif file.endswith(".sha256"):
        files_sha256.append(file)
        f = open(file)
        if f is not None:
            for line in f.readlines():
                line = line.strip("\\")
                sha256 = line.split(" ")[0].strip("\n")
                file_sha256s.append(sha256)
                # print "file " + file
                # print "SHA256 " + sha256
                new_file = os.path.join(os.path.dirname(file), "SHA256 " + sha256 + ".txt")
                if not __gua_file_exist(new_file):
                    print "create file fail: %s" % new_file
                else:
                    # print "create file: %s" % new_file
                    pass
        f.close()


# theZoo
"""
fuck_files(base_dir, cbk_theZoo_files_create_md5_sha256_files)
print "\n"
print "md5 files: %d" % len(files_md5)
print "file md5s: %d" % len(file_md5s)
print "sha256 files: %d" % len(files_sha256)
print "file sha256s: %d" % len(file_sha256s)
print "\n"
fuck_files(base_dir, cbk_collect_file_list)
new_file_list = os.path.join(base_dir, "file_list_" + time_str() + ".txt")
f = open(new_file_list, "w")
f.write("\n".join("%s" % file for file in v_collected_files))
f.close()
print "write file list to file: %s" % new_file_list
print "\n"
"""


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


if __name__ == '__main__':

    # sigmake.exe --> 1.err
    file_exc = open(r"D:\\SoftWare\\IDA Pro v6.8\\flair68\\flair68\\bin\\win\\1.exc")
    # excs: {"pat_1": 2, "pat_2": 5}
    excs = {}
    for line in file_exc.readlines():
        if not line.startswith(";"):
            exc = line.split(" ")[-1].strip("\n")
            if len(exc) == 64:
                if exc not in excs:
                    excs[exc] = 1
                else:
                    excs[exc] = excs[exc] + 1
    file_exc.close()
    print "read exc finish, exc cnt: %d" % len(excs)

    file_pat = open(r"D:\\SoftWare\\IDA Pro v6.8\\flair68\\flair68\\bin\\win\\1.pat")
    pats = []
    for line in file_pat.readlines():
        is_exist = False
        for (exc, cnt) in excs.items():
            if exc in line:
                if excs[exc] == 1:
                    print "line has pat, but is last one, take this as not exist. %s - %s" % (line, exc)
                else:
                    print "line has pat, but not last one, take this as already exist. %s - %s" % (line, exc)
                    excs[exc] = excs[exc] - 1
                    is_exist = True
                break
        if not is_exist:
            pats.append(line)
        else:
            print "not add line: %s" % line
    file_pat.close()
    print "filter pats finish"

    file_pat_ex = open(r"D:\\SoftWare\\IDA Pro v6.8\\flair68\\flair68\\bin\\win\\1.pat_ex", "w")
    file_pat_ex.write("".join("%s" % pat for pat in pats))
    file_pat_ex.close()
    print "write pats to new file finish"

    """
    if len(sys.argv) > 1:
        base_dir = sys.argv[1]
        if os.path.isdir(base_dir):
            print "input dir: " + base_dir
            # fuck_dirs(base_dir, cbk_dir_set_attr)
            # fuck_files(base_dir, cbk_file_rename)
            # fuck_files(base_dir, cbk_file_set_attr)
            # fuck_files(base_dir, cbk_mv_to_new_dir_and_create_note_file)

            print "finish"
        else:
            print "you should provide some valid dir, but not this one: " + base_dir
    else:
        print "please at least provide some string...."
    """
