# -*- coding: utf-8 -*-

"""
log things
"""

# ---------------------------------------------------------------------------
# global config var

# is save pai log to file
v_tmp_is_save_process_exit_log = False


# ---------------------------------------------------------------------------
# global self var

# api log printed strings
v_tmp_log_lines = []


# ---------------------------------------------------------------------------

def pt_log(line):
    """
        print lines, and add to global var

        !+ we add to glboal var, and save to disk when process exit(or other conditions), so that we can "view" records when we can't, like pc restart...
    """
    print line

    global v_tmp_log_lines
    v_tmp_log_lines.append(line)


def callback_process_exit_save_api_to_file(dbg):
    """
        save log to file
    """
    global v_tmp_is_save_process_exit_log
    if v_tmp_is_save_process_exit_log:
        try:
            file = open("api_log.txt", "w")
        except:
            print ">>> save api log file exception"
        else:
            global v_tmp_log_lines
            for line in v_tmp_log_lines:
                file.write(line + "\n")
            file.close()
            print ">>> save api log to file api_log.txt success"
