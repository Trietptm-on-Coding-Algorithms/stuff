# -*- coding: utf-8 -*-

"""
  ny thing
"""

import os
import sys
import inspect
import traceback

try:
    # import xrkdef
    import xrklog
    import xrkgame
    import xrkutil
    # import xrkcloud
except:
    this_path = os.path.split(os.path.realpath(inspect.stack()[-1][1]))[0]
    sys.path.append(this_path)
    try:
        import xrklog
        # import xrkdef
        import xrkgame
        import xrkutil
        # import xrkcloud
    except Exception, e:
        import immlib as dbglib
        dbg = dbglib.Debugger()
        dbg.log("xrk ny cst import error: %s" % e, highlight=1)
        error = traceback.format_exc()
        while len(error) > 200:
            tmp = error[:200]
            dbg.log("  %s" % tmp, highlight=1)
            error = error[200:]
        dbg.log("  %s" % error, highlight=1)

        assert False


# -------------------------------------------------------------------------
# sdg definication
# -------------------------------------------------------------------------


def get_ny_sdg_list():
    ny_sdg_list = [xrkgame.sdg("base_player", "B9 x x x x E8 ? ? ? ? 8B 4C 24 04 F7 D8 1B C0 F7 D8 48 89 41 04 B0 01 C3"),
                   xrkgame.sdg("base_player_id", "83 EC 1C DD 05 x x x x 8A 4C 24 20 DD 5C 24 0A 6A 1B DD 44 24 28 8D 54 24 04 B8 66 03 00 00"),
                   xrkgame.sdg("base_player_name", "89 44 24 20 89 44 24 24 89 44 24 28 89 44 24 2C 89 44 24 30 A1 x x x x"),
                   xrkgame.sdg("base_player_hp", "DE C9 DC 5C 24 1C DF E0 F6 C4 41 A1 x x x x 75 ? 85 C0"),
                   # xrkgame.sdg("base_player_pos_x", "D9 5C 24 0C DB 44 24 18 D9 5C 24 10 DB 05 x x x x D9 5C 24 14 DB 05 ? ? ? ? D9 5C 24 18"),
                   xrkgame.sdg("base_player_around_xs", "0F B6 97 E0 00 00 00 DD 87 D8 00 00 00 83 EC 08 B9 x x x x DD 1C 24 52 E8 ? ? ? ? 89 44 24 20 85 C0 0F 84"),
                   xrkgame.sdg("base_bag_item_transfer", "50 6A FF 6A 66 51 52 B9 x x x x E8 ? ? ? ? 8D 4C 24 2C C6 84 24 C0 00 00 00 00"),
                   xrkgame.sdg("call_bag_item_trnasfer", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC D0 00 00 00 A1 ? ? ? ? 33 C4 89 84 24 CC 00 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 E4 00 00 00 64 A3 00 00 00 00 89 4C 24 14 8D"),
                   # xrkgame.sdg("ctor_auto_attack_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 14 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 28 64 A3 00 00 00 00 8B F1 89 74 24 1C E8"),
                   # xrkgame.sdg("ctor_login_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 18 03 00 00 A1 ? ? ? ? 33 C4 89 84 24 14 03 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 2C 03 00 00 64 A3 00 00 00 00 8B E9 89 6C 24"),
                   # 字符串 NpcQuestWnd x-ref的第1个
                   xrkgame.sdg("ctor_npc_talk_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC AC 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 A8 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 C0 01 00 00 64 A3 00 00 00 00 8B F1 89 74 24"),
                   # xrkgame.sdg("base_shop", "83 EC 08 56 8B 74 24 10 DD 86 00 01 00 00 57 DC 1D x x x x 8B F9 DF E0 F6 C4 44"),
                   xrkgame.sdg("base_left_click_obj", "50 B9 x x x x E8 ? ? ? ? 33 C0 5E C2 10 00 80 3D ? ? ? ? 00 74"),
                   xrkgame.sdg("call_left_click_obj", "83 EC 64 E8 ? ? ? ? 8B C8 E8 ? ? ? ? 85 C0 0F 85 ? ? ? ? 56 BE 05 00 00 00 39 35"),
                   xrkgame.sdg("base_skill_slot", "33 FF BB x x x x 85 ED 0F 85 ? ? ? ? FF 15 ? ? ? ? 33 C0 3B 70 10"),
                   xrkgame.sdg("call_skill_attack", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC D0 06 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D"),
                   # xrkgame.sdg("call_change_auto_attack_setting", "E8 ? ? ? ? B9 ? ? ? ? E9 ? ? ? ?"),
                   xrkgame.sdg("base_auto_attack_setting", "A1 x x x x 83 C4 10 25 FF 3F 00 00 6A 00 89 06 E8"),
                   # xrkgame.sdg("call_start_auto_attack", "A1 ? ? ? ? 83 EC 08 55 56 57 BF 01 00 00 00 57 8B F1 8B 0D ? ? ? ? 50 51 B9 ? ? ? ? E8 ? ? ? ? 84 C0 74 ? 83 EC 1C 8B CC 89 64"),
                   # xrkgame.sdg("call_stop_auto_attack", "51 53 56 8B F1 E8 ? ? ? ? D9 EE DC 15 ? ? ? ? 33 DB DF E0 F6 C4 44 7B ? B8 FF 00 00 00"),
                   xrkgame.sdg("base_win_handle_pointer", "A1 x x x x 8D 54 24 20 52 50 FF 15"),
                   # xrkgame.sdg("base_cur_map_id", "8B 91 EC 01 00 00 A1 x x x x"),
                   xrkgame.sdg("base_cur_win_big_map", "8B 8C 24 B4 00 00 00 8B 94 24 B0 00 00 00 51 52 B9 x x x x"),
                   xrkgame.sdg("call_route_same_map", "55 8B EC 83 E4 C0 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC E8 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 B0 01 00 00 53 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 F8 01 00 00 64 A3 00 00 00 00 8B F1 B9 ? ? ? ? E8 ? ? ? ? E8"),
                   xrkgame.sdg("base_route_diff_map", "8B 54 24 5C 53 52 8B 54 24 60 52 50 51 B9 x x x x"),
                   xrkgame.sdg("call_route_diff_map", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 40 A1 ? ? ? ? 33 C4 89 44 24 3C 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 54 64 A3 00 00 00 00 8B F1 E8 ? ? ? ? 80 B8 C0 00 00 00 00"),
                   # xrkgame.sdg("base_is_moving", "2B 8A 24 01 00 00 81 F9 2C 01 00 00 8B 0D x x x x 73 ? 39 8A 28 01 00 00"),
                   # 字符串 CSelServerWnd::GetCurrentThreadInfo x-ref上面第2个mov的操作地址
                   xrkgame.sdg("base_cur_line", "89 46 23 51 89 46 27 E8 ? ? ? ? 8B 3D x x x x 83 C4 0C 56 57 8B CB E8"),
                   xrkgame.sdg("base_is_in_safe_region", "83 3D x x x x 00 0F 85 ? ? ? ? 68 ? ? ? ? 68 ? ? ? ? 6A 06 6A 05 E8 ? ? ? ? D9 7C 24 38"),
                   xrkgame.sdg("call_use_normal_bag_item", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 50 A1 ? ? ? ? 33 C4 89 44 24 4C 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 64 64 A3 00 00 00 00 80 3D ? ? ? ? 00"),
                   xrkgame.sdg("base_s0x335_dA", "DD 05 x x x x 6A 12 8D 44 24 14 DD 5C 24 1E BA 35 03 00 00 50"),
                   # 字符串 QiandaoMain 所在函数
                   xrkgame.sdg("ctor_daily_sign_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 28 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 3C 64 A3 00 00 00 00 8B F1 89 74 24 18 E8 ? ? ? ? 8D BE 38 04 00 00 33 DB 8B CF 89 5C 24 44 E8"),
                   # 字符串 Qiaodao 第2个x-ref下面第2个CALL
                   xrkgame.sdg("call_daily_sign", "83 EC 14 8B 89 04 05 00 00 6A 13 8D 54 24 04 B8 92 02 00 00 89 4C 24 0F 52 B9"),
                   # 找到上面那个，就找到这个了
                   xrkgame.sdg("call_daily_sign_gift", "83 EC 14 8B 89 7C 04 00 00 6A 13 8D 54 24 04 B8 92 02 00 00 89 4C 24 0F 52 B9"),
                   xrkgame.sdg("call_change_pk_mode", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC C8 00 00 00 A1 ? ? ? ? 33 C4 89 84 24 C4 00 00 00 53 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 D8 00 00 00 64 A3 00 00 00 00 68 ? ? ? ? 8D 4C 24 30 FF 15"),
                   # 字符串 SelRole_SafetyMode_Note 所在函数
                   xrkgame.sdg("ctor_select_player_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 24 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 38 64 A3 00 00 00 00 8B F1 89 74 24 14 E8 ? ? ? ? 8D BE 3C 04 00 00 33 ED 8B CF 89 6C 24 40"),
                   # 字符串 CArkScrollBar 下边第2个虚表+0x19C
                   xrkgame.sdg("call_edit_ctrl_backspace", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 2C A1 ? ? ? ? 33 C4 89 44 24 28 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 40 64 A3 00 00 00 00 8B F1 80 BE"),
                   # 字符串 ArkEdit::DealAsciiChar 所在函数
                   xrkgame.sdg("call_edit_ctrl_input_char", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 28 A1 ? ? ? ? 33 C4 89 44 24 24 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 3C 64 A3 00 00 00 00 8B F1 80 BE"),
                   # xrkgame.sdg("base_game_send", "DD 46 10 B9 36 03 00 00 6A 16 DD 5C 24 2E 8D 54 24 20 66 89 4C 24 20 52 B9 x x x x C7 44 24 26 16 00 00 00"),
                   xrkgame.sdg("call_game_send", "83 EC 08 56 8B 74 24 10 0F B7 06 57 8B F9 B9 96 00 00 00 66 3B C1 74 ? 66 83 F8 65 74 ? BA A8"),
                   xrkgame.sdg("call_open_chengzhangshouce_win", "83 EC 0C 6A 0B 8D 4C 24 04 B8 BE 02 00 00 51 B9 ? ? ? ? 66 89 44 24 08 C7 44 24 0A 0B 00 00"),
                   xrkgame.sdg("base_all_item_types", "8D 4C 24 3C 51 8D 54 24 28 52 8D 4C 24 30 51 8D 54 24 38 52 50 B9 x x x x"),
                   xrkgame.sdg("base_all_item_types", "8D 4C 24 3C 51 8D 54 24 28 52 8D 4C 24 30 51 8D 54 24 38 52 50 B9 x x x x"),
                   xrkgame.sdg("ctor_accepted_miss_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 50 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 4C 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 64 01 00 00 64 A3 00 00 00 00 8B F1 89 74 24"),
                   xrkgame.sdg("base_all_mis_bag_items", "B9 x x x x E8 ? ? ? ? 8D 4C 24 14 8B D8 E8 ? ? ? ? 8B 50 04 8D 44 24 20"),
                   # 字符串MAIL_DONT_GET_ATTACHMENT的xref，上面第一个基址
                   # rkgame.sdg("base_all_normal_bag_items", "B9 x x x x E8 ? ? ? ? 8D AE B0 00 00 00 57 8B CD 8B D8 E8"),
                   xrkgame.sdg("base_all_cangku_items", "53 55 56 57 B9 x x x x E8 ? ? ? ? E8 ? ? ? ? 8B C8"),
                   xrkgame.sdg("call_get_shop_detail_by_id", "83 EC 5C A1 ? ? ? ? 33 C4 89 44 24 58 56 8B 74 24 70 85 F6 0F 84 ? ? ? ? D9 EE DC 16 DF"),
                   xrkgame.sdg("call_baitan_input_name", "55 8B EC 83 E4 C0 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC A8 00 00 00 A1 ? ? ? ? 33 C4 89 44 24 70 53 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 B8 00 00 00 64 A3 00 00 00 00 DD 45 14"),
                   # 字符串 #cffcc33 所在函数
                   xrkgame.sdg("call_show_info_middle_up", "55 8B EC 83 E4 C0 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC E8 00 00 00 A1 ? ? ? ? 33 C4 89 84 24 B0 00 00 00 53 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 F8 00 00 00 64 A3 00 00 00 00 8B 75 08 8B C6 8B D9 8D 50 01 8D 9B 00 00 00 00"),
                   xrkgame.sdg("call_show_tip_right_bottom", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 4C A1 ? ? ? ? 33 C4 89 44 24 48 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 60 64 A3 00 00 00 00 8B 7C 24 70 68 ? ? ? ? 8B F1 E8"),
                   # 函数 __func_later_mis_accept_finish_continue 任何一个x-ref上面第2个mov的操作数
                   xrkgame.sdg("base_s0x2AA_i12", "8B 01 8B 90 A8 00 00 00 6A 00 FF D2 8B 15 x x x x C6 05"),
                   xrkgame.sdg("base_is_all_win_closed", "59 5F 5E 5D 5B 83 C4 38 C3 83 3D x x x x 00 89 7C 24 18 89 74 24 14"),
                   xrkgame.sdg("call_iter_map_npcs", "8B 44 24 0C 85 C0 74 ? 3B 44 24 04 74 ? FF 15 ? ? ? ? 56 8B 74 24 14 57 8B 7C 24 10 8B CE 2B CF B8 E9 A2 8B 2E"),
                   xrkgame.sdg("call_mis_follow_unfollow", "83 EC 10 8B 4C 24 14 6A 0F 8D 54 24 04 B8 0A 02 00 00 89 4C 24 0F 52 B9 ? ? ? ? 66 89 44 24"),
                   xrkgame.sdg("call_make_team", "83 EC 10 B9 ? ? ? ? E8 ? ? ? ? 85 C0 75 ? B9 ? ? ? ? E8 ? ? ? ? 84 C0 74 ? 83 EC 1C 8B CC 89 64 24 1C 68 ? ? ? ? FF 15"),
                   xrkgame.sdg("call_leave_team", "83 EC 0C B9 ? ? ? ? E8 ? ? ? ? 84 C0 75 ? 32 C0 83 C4 0C C2 04 00 80 7C 24 10 00 75 ? B9 ? ? ? ? E8 ? ? ? ? 85 C0 75 ? 6A 0B"),
                   xrkgame.sdg("call_invite_into_team", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 3C A1 ? ? ? ? 33 C4 89 44 24 38 A1 ? ? ? ? 33 C4 50 8D 44 24 40 64 A3 00 00 00 00 B9"),
                   xrkgame.sdg("call_apply_into_team", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 3C A1 ? ? ? ? 33 C4 89 44 24 38 56 A1 ? ? ? ? 33 C4 50 8D 44 24 44 64 A3 00 00 00 00 8B F1 B9"),
                   xrkgame.sdg("base_team_member_cnt", "33 C0 83 3D x x x x 05 0F 94 C0 C3"),
                   xrkgame.sdg("base_team_member_details", "8B 38 8B 35 x x x x C7 44 24 44 00 00 00 00 89 7C 24 3C 89 74 24 38 8B 1D ? ? ? ? 85 F6 74"),
                   xrkgame.sdg("call_use_skill_with_pos", "55 8B EC 83 E4 C0 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 68 07 00 00 53 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 78 07 00 00 64 A3 00 00"),
                   # xrkgame.sdg("call_use_skill_no_pos_no_tar", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 60 53 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 70 64 A3 00 00 00 00 8B F1 8B 06 8B 90 C4 00 00 00 FF D2 85 C0 0F 85"),
                   xrkgame.sdg("call_show_validate_image", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 24 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 20 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 38 01 00 00 64 A3 00 00 00 00 8B 9C 24 48 01"),
                   # 字符串 #P5#P9 第2个x-ref
                   xrkgame.sdg("call_show_talk_msg", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 24 A1 ? ? ? ? 33 C4 89 44 24 20 53 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 34 64 A3 00 00 00 00 8B 7C 24 44 8B C7 8B D9 8D 50 01 8D 64 24 00"),
                   xrkgame.sdg("base_string_table", "83 EC 1C 8B C4 89 64 24 20 8D 4C 24 24 51 50 B9 x x x x C7 44 24 50 00 00 00 00"),
                   # 字符串#r#n#B%s %d的第2个x-ref，上面第1个基址
                   # xrkgame.sdg("base_richang_mis_progress", "55 56 83 C0 10 57 89 44 24 10 A1 x x x x 8B 28 8B 35 ? ? ? ? 8B FF 8B 3D ? ? ? ? 85 F6"),
                   xrkgame.sdg("call_appoint_as_team_leader", "55 8B EC 83 E4 C0 83 EC 34 53 56 8B D9 57 B9 ? ? ? ? E8 ? ? ? ? 84 C0 75 ? 32 C0 5F 5E"),
                   xrkgame.sdg("base_usual_setting_refuse_team", "33 C4 89 44 24 44 80 3D x x x x 00 56 8B 74 24 50 57 8B F9"),
                   xrkgame.sdg("call_kick_team_member", "83 EC 14 56 8B F1 B9 ? ? ? ? E8 ? ? ? ? 85 C0 75 ? B9 ? ? ? ? E8 ? ? ? ? 84 C0 74 ? DD 05 ? ? ? ? DD 44 24 1C DD E1 DF E0"),
                   xrkgame.sdg("call_change_team_pick_mode", "83 EC 0C 56 8B F1 B9 ? ? ? ? E8 ? ? ? ? 85 C0 74 ? 32 C0 5E 83 C4 0C C2 04 00 53 8B 5C 24 18 3B 5E 74 74"),
                   xrkgame.sdg("call_jiesan_team", "83 EC 0C B9 ? ? ? ? E8 ? ? ? ? 85 C0 74 ? 32 C0 83 C4 0C C3 B9"),
                   # 多个结果
                   # xrkgame.sdg("ctor_other_player_zb_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 51 56 A1 ? ? ? ? 33 C4 50 8D 44 24 0C 64 A3 00 00 00 00 8B F1 89 74 24 08 E8 ? ? ? ? 8D 8E 38"),
                   xrkgame.sdg("call_check_tar_player_zhuangbei", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 38 A1 ? ? ? ? 33 C4 89 44 24 34 53 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 48 64 A3 00 00 00 00 DD 44 24 58 8B F9 83 EC 08 B9"),
                   xrkgame.sdg("call_follow_player", "83 EC 08 8B 44 24 0C DD 00 53 83 EC 08 DD 54 24 0C B9 ? ? ? ? DD 1C 24 E8"),
                   # xrkgame.sdg("base_is_following_player", "39 7E 24 75 ? 89 6E 24 89 2D x x x x C7 05 ? ? ? ? FF 00 00 00"),
                   # 字符串：CFBClient_OPState::OnLButtonDown_Game x-ref上面第1个
                   xrkgame.sdg("base_followed_player_id", "D9 EE 83 EC 1C 8B CC DD 1D x x x x 89 64 24 54 68"),
                   xrkgame.sdg("call_beg_trade", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 58 A1 ? ? ? ? 33 C4 89 44 24 54 53 56 A1 ? ? ? ? 33 C4 50 8D 44 24 64 64 A3 00 00 00 00 8B 74 24 74 85 F6 0F 84"),
                   # 字符串 [交易]-CancelTrade x-ref下第1个mov操作数
                   # xrkgame.sdg("base_trade_accept_reject", "6A 06 6A 03 E8 ? ? ? ? 83 C4 0C B9 x x x x E8"),
                   # 字符串 OP_ITEM_TRADE_PLAYER 倒数第2个x-ref的下面第5个函数
                   # xrkgame.sdg("call_trade_accept_reject", "83 EC 1C 53 56 8B F1 33 DB 39 9E 50 6A 00 00 0F 86 ? ? ? ? 8B 86 50 6A 00 00 57 8B BE 4C 6A 00 00 03 C7 3B F8 76 ? FF 15 ? ? ? ? 8B 8E 34 6A 00 00 89 4C 24 0C 8D 4C 24 0C 89 7C 24 10 E8"),
                   xrkgame.sdg("call_trade_lock", "83 EC 0C 68 ? ? ? ? 6A 06 6A 03 E8 ? ? ? ? 83 C4 0C 6A 0B 8D 4C 24 04 B8 C9 02 00 00 51 B9 ? ? ? ? 66 89 44 24 08 C7 44 24 0A 0B 00 00 00 C6 44 24 12 01"),
                   xrkgame.sdg("all_trade_cancel", "83 EC 0C 68 ? ? ? ? 6A 06 6A 03 E8 ? ? ? ? 83 C4 0C 6A 0B 8D 4C 24 04 B8 C9 02 00 00 51 B9 ? ? ? ? 66 89 44 24 08 C7 44 24 0A 0B 00 00 00 C6 44 24 12 00"),
                   xrkgame.sdg("call_trade_confirm", "83 EC 0C 68 ? ? ? ? 6A 06 6A 03 E8 ? ? ? ? 83 C4 0C 6A 0B 8D 4C 24 04 B8 C9 02 00 00 51 B9 ? ? ? ? 66 89 44 24 08 C7 44 24 0A 0B 00 00 00 C6 44 24 12 02"),
                   # 字符串 TradeWnd 所在函数
                   xrkgame.sdg("ctor_trade_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 51 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 18 64 A3 00 00 00 00 8B F1 89 74 24 14 E8 ? ? ? ? C7 86"),
                   xrkgame.sdg("call_trade_add_item", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 7C A1 ? ? ? ? 33 C4 89 44 24 78 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 90 00 00 00 64 A3 00 00 00 00 8B BC 24 A0 00 00 00 8B E9 85 FF 0F 8C"),
                   xrkgame.sdg("ctor_input_edit_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 51 56 A1 ? ? ? ? 33 C4 50 8D 44 24 0C 64 A3 00 00 00 00 8B F1 89 74 24 08 E8 ? ? ? ? 68 2C 01 00 00 8B CE C7 44 24 18 00 00 00 00 C7 06"),
                   xrkgame.sdg("call_trade_add_silver", "83 EC 24 56 8B F1 E8 ? ? ? ? 8B C8 E8 ? ? ? ? D9 EE DC 5C 24 30 DF E0 F6 C4 05 0F 8A"),
                   # 字符串 PROTECT_POPO_OPEN_ERR x-ref上边第3个CALL
                   xrkgame.sdg("call_is_window_showing", "56 8B F1 8B 8E 00 03 00 00 85 C9 74 ? E8 ? ? ? ? 84 C0 75 ? 5E C3 8A 46 6D 5E C3"),
                   # 字符串 AM_Wnd 的第1个x-ref。因为这个x-ref比较多，所以可能不对
                   xrkgame.sdg("ctor_buy_item_from_npc_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 51 53 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 14 64 A3 00 00 00 00 8B F1 89 74 24 10 E8 ? ? ? ? C7 86 5C 04 00 00 ? ? ? ? 33 DB C7 06"),
                   # 用不用输入数量的都是这个call，不过用输入的调用结果是弹出输入数量对话框，而不是直接购买成功
                   # xrkgame.sdg("call_buy_item_from_npc_no_input_cnt", "55 8B EC 83 E4 C0 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC E8 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 B0 01 00 00 53 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 F8 01 00 00 64 A3 00 00 00 00 8B F9 68 ? ? ? ? 8D 4C 24 78 89 7C 24 30 FF"),
                   # 字符串 NPC_TRADE_BIND_CONFIRM x-ref上面第3个CALL
                   xrkgame.sdg("call_buy_item_from_npc_need_input_buy_cnt_direct", "83 EC 2C 53 8B 5C 24 34 56 57 8B 7C 24 40 8B F1 8B 86"),
                   xrkgame.sdg("call_npc_buy_or_sell_need_input_buy_or_sell_cnt", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 4C A1 ? ? ? ? 33 C4 89 44 24 48 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 60 64 A3 00 00 00 00 8B D9 E8 ? ? ? ? 8B C8 E8"),
                   xrkgame.sdg("call_sell_item_to_npc_no_input_cnt", "83 EC 20 53 8B 5C 24 2C 56 8B F1 85 DB 7D ? 53 68 ? ? ? ? 68 ? ? ? ? 6A 06 6A 04 E8 ? ? ? ? 83 C4 14 5E 5B 83 C4 20 C2 08 00 80 3D"),
                   xrkgame.sdg("base_all_maps_2", "8B 54 24 10 8D 44 24 0C 50 B9 x x x x 89 54 24 10 E8 ? ? ? ? 83 C0 08 BE 10 00 00 00 39 70 18 72 ? 8B 40 04 EB ? 83 C0 04"),
                   xrkgame.sdg("call_relative_screen_pos_to_internal_pos", "53 55 56 57 8B F9 D9 87 48 01 00 00 8D B7 48 01 00 00 E8 ? ? ? ? D9 87 4C 01 00 00 8B 6C 24 18 8B 5D 00 2B D8 E8"),
                   xrkgame.sdg("base_route_target_x_only_when_clicking_big_map", "8B 54 24 2C 8B 44 24 30 8D 4C 24 64 89 15 x x x x"),
                   xrkgame.sdg("base_route_target_y_only_when_clicking_big_map", "8B 4C 24 38 8B 44 24 34 89 0D x x x x"),
                   xrkgame.sdg("base_route_target_x_when_clicking_ground_or_mis_guide", "8B 44 24 14 8B 4C 24 18 A3 x x x x"),
                   xrkgame.sdg("base_cur_player_profession", "0F B6 05 x x x x C7 84 24 AC 00 00 00 00 00 00 00 8D 8C 24 84 00 00 00 3B D8 74"),
                   # xrkgame.sdg("base_cur_selected_obj_id", "D9 EE 56 DC 1D x x x x 8B F1 DF E0 F6 C4 44 7B ? 83 3D"),
                   xrkgame.sdg("base_around_items", "8B 28 A1 x x x x 32 DB 8B F0 88 5C 24 17 89 6C 24 1C 89 74 24 18"),
                   # 字符串 MapNameWnd x-ref下面第2个CALL
                   xrkgame.sdg("call_iter_win_ctrls", "53 56 8B B1 04 03 00 00 57 85 F6 74 ? 8B 7C 24 10 8B 1D"),
                   xrkgame.sdg("call_ctor_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC B8 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 B4 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 CC 01 00 00 64 A3 00 00 00 00 8B B4 24 E0 01"),
                   # xrkgame.sdg("base_is_player_on_zuoqi", "81 C7 C8 03 00 00 43 81 FF x x x x 7C ? 8B 16"),
                   # 字符串 QCWnd 所在函数
                   # xrkgame.sdg("ctor_zuoqi_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 44 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 58 64 A3 00 00 00 00 8B F1 89 74 24 14 E8 ? ? ? ? 33 DB 8D 8E A0 04 00 00 89 5C 24 60 C7 06"),
                   xrkgame.sdg("call_on_off_zuoqi", "55 8B EC 83 E4 C0 83 EC 7C A1 ? ? ? ? 33 C4 89 44 24 78 56 6A 14 8B F1 E8"),
                   xrkgame.sdg("ctor_handin_item_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 51 53 56 A1 ? ? ? ? 33 C4 50 8D 44 24 10 64 A3 00 00 00 00 8B F1 89 74 24 0C E8 ? ? ? ? 8B 4C 24 20 33 DB 53 53 53 C7 06"),
                   xrkgame.sdg("call_dispatch_msg", "55 8B EC 83 E4 F8 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC A4 00 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 B8 00 00 00 64 A3 00"),
                   xrkgame.sdg("base_all_jiyin_bag_items", "0F 94 C0 0F B6 C8 51 52 B9 x x x x E8 ? ? ? ? 0F B6 46 14 03 FB 3B F8"),
                   # 字符串 ShopListWndGai3 x-ref下第1个CALL
                   # xrkgame.sdg("ctor_shop_list_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 51 56 A1 ? ? ? ? 33 C4 50 8D 44 24 0C 64 A3 00 00 00 00 8B F1 89 74 24 08 E8 ? ? ? ? 8D 8E 64 04 00 00 C7 44 24 14 00 00 00 00 C7 06 ? ? ? ? C7 86 38 04 00 00"),
                   # 字符串 ShopMemberWnd 所在函数
                   xrkgame.sdg("ctor_shop_detail_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 38 53 56 A1 ? ? ? ? 33 C4 50 8D 44 24 44 64 A3 00 00 00 00 8B F1 89 74 24 0C E8 ? ? ? ? 33 DB 8D 8E"),
                   xrkgame.sdg("call_npc_talk", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC CC 08 00 00 A1 ? ? ? ? 33 C4 89 84 24 C8 08 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 E0 08 00 00 64 A3 00 00 00 00 8B F9 8B 07 8B"),
                   # 字符串 #cffccad66剩余时间：#n%d秒 上面第1个cmp的操作数
                   xrkgame.sdg("base_validate_remain_secs", "39 3D x x x x 74 ? 57 8D 4C 24 38 68"),
                   xrkgame.sdg("func_stack_npc_route_2", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 24 53 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 34 64 A3 00 00 00 00 8B F1 33 FF 89 7C 24 10 E8"),
                   xrkgame.sdg("func_translate_position_internal_to_show", "55 8B EC 83 EC 14 8B 45 0C 8B 08 8B 50 04 89 4D F8 89 55 FC DD 05 ? ? ? ? DC 35 ? ? ? ? D9 5D F4 8D 4D EC E8"),
                   xrkgame.sdg("func_log_1", "E8 ? ? ? ? 80 78 58 00 75 ? 33 C0 C3 8B 4C 24 0C 8B 54 24 08 8D 44 24 10 50 8B 44 24 08 51 52 50 E8"),
                   # 字符串：ProcessMsg %d begin 所在函数
                   # xrkgame.sdg("func_game_recv", "55 8B EC 83 E4 C0 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 34 B8 ? ? ? ? E8 ? ? ? ? A1 ? ? ? ? 33 C4"),
                   xrkgame.sdg("func_iter_player_around_xs", "8B 44 24 04 56 8B F1 83 F8 29 0F 87 ? ? ? ? 0F B6 80"),
                   xrkgame.sdg("func_fill_invite_into_team_sx25D", "DD 44 24 04 56 8B 74 24 10 DD 59 0A B8 5D 02 00 00 66 89 01 8B C6 57 C7 41 02 32 00 00 00 8D 79 12 8D 50 01 8A 08 40 84 C9 75"),
                   xrkgame.sdg("func_iter_team_members", "55 8B EC 83 E4 F8 83 EC 0C 53 8B D9 8B 43 18 8B 08 56 8B 33 57 89 4C 24 14 89 74 24 10 8D 49 00 8B 7B 18 8B 03 85 F6 74 ? 3B F0 74 ? FF 15 ? ? ? ? 39 7C 24 14 74 ? 85 F6 75 35 FF 15 ? ? ? ? 8B 54 24 14"),
                   xrkgame.sdg("func_fill_use_skill_sxB5", "8A 54 24 0C DD 44 24 04 B8 B5 00 00 00 DD 59 0A DD 44 24 10 66 89 01 8A 44 24 18 DD 59 13 88 51"),
                   xrkgame.sdg("func_x_obj_click", "55 8B EC 83 E4 C0 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 28 01 00 00 53 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 38 01 00 00 64 A3 00 00"),
                   # 字符串：FIGHT_POPO_SETSKILLNOMATCH x - ref的上面第2个call
                   xrkgame.sdg("func_iter_all_player_skills", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 20 A1 ? ? ? ? 33 C4 89 44 24 1C 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 34 64 A3 00 00 00 00 8B 6C 24 44 8B D9 33 F6 8D BB"),
                   xrkgame.sdg("func_fill_talk_msg_sx65", "8B 44 24 04 8B 54 24 08 55 56 8B F1 81 46 02 0C FE FF FF 89 46 0A 8B C2 57 C6 46 0E 00 8D 7E 23"),
                   xrkgame.sdg("func_iter_string_table", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 28 A1 ? ? ? ? 33 C4 89 44 24 24 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 38 64 A3 00 00 00 00 8D 71 04 8D 44 24 48 50 8D 4C 24 14 51 8B CE C7 44 24 48 00 00 00 00 E8 ? ? ? ? 8B 7C 24"),
                   xrkgame.sdg("func_iter_all_cangku_items", "83 EC 0C 8B 41 1C 53 55 8B 69 04 56 8B 30 57 89 4C 24 10 89 74 24 18 89 6C 24 14 EB ? 8D 49 00 8B 79 1C 8B 41 04 85 ED"),
                   # 字符串 PIC_STR_BABY_ARROW x-ref上面第2个CALL
                   xrkgame.sdg("func_iter_all_baitan_items", "83 EC 08 53 55 56 57 8D B1 0C 05 00 00 8D 44 24 1C 50 8D 4C 24 14 51 8B CE E8"),
                   # 字符串 CInfoWndMgr.cpp 第1个x-ref函数，内部调用了7次此函数
                   xrkgame.sdg("func_iter_all_accepted_mis", "83 EC 14 53 55 56 57 8B F9 8B 87 4C 05 00 00 8B 28 8B B7 34 05 00 00 89 6C 24 14 89 74 24 10 90 8B 9F 4C 05 00 00 8B 87 34 05 00 00 85 F6"),
                   # 字符串 PIC_MISSION_TYPE_ICON_EXPERIENCE x-ref上第10个CALL，这个函数内部F5顺着数下来第3个CALL
                   xrkgame.sdg("func_iter_all_accepted_mis_1", "83 EC 08 53 55 56 8B D9 57 8D 4C 24 20 C7 44 24 10 00 00 00 00 8B 44 24 20 51 8D 54 24 14 8D B3"),
                   xrkgame.sdg("func_fill_apply_into_team_sx25A", "DD 44 24 04 56 8B 74 24 10 DD 59 0A B8 5A 02 00 00 66 89 01 8B C6 57 C7 41 02 32 00 00 00 8D 79 12 8D 50 01 8A 08 40 84 C9 75"),
                   xrkgame.sdg("func_iter_maps", "83 EC 08 56 57 8D 44 24 18 50 8D 54 24 0C 52 83 C1 44 C7 44 24 10 00 00 00 00 E8"),
                   # 字符串 没有定义怪物装备 %f x-ref下面第5个CALL
                   xrkgame.sdg("func_recv_daily_sign_reply", "83 EC 08 56 57 6A 00 6A 00 6A 00 8B F1 6A 00 8D BE"),
                   # 字符串 PIC_STR_FACE_60_%d%d%d 所在函数
                   xrkgame.sdg("func_iter_team_members_1", "55 8B EC 83 E4 C0 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC E8 00 00 00 A1 ? ? ? ? 33 C4 89 84 24 B0 00 00 00 53 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 F8 00 00 00 64 A3 00 00 00 00 89 4C 24 38 33 F6 8D 4C 24 1C 89 74 24 50 E8"),
                   # 字符串 枪械师 x-ref的第1个
                   xrkgame.sdg("func_switch_profession_to_string", "51 56 C7 44 24 04 00 00 00 00 E8 ? ? ? ? 85 C0 75 ? 8B 74 24 0C 68 ? ? ? ? 8B CE FF 15 ? ? ? ? 8B C6 5E 59 C3 55 57 E8 ? ? ? ? 8B 6C 24 18 8B 35"),
                   xrkgame.sdg("func_recv_x2e5_be_team_invited", "83 EC 48 A1 ? ? ? ? 33 C4 89 44 24 44 80 3D ? ? ? ? 00 56 8B 74 24 50 57 8B F9 74 ? DD"),
                   xrkgame.sdg("func_usual_setting", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 1C 53 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 2C 64 A3 00 00 00 00 8B F1 8B 5C 24 3C 53 E8 ? ? ? ? 84 ? 0F 84 ? ? ? ? 56 E8 ? ? ? ? 56 E8 ? ? ? ? 83 C4 08 68"),
                   xrkgame.sdg("func_effect_setting", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 1C 53 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 2C 64 A3 00 00 00 00 8B F1 8B 5C 24 3C 53 E8 ? ? ? ? 84 DB 0F 84 ? ? ? ? 56 E8 ? ? ? ? 56 E8 ? ? ? ? 83 C4 08 6A 00 8B CE E8"),
                   # 字符串：从物品表中 x - ref上面的第1个。中文字符串先用010Editor转成HEX，再搜索
                   # xrkgame.sdg("func_iter_all_item_types", "83 EC 08 53 55 56 57 8D B1 64 04 00 00 8D 44 24 1C 50 8D 4C 24 14 51 8B CE E8 ? ? ? ? 8B 7C 24 10 8B 5E 18 8B 36 8B 2D"),
                   # 字符串 CSeeEquipWnd.cpp 第2个x-ref
                   # xrkgame.sdg("func_recv_new_item_of_player", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 3C 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 38 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 50 01 00 00 64 A3 00 00 00 00 8B BC 24 64 01"),
                   xrkgame.sdg("func_recv_trade_beg", "55 8B EC 83 E4 F8 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 68 A1 ? ? ? ? 33 C4 89 44 24 60 53 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 78 64 A3 00 00 00 00 80 3D"),
                   # 字符串：Protect_INFO_ItemLock_OP_Fail_Lock，x-ref上面的第3个CALL
                   # xrkgame.sdg("func_switch_to_choose_item_source", "8B 4C 24 08 85 C9 0F 8C ? ? ? ? 8B 44 24 04 83 C0 9C 83 F8 75 0F 87 ? ? ? ? 0F B6 80"),
                   # 字符串 MSG_OKCANCEL_SAIL_CARD 第1个x-ref
                   xrkgame.sdg("func_if_to_choose_tijiao_window", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC A0 00 00 00 A1 ? ? ? ? 33 C4 89 84 24 9C 00 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 B4 00 00 00 64 A3 00 00 00 00 8B F1 8B 86"),
                   # 字符串 CArkItemButton::UseItem[%d][%d] 所在函数
                   # xrkgame.sdg("func_use_item", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 48 A1 ? ? ? ? 33 C4 89 44 24 44 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 5C 64 A3 00 00 00 00 8B F1 8B 86"),
                   # xrkgame.sdg("func_trade_handler", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 88 00 00 00 A1 ? ? ? ? 33 C4 89 84 24 84 00 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 9C 00 00 00 64 A3 00 00 00 00 8B AC 24 AC 00"),
                   xrkgame.sdg("func_input_edit_handler", "55 8B EC 83 E4 C0 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC E8 00 00 00 A1 ? ? ? ? 33 C4 89 84 24 B0 00 00 00 53 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 F8 00 00 00 64 A3 00 00 00 00 8B 7D 08 68"),
                   xrkgame.sdg("func_recv_trade_party_confirmed_with_silver_rx2CA", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 44 A1 ? ? ? ? 33 C4 89 44 24 40 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 54 64 A3 00 00 00 00 DD 44 24 68 83 EC 08 DD 1C 24 8B F1 8D 54 24"),
                   xrkgame.sdg("func_iter_all_maps_2", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 0C 02 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 20 02 00 00 64 A3 00 00 00 00 8B F1 8B"),
                   xrkgame.sdg("func_move", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC A8 06 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 BC 06 00 00 64 A3 00 00 00 00 8B E9 33"),
                   xrkgame.sdg("func_fill_route_detail_0x96", "8B 44 24 20 D9 44 24 14 8B 54 24 04 56 8B F1 8B 4C 24 1C 50 51 83 EC 10 D9 5C 24 0C 8B CE D9 44"),
                   xrkgame.sdg("func_calc_path", "55 8B EC 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 78 01 00 00 56 A1 ? ? ? ? 33 C5 50 8D 45 F4 64 A3 00 00 00 00 89 8D 9C FE FF FF 8B"),
                   # 字符串 PickCB x-ref中的某一个
                   xrkgame.sdg("call_auto_attack_pickup_yaoji_setting_mm_to_ui", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 44 A1 ? ? ? ? 33 C4 89 44 24 40 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 58 64 A3 00 00 00 00 8B E9 33 DB 8D 4C 24 38 88 1D"),
                   # 字符串 percent = %d 所在函数
                   xrkgame.sdg("call_auto_attack_pickup_yaoji_setting_ui_to_mm", "83 EC 08 56 68 ? ? ? ? 8B F1 E8"),
                   xrkgame.sdg("func_skills_offset_to_player_base_offset", "33 C4 50 8D 44 24 34 64 A3 00 00 00 00 8B 6C 24 44 8B D9 33 F6 8D BB x x x x 8B CF E8"),
                   xrkgame.sdg("func_show_trade_party_info", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 94 00 00 00 A1 ? ? ? ? 33 C4 89 84 24 90 00 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 A8 00 00 00 64 A3 00 00 00 00 8B BC 24 B8 00 00 00 8B E9 57 8D 4C 24 38 FF 15"),
                   # xrkgame.sdg("func_iter_all_normal_bag_items", "33 C0 8D 91 D8 04 00 00 80 7C 01 28 00 74 ? 83 3A 00 74 ? 40 81 C2 C8 03 00 00 3D F5 00 00 00 72"),
                   # xrkgame.sdg("func_switch_color_value_to_color_str", "51 0F B6 41 28 56 C7 44 24 04 00 00 00 00 83 F8 03 77 ? FF 24 85 ? ? ? ? 8B 74 24 0C 68"),
                   # xrkgame.sdg("hex_func_shop_set_slot_in_page", "56 8B F1 81 7E 18 EA 00 00 00 75 ? 68 ? ? ? ? 68 ? ? ? ? 6A 00 6A 04 E8 ? ? ? ? 83 C4 10 32 C0 5E C2 08 00 8B 4C 24 08 85 C9 7C"),
                   xrkgame.sdg("func_check_item_type", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 20 A1 ? ? ? ? 33 C4 89 44 24 1C 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 2C 64 A3 00 00 00 00 8B 7C 24 3C 8B F1 57 B9"),
                   # xrkgame.sdg("func_recv_x250_handle_items", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC C8 07 00 00 A1 ? ? ? ? 33 C4 89 84 24 C4 07 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 DC 07 00 00 64 A3 00 00 00 00 8B 84 24 F8 07"),
                   xrkgame.sdg("func_trade_status_change", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 78 A1 ? ? ? ? 33 C4 89 44 24 74 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 84 00 00 00 64 A3 00 00 00 00 8B B4 24 94 00 00 00 8B 46 0A 50 68"),
                   xrkgame.sdg("func_trade_party_lock", "83 3D ? ? ? ? 10 A1 ? ? ? ? 56 8B F1 73 ? B8 ? ? ? ? 50 E8 ? ? ? ? 8B C8 E8"),
                   # xrkgame.sdg("func_x_trade_info", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 24 A1 ? ? ? ? 33 C4 89 44 24 20 A1 ? ? ? ? 33 C4 50 8D 44 24 28 64 A3 00 00 00 00 83 7C 24 4C 00 C7 44 24 30 00 00 00 00 74 ? 83 EC 1C 8D 44 24 54 8B CC 89 64 24 20 50 FF 15"),
                   xrkgame.sdg("func_trade_end", "56 57 68 ? ? ? ? 6A 06 6A 03 8B F1 E8 ? ? ? ? 83 C4 0C 33 FF 57 57 B9 ? ? ? ? E8"),
                   # xrkgame.sdg("func_trade_end_get_item_silver", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 08 04 00 00 A1 ? ? ? ? 33 C4 89 84 24 04 04 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 1C 04 00 00 64 A3 00 00 00 00 8D 4C 24 34 FF"),
                   xrkgame.sdg("func_trade_built", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 0C 64 A3 00 00 00 00 8B F9 8B 74 24 1C 0F B6 46 3F 0F B7 4E 12"),
                   xrkgame.sdg("func_fill_use_normal_item_s0x20D", "8B 54 24 0C DD 44 24 04 B8 0D 02 00 00 DD 59 0A 66 89 01 8B 44 24 10 89 51 12 8B 54 24 14 89 41"),
                   # 字符串 CCommerceInfo::SetItem pSI = NULL 第1个x-ref
                   xrkgame.sdg("func_process_recved_shop_items", "DD 44 24 04 83 EC 08 DD 1C 24 E8 ? ? ? ? 83 C4 08 85 C0 75 ? 68 ? ? ? ? 6A 06 6A 04 E8 ? ? ? ? 83 C4 0C C3 8B 4C 24 0C 83 F9 6F 7D"),
                   xrkgame.sdg("func_iter_all_shops", "D9 EE DC 5C 24 04 DF E0 F6 C4 44 7A ? 33 C0 C3 A1 ? ? ? ? 53 8B 1D ? ? ? ? 55 8B 28 56"),
                   # 可以查找字符串：CLoginWnd::EnterGame Step 000
                   xrkgame.sdg("call_login_1", "56 68 ? ? ? ? 6A 06 6A 02 8B F1 E8 ? ? ? ? A1 ? ? ? ? 83 C4 0C 83 3D ? ? ? ? 10 73 ? B8 ? ? ? ? 8B"),
                   # 字符串 CSelServerWnd.cpp 第1个x-ref
                   xrkgame.sdg("ctor_select_line_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 10 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 0C 01 00 00 53 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 20 01 00 00 64 A3 00 00 00 00 8B F1 89 74 24 14"),
                   # 字符串 MissionWnd 所在函数
                   xrkgame.sdg("ctor_main_mis_talk_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 04 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 00 01 00 00 53 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 14 01 00 00 64 A3 00 00 00 00 8B F1 89 74 24 48"),
                   # 字符串 #cffccad66剩余时间：#n%d秒 所在函数
                   xrkgame.sdg("func_update_validate_remain_secs", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 44 A1 ? ? ? ? 33 C4 89 44 24 40 53 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 54 64 A3 00 00 00 00 B8 01 00 00 00 33 DB 8B F1 84 05"),
                   # 字符串 角色返回消息错误：角色个数大于5 所在函数
                   xrkgame.sdg("func_recv_0x192_acnt_player_info", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 1C 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 30 64 A3 00 00 00 00 8B D9 80 BB"),
                   # 字符串 LOGIN_MSGBOX_CHANGE_THREAD_FULL 所在CALL的x-ref上面第2个CALL
                   xrkgame.sdg("func_recv_0x1A1_in_game_select_line", "B8 CC 12 00 00 E8"),
                   xrkgame.sdg("ctor_esc_context_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 51 53 56 A1 ? ? ? ? 33 C4 50 8D 44 24 10 64 A3 00 00 00 00 8B F1 89 74 24 0C E8 ? ? ? ? 33 DB 8D 8E 4C 04 00 00 89 5C 24 18 C7 06 ? ? ? ? FF 15"),
                   # 字符串 请稍 x-ref下面第5个CALL
                   xrkgame.sdg("call_back_to_role_select_or_login", "83 EC 0C 56 8B F1 E8 ? ? ? ? 6A 01 B9"),
                   # xrkgame.sdg("func_esc_btn_handlers", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 4C 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 48 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 60 01 00 00 64 A3 00 00 00 00 8B F9 8B 8C 24 70 01 00 00 33 DB 3B CB 0F 84"),
                   xrkgame.sdg("call_get_related_str", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 51 56 A1 ? ? ? ? 33 C4 50 8D 44 24 0C 64 A3 00 00 00 00 83 EC 1C 8D 44 24 38 8B CC 89 64 24 24 50 C7 44 24 34 00 00 00 00 FF 15"),
                   # 字符串 该场景中无法换线，请先离开该场景 x-ref上第4个CALL
                   xrkgame.sdg("call_show_msg_box", "8B 0D ? ? ? ? E8 ? ? ? ? 84 C0 74 ? 8B 0D ? ? ? ? 8B 01 8B 90 A8 00 00 00 6A 00 FF D2 8B 0D ? ? ? ? E8 ? ? ? ? 84 C0 74 ? 8B 0D ? ? ? ? 8B 01 8B 90 A8 00 00 00 6A 00 FF D2 8B 4C 24 04 85 C9"),
                   # 找到上面那个就找到这个了a3==1
                   xrkgame.sdg("call_show_msg_box_1", "8B 0D ? ? ? ? 83 EC 24 53 56 57 E8 ? ? ? ? 84 C0 74 ? 8B 0D ? ? ? ? 8B 01 8B 90"),
                   xrkgame.sdg("call_show_msg_box_2", "51 8B 0D ? ? ? ? 53 56 57 E8 ? ? ? ? 84 C0 74"),
                   # xrkgame.sdg("func_check_login_result", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 1C 03 00 00 A1 ? ? ? ? 33 C4 89 84 24 18 03 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 30 03 00 00 64 A3 00 00 00 00 8B AC 24 40 03 00 00 8B F9 85 ED 0F 84"),
                   xrkgame.sdg("call_cbk_input_then_click_okay", "8B 44 24 04 50 6A 03 E8 ? ? ? ? 83 C4 08 E8 ? ? ? ? 8B C8 E9"),
                   xrkgame.sdg("func_recv_0xDC_clear_shop_item_list", "53 55 56 57 68 E8 03 00 00 6A 00 6A 03 8B D9 E8 ? ? ? ? 8B 6C 24 20 DD 45 0C 8D 7D 0C 83 C4 04 DD 1C 24 E8 ? ? ? ? 8B F0 83 C4 08 85 F6"),
                   xrkgame.sdg("base_shop_list", "33 C0 C3 A1 x x x x 53 8B 1D ? ? ? ? 55 8B 28 56"),
                   xrkgame.sdg("func_recv_0xDB_shop_may_invalid", "8B 44 24 04 83 E8 0E 74 ? 83 E8 0F 74 ? 83 E8 02 74 ? 32 C0 C3 6A 01 68 ? ? ? ? E8 ? ? ? ? 8B C8 E8"),
                   # 字符串 CValidateMgr::CheckCodeNetMsg 所在函数
                   xrkgame.sdg("func_recv_385_pic_validate", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 18 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 28 64 A3 00 00 00 00 8B E9 83 7D 1C 00 74 ? E8"),
                   # xrkgame.sdg("call_answer_pic_validate", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 38 A1 ? ? ? ? 33 C4 89 44 24 34 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 44 64 A3 00 00 00 00 8B F1 8B 4C 24 54 E8 ? ? ? ? 50 8D 4C 24 28 FF 15 ? ? ? ? 81 7C 24 58 01 02 00 00 C7 44"),
                   xrkgame.sdg("base_game_svr_name", "33 C4 50 8D 44 24 50 64 A3 00 00 00 00 A1 ? ? ? ? BF 10 00 00 00 8B F1"),
                   xrkgame.sdg("base_silver", "DD 41 30 83 EC 10 DD 5C 24 08 DD 05 x x x x DD 1C 24 E8"),
                   xrkgame.sdg("base_silver_binded", "DD 05 x x x x 8D 54 24 28 52 8B F8 83 EC 08 8D 44 24 58 DD 1C 24 50 E8"),
                   # 字符串 BindGoldRich x-ref上第1个fld操作数
                   xrkgame.sdg("base_gold_binded", "DD 05 x x x x 83 EC 08 8D 4C 24 14 DD 1C 24 51 E8"),
                   xrkgame.sdg("func_get_host_info", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 38 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 44 64 A3 00 00 00 00 8B F1 68 ? ? ? ? 6A 00 6A 02 E8 ? ? ? ? 8D 44 24 18 50 E8"),
                   xrkgame.sdg("call_get_adapter_info", "81 EC E4 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 E0 01 00 00 53 55 56 8B B4 24 F4 01 00 00 33 DB 6A 6C 8D 44 24 1C 53 50 89 74 24 20 89 5C 24 1C"),
                   xrkgame.sdg("call_get_cpuid", "81 EC B4 04 00 00 A1 ? ? ? ? 33 C4 89 84 24 B0 04 00 00 53 56 8B B4 24 C0 04 00 00 57 C7 44 24 0C 00 00 00 00 B8 02 00 00 00 0F A2 33 DB 68 80 00 00 00 8D 44 24 3D 53 50 88 5C 24 44 E8"),
                   xrkgame.sdg("call_get_disk_info", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 44 05 00 00 A1 ? ? ? ? 33 C4 89 84 24 40 05 00 00 56 A1 ? ? ? ? 33 C4 50 8D 84 24 4C 05 00 00 64 A3 00 00 00 00 8B B4 24 5C 05 00 00 8D"),
                   # 字符串 ASS_SKILL_2 x-ref上面第1个CALL
                   # xrkgame.sdg("func_player_skill_info", "56 8B 74 24 08 85 F6 74 ? B9 ? ? ? ? E8 ? ? ? ? 8B CE 5E 85 C0 75 ? E9 ? ? ? ? E9 ? ? ? ? 5E C3"),
                   # 字符串 NEM_STALL_BUY x-ref下边的第4个CALL
                   xrkgame.sdg("func_skill_upgrade", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 5C 02 00 00 A1 ? ? ? ? 33 C4 89 84 24 58 02 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 70 02 00 00 64 A3 00 00 00 00 8B 84 24 80 02 00 00 48 C7 84 24 78 02 00 00 00 00 00 00 BE 01"),
                   # 字符串 #n#c%s%d#n  x-ref上面第2个
                   xrkgame.sdg("func_get_silver_value_level", "DD 05 ? ? ? ? 33 C9 DD 44 24 04 D8 D1 DF E0 DD D9 F6 C4 01 75"),
                   # xrkgame.sdg("func_skill_view_xx", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 68 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 64 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 7C 01 00 00 64 A3 00 00 00 00 8B AC 24 8C 01"),
                   # 字符串 CStormTrialLevel::SendMsg 所在函数。直接进入，不用打开窗口。这个只是进入，不是重返。
                   xrkgame.sdg("call_x_fengbao_enter", "83 EC 14 8B 4C 24 1C 8B 54 24 20 53 8A 5C 24 1C B8 1E 01 00 00 66 89 44 24 04 8D 44 24 04 6A 13 50 C7 44 24 0E 13 00 00 00 88 5C 24 16 89 4C 24"),
                   xrkgame.sdg("func_game_send_proxy", "8B 44 24 08 8B 4C 24 04 50 51 B9 ? ? ? ? E8 ? ? ? ? C3"),
                   # 字符串 CARRIERSTATE_CANNOTSETAUTOSKILL 所在函数
                   xrkgame.sdg("func_x_auto_attack", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 44 A1 ? ? ? ? 33 C4 89 44 24 40 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 58 64 A3 00 00 00 00 8B 54 24 70 8B 6C 24"),
                   xrkgame.sdg("func_later_mis_accept_finish_continue", "83 EC 28 A1 ? ? ? ? 33 C4 89 44 24 24 8B 44 24 30 8B 50 04 8B 40 0C 83 E8 00 B9 C3 03 00 00 66 89 0C 24 8B 4C 24 2C C7 44 24 02 21 00 00 00"),
                   # 字符串 #c(78)#u跳过电影#n#c(-1) 所在函数
                   xrkgame.sdg("ctor_later_main_mis_curtain_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 14 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 28 64 A3 00 00 00 00 8B F1 89 74 24 14 E8 ? ? ? ? 33 DB 8D 8E 7C 04 00 00 89 5C 24 30 C7 06"),
                   xrkgame.sdg("call_later_main_mis_curtain_win_show_or_hide", "53 8B 5C 24 08 33 C0 56 8B F1 88 9E"),
                   # 字符串 PopTip_TASK_%d 所处位置上面虚表的最后一个
                   xrkgame.sdg("func_npc_talk_win_xx", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC B8 00 00 00 A1 ? ? ? ? 33 C4 89 84 24 B4 00 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 CC 00 00 00 64 A3 00 00 00 00 8B 9C 24 DC 00"),
                   # 窗口的显示和隐藏函数，都在虚表的0xA4
                   xrkgame.sdg("call_show_hide_npc_talk_win", "83 EC 20 53 8B 5C 24 28 56 8B F1 84 DB 0F 84 ? ? ? ? 8D 44 24 08 50 E8 ? ? ? ? DD 05 ? ? ? ? 8B 4C 24 08 8B 54 24 0C 83 EC 18 8B C4 DD 5C 24 10 89 08 8B 4C 24 28 89 50 04 8B 54 24"),
                   # 字符串 登陆界面CLoginWnd::OnLoginCommon Step 0" x-ref上第3个CALL
                   # xrkgame.sdg("call_login_process_username_and_pwd", "83 EC 70 A1 ? ? ? ? 33 C4 89 44 24 6C D9 EE 53 8B 5C 24 7C 55 56 8B F1 8B 8C 24 80 00 00 00 DD 5E 0E 8B C1 57 C7 46 02 D2 04 00 00 C7 46 0A FF FF FF FF 8D BE A1 04 00 00 8D 68 01 8D 49 00"),
                   # 字符串 CArkScrollBar 下面第2张虚表+0xD0
                   # xrkgame.sdg("call_get_edit_ctrl_content", "8B 81 98 0D 00 00 85 C0 74 ? 83 78 18 10 72 ? 8B 40 04 C3 83 C0 04 C3 E9"),
                   # 字符串 CArkScrollBar 下面第2张虚表+0xD4
                   # xrkgame.sdg("call_set_edit_ctrl_content", "55 8B EC 83 E4 F8 83 EC 1C 53 56 8B D9 8B B3 98 0D 00 00 57 85 F6 75"),
                   xrkgame.sdg("func_login_basic_check", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 90 00 00 00 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 9C 00 00 00 64 A3 00 00 00 00 8B F1 A1 ? ? ? ? 50 E8"),
                   # 字符串 "%d.%d.%d.%d" 所在函数
                   xrkgame.sdg("func_x_game_version", "83 EC 10 55 56 33 C0 57 8B 7C 24 20 83 7F 18 10 89 44 24 0C 89 44 24 10 89 44 24 14 89 44 24 18 8D 77 04 72 ? 8B 06 EB ? 8B C6 8B 2D"),
                   # 字符串 登陆界面CLoginWnd::OnLoginCommon Step 0" 所在函数
                   # xrkgame.sdg("func_login_steps", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC D0 06 00 00 A1 ? ? ? ? 33 C4 89 84 24 CC 06 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 E4 06 00 00 64 A3 00 00 00 00 8B 9C 24 F4 06"),
                   # 字符串 输入的密保是 %s , 输够了位 x-ref上第2个CALL
                   xrkgame.sdg("call_send_what_is_asked_when_login", "83 EC 30 A1 ? ? ? ? 33 C4 89 44 24 2C 8A 4C 24 34 B8 F3 03 00 00 56 8B 74 24 3C 66 89 44 24 04 8B C6 C7 44 24 06 2B 00 00 00 88 4C 24 0E 8D 50 01 8A 08 40 84 C9 75"),
                   xrkgame.sdg("call_chat_press_enter", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 80 00 00 00 A1 ? ? ? ? 33 C4 89 44 24 7C 53 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 90 00 00 00 64 A3 00 00 00 00 68 ? ? ? ? 8B F1 E8 ? ? ? ? 8B F8 85 FF 0F 84 ? ? ? ? 8B 07 8B"),
                   # 字符串 ChatWnd 所在函数
                   # xrkgame.sdg("ctor_chat_input_edit_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 0C 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 20 64 A3 00 00 00 00 8B F1 89 74 24 18 E8 ? ? ? ? 8D BE"),
                   # 字符串 InputWnd::ShowCardError 所在函数
                   # xrkgame.sdg("func_login_error", "8B 44 24 04 80 78 0B 00 75 ? 0F B6 40 0C"),
                   # 字符串 SkillWnd 所在函数
                   xrkgame.sdg("ctor_skill_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 48 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 5C 64 A3 00 00 00 00 8B F1 89 74 24 20 E8"),
                   xrkgame.sdg("call_show_hide_skill_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 28 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 3C 64 A3 00 00 00 00 8B F1 80 7C 24 4C 00 0F 84 ? ? ? ? 6A 03 8D 44 24 24 68"),
                   # 字符串 EquipLevelUp 所在函数
                   xrkgame.sdg("ctor_zhandoujiqiao_win", "55 8B EC 83 E4 F8 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC C8 00 00 00 A1 ? ? ? ? 33 C4 89 84 24 C0 00 00 00 53 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 D8 00 00 00 64 A3 00 00 00 00 8B F1 89 74 24 58 E8"),
                   # 字符串 摆摊状态不能使用该功能 所在函数
                   # xrkgame.sdg("call_show_hide_zhandoujiqiao_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 40 A1 ? ? ? ? 33 C4 89 44 24 3C 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 4C 64 A3 00 00 00 00 80 7C 24 5C 00 8B F1 0F 84"),
                   # 字符串 SI_ToEndButton x-ref上面第2个CALL
                   xrkgame.sdg("func_get_ctrl_name_by_base", "83 79 48 10 72 ? 8B 41 34 C3 8D 41 34 C3"),
                   xrkgame.sdg("func_update_line_info", "55 8B EC 83 E4 F8 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 90 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 88 01 00 00 53 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 A0 01 00 00 64 A3 00 00 00 00"),
                   xrkgame.sdg("func_switch_line_state", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC AC 00 00 00 A1 ? ? ? ? 33 C4 89 84 24 A8 00 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 C0 00 00 00 64 A3 00 00 00 00 8B B4 24 D4 00 00 00 8B AC 24 D8 00 00 00 8B BC 24 DC 00 00 00"),
                   # 字符串 LOGIN_MSGBOX_SELECT_THREAD_MAINTAIN 第2个x-ref
                   xrkgame.sdg("call_go_to_selected_line", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 6C 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 68 01 00 00 56 A1"),
                   # 字符串 QuickEquip 第3个x-ref
                   xrkgame.sdg("ctor_huanzhuang_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 08 53 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 18 64 A3 00 00 00 00 8B F1 89 74 24 14 E8 ? ? ? ? 8D 44 24 13 50 8D 4C 24 17 8D BE"),
                   # xrkgame.sdg("call_huanzhuang_ok", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 94 00 00 00 A1 ? ? ? ? 33 C4 89 84 24 90 00 00 00 53 56 A1 ? ? ? ? 33 C4 50 8D 84 24 A0 00 00 00 64 A3 00 00 00 00 8B F1 E8"),
                   xrkgame.sdg("func_huanzhuang_close", "55 8B EC 83 E4 C0 83 EC 30 83 B9 58 04 00 00 00"),
                   xrkgame.sdg("base_auto_attack_pickup_and_yaoji_setting", "F6 05 x x x x 04 74 ? DD 46 0A 6A 13 8D 44 24 0C DD 5C 24 16 BA 5F 02 00 00 50 B9"),
                   # 字符串 #r#n#R(储存的经验已达上限)#r#n#Y(休 x-ref的上面第3个fld
                   xrkgame.sdg("base_jingyan_player_need", "8B 88 3C 04 00 00 DD 05 x x x x 83 F9 64 C7 80 40 04 00 00 64 00"),
                   # 字符串 #r#n#R(储存的经验已达上限)#r#n#Y(休 x-ref的上面第1个fcomp
                   xrkgame.sdg("base_jingyan_player_has", "DC 1D x x x x 83 EC 08 DF E0 DD 05"),
                   # 字符串 #r#n#R(储存的经验已达上限)#r#n#Y(休 x-ref的上面第1个fld
                   xrkgame.sdg("base_jingyan_player_max", "83 EC 08 DF E0 DD 05 x x x x DD 1C 24"),
                   # 字符串 技能等级不足5级，不能使用！ x-ref上面第3个CALL上面的第1个BASE
                   xrkgame.sdg("base_huoli_cur", "8B 4E 04 8B 16 53 55 8B 2D x x x x 51 52 E8 ? ? ? ? 8B C8 E8"),
                   # 取值__int16
                   xrkgame.sdg("base_player_level", "0F B7 8B DA 00 00 00 66 89 0D x x x x 8B 93 F4 00 00 00"),
                   # 字符串 InSideGame：登记线路和角色――%s %s %s x-ref下面第4个CALL下的第2个BASE
                   # xrkgame.sdg("base_player_fight", "8B 93 76 02 00 00 89 15 x x x x 8B 83 7A 02 00 00"),
                   xrkgame.sdg("call_level_up", "83 EC 10 81 7C 24 14 02 06 00 00 75 ? 83 7C 24 18 01 75 ? 6A 0F 8D 4C 24 04 B8 29 03 00 00 51 B9 ? ? ? ? 66 89 44 24 08 C7 44 24 0A 0F 00"),
                   # xrkgame.sdg("base_calc_pos_show_for_destroy_item", "89 35 x x x x 8B BB C0 03 00 00 8B CB E8 ? ? ? ? 0F B6 D0 0F B6 43 28 52 50 8B CF E8"),
                   xrkgame.sdg("func_destroy_item_no_input_cnt", "83 EC 08 81 7C 24 0C 02 06 00 00 75 ? 83 7C 24 10 01 75 ? 56 8B 35 ? ? ? ? 85 F6 74 ? 8D 44 24 04 50 8B CE E8"),
                   # 字符串 BabySkillReplaceWnd2 所处位置下1个CALL
                   xrkgame.sdg("func_destroy_item_need_input_cnt", "83 EC 0C 56 8B F1 E8 ? ? ? ? 8B C8 E8 ? ? ? ? E8"),
                   # 字符串 CStorgeWnd.cpp 前2个x-ref
                   xrkgame.sdg("ctor_cangku_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 48 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 44 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 5C 01 00 00 64 A3 00 00 00 00 8B E9 89 6C 24 34 E8"),
                   # xrkgame.sdg("func_cangku_win_show_hide", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 28 A1 ? ? ? ? 33 C4 89 44 24 24 53 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 38 64 A3 00 00 00 00 80 7C 24 48 00 8B F1 0F 84"),
                   # xrkgame.sdg("func_switch_to_get_item_container_source", "8B 4C 24 08 85 C9 0F 8C ? ? ? ? 8B 44 24 04 83 C0 9C 83 F8 75 0F 87"),
                   # 字符串 摆摊状态不能使用随身合成功能 第2个x-ref
                   # xrkgame.sdg("call_show_hide_hecheng_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 44 A1 ? ? ? ? 33 C4 89 44 24 40 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 54 64 A3 00 00 00 00 80 7C 24 64 00 8B F1 0F 84"),
                   # 字符串 ComposeMain 所在函数
                   # xrkgame.sdg("ctor_hecheng_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 38 53 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 48 64 A3 00 00 00 00 8B F1 89 74 24 10 E8 ? ? ? ? 33 DB 53 53 53 C7 06"),
                   # 字符串 NEM_STONE_COMPOSE x-ref的第3个
                   xrkgame.sdg("func_hecheng", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 2C 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 40 01 00 00 64 A3 00 00 00 00 8B F9 6A 12 E8"),
                   # 字符串 JiyinPY 所在位置下的第1个函数
                   xrkgame.sdg("func_silver_bag_to_cangku_or_cangku_to_bag", "55 8B EC 83 E4 C0 83 EC 34 53 56 57 8B F1 E8 ? ? ? ? 8B C8 E8 ? ? ? ? E8 ? ? ? ? DD 45 0C 8D 8E"),
                   xrkgame.sdg("func_show_hide_tab_map_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 60 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 5C 01 00 00 53 56 A1 ? ? ? ? 33 C4 50 8D 84 24 6C"),
                   # 字符串 MapWnd 所在函数
                   xrkgame.sdg("ctor_tab_map_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 10 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 0C 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 24 01 00 00 64 A3 00 00 00 00 8B F1 89 74 24 1C E8 ? ? ? ? 8D"),
                   # 积分面板的基址：字符串 @score( 下面第1个虚表 找到积分面板基址，就找到这个了
                   xrkgame.sdg("func_show_hide_jifen_panel", "83 EC 6C 53 8B 5C 24 74"),
                   # 字符串 CBackwardLotteryWnd::ShowEffect x-ref下边第2个CALL
                   xrkgame.sdg("func_lianbangjiasu_send_result", "83 EC 14 56 8B F1 83 BE FC 04 00 00 02 75"),
                   # 字符串 cl_pic_string_def.csv 下面第1个需表，是联邦加速的基址。或者用下面那个。 找msg_handler，顺着下去，就找到了
                   xrkgame.sdg("call_lianbangjiasu_start", "56 8B F1 83 BE 78 04 00 00 00 74 ? 68 ? ? ? ? E8 ? ? ? ? 8B 10 8B C8 8B 82"),
                   # 字符串 BackwardLotteryWnd 所在函数
                   xrkgame.sdg("ctor_lianbangjiasu_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 24 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 30 64 A3 00 00 00 00 8B F1 89 74 24 10 68 ? ? ? ? 8D 4C 24 18 FF 15"),
                   # 字符串 CE_STR_LUCKYCOMPASS_LIDU 所在函数
                   xrkgame.sdg("func_xingyunchoujiang_win_msg_handler", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 74 05 00 00 A1 ? ? ? ? 33 C4 89 84 24 70 05 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 88 05 00 00 64 A3 00 00 00 00 8B B4 24 98 05"),
                   # 字符串 CE_STR_LUCKYCOMPASS_LIDU 下第1个需表为幸运抽奖基址，需表+0x100处为state_detector
                   # 函数 _func_xingyunchoujiang_state_detector 内的send函数
                   xrkgame.sdg("func_send_xingyunchoujiang_result", "8B 54 24 04 81 EC 14 04 00 00"),
                   # 字符串 PIC_STR_LUCKY_ARROW 所在函数
                   xrkgame.sdg("ctor_xingyunchoujiang_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 9C 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 98 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 B0 01 00 00 64 A3 00 00 00 00 8B F1 89 74 24"),
                   # 字符串 CE_STR_LUCKYCOMPASS_BEGIN 所在函数
                   xrkgame.sdg("func_show_hide_xingyunchoujiang_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 2C 04 00 00 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 38 04 00 00 64 A3 00 00 00 00 8B F1 80 BC 24 48 04 00 00 00 0F 84"),
                   # 虚表+0x100处
                   xrkgame.sdg("func_xingyunchoujiang_state_detector", "83 EC 0C F6 05 ? ? ? ? 01 56 8B F1 75 ? 83 0D ? ? ? ? 01 C7 05 ? ? ? ? 00 00 00 00 56 B9 ? ? ? ? E8 ? ? ? ? DD 05"),
                   # 字符串 CE_STR_BACKWARD_LOTTERY x-ref上边第4个CALL
                   xrkgame.sdg("func_generate_lianbangjiasu_options", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 1C 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 30 64 A3 00 00 00 00 8B D9 33 F6 8D AB"),
                   xrkgame.sdg("func_show_hide_aoding_destroy_item_win", "53 8B 5C 24 08 56 53 8B F1 E8 ? ? ? ? 84 DB 74 ? 83 3D"),
                   xrkgame.sdg("func_aoding_destroy_items", "81 EC 0C 01 00 00 53 56 8B F1 57 B9 13 00 00 00 8D 44 24 2E 33 DB 89 58 F8 89 58 FC 89 18 83 C0 0C 83 E9 01 79 ? B8 F6 01 00 00 66 89 44 24 0C"),
                   # 字符串 EQUIP_REFORM_RULE_SILVER_CARD 所在函数
                   xrkgame.sdg("func_show_hide_gaizao_win", "53 8B 5C 24 08 56 53 8B F1 E8 ? ? ? ? 84 DB 75 ? E8 ? ? ? ? 8B 10"),
                   # 字符串 EquipRMKWnd2 x-ref下第1个CALL
                   xrkgame.sdg("ctor_gaizao_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 08 53 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 18 64 A3 00 00 00 00 8B F1 89 74 24 10 E8 ? ? ? ? 33 DB C7 06"),
                   # 字符串 m_byAddSuccessRateType[%d] 所在函数
                   xrkgame.sdg("func_gaizao", "81 EC 10 01 00 00 56 8B F1 E8"),
                   xrkgame.sdg("func_send_skill_upgrade", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 9C 02 00 00 A1 ? ? ? ? 33 C4 89 84 24 98 02 00 00 56 A1 ? ? ? ? 33 C4 50 8D 84 24 A4 02"),
                   # 字符串 pSkillLevel!=NULL 所在函数
                   xrkgame.sdg("func_get_max_learn_level_of_skill", "81 EC 04 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 00 01 00 00 8B 41 58 0F B7 48 1C 56 57 51 B9 ? ? ? ? E8 ? ? ? ? 8B F0 85 F6 75"),
                   # 显示的，从1开始算的
                   xrkgame.sdg("base_cur_player_level_show", "0F B7 05 x x x x 8B 4C 24 10 5F 5E 5D 5B 3B C8 77"),
                   # 字符串 技能数值不存在[id=%d,level=%d] 所在函数
                   xrkgame.sdg("func_get_player_level_needed_to_learn_next_level_skill", "81 EC 04 04 00 00 A1 ? ? ? ? 33 C4 89 84 24 00 04 00 00 56 57 8B BC 24 10 04 00 00 8B F1 0F B7 06 57 50 B9"),
                   # 下边儿这俩都是只是在显示skill界面时构造一次，然后鼠标放上去之后调用的是构造之后的，而不是再构造
                   # 字符串 #n#cffff0300#F?12需要角色等级达到%s级才能学习该技能#r" 所在函数
                   # xrkgame.sdg("func_construct_skill_most_view", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 48 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 44 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 5C 01 00 00 64 A3 00 00 00 00 8B B4 24 6C 01"),
                   # 字符串 #n#W#F?12(%d+%d) 所在函数
                   xrkgame.sdg("func_construct_skill_detail_view", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 08 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 04 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 1C 01 00 00 64 A3 00 00 00 00 8B 84 24 2C 01 00 00 8B B4 24 3C 01 00 00"),
                   # 字符串 CORPS_INFO_NORMAL_MAINTENANCE_CHAT 上面第1个CALL
                   xrkgame.sdg("func_format_show_silver_by_value", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 20 56 A1 ? ? ? ? 33 C4 50 8D 44 24 28 64 A3 00 00 00 00 DD 44 24 3C 83 EC 08 C7 44 24 10 00 00 00 00 DD 1C 24 E8"),
                   # 字符串 能升级失败 bSuc == FALSE dwTypeID = %d GetLevel = %d x-ref上面的第2个CALL
                   xrkgame.sdg("call_get_skill_upgrade_requirements", "53 55 8B E9 56 8B B5 88 00 00 00 57 3B B5 8C 00 00 00 76 ? FF 15 ? ? ? ? 8B 7D 7C 8D 49 00 8B 9D 8C 00 00 00 39 9D 88 00 00 00 76 ? FF 15"),
                   # 字符串 pSkillLevel!=NULL x-ref上面第1个CALL的base
                   xrkgame.sdg("base_skill_upgrate_requirements_array", "0F B7 48 1C 56 57 51 B9 x x x x E8 ? ? ? ? 8B F0 85 F6 75"),
                   xrkgame.sdg("call_show_hide_chengzhangshouce_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 28 A1 ? ? ? ? 33 C4 89 44 24 24 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 34 64 A3 00 00 00 00 80 7C 24 44 00 8B F1 0F 84 ? ? ? ? 6A 01 68"),
                   # 字符串 GrowthHandBookRecommendWnd 所在函数
                   xrkgame.sdg("ctor_chengzhangshouce_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 80 00 00 00 A1 ? ? ? ? 33 C4 89 44 24 7C 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 94 00 00 00 64 A3 00 00 00 00 8B F1 89 74 24 30 E8 ? ? ? ? 8D 44 24 1F 50 8D 54 24 23 33 FF 8D 8E"),
                   # 字符串 收到活动指引操作码%d 所在函数的第2个x-ref上边的第2个CALL
                   # xrkgame.sdg("func_recv_2BF_update_richang_mis_progresses", "83 EC 08 8B 44 24 0C 80 78 0A 00 C6 05"),
                   xrkgame.sdg("func_get_local_time", "81 EC E0 00 00 00 A1 ? ? ? ? 33 C4 89 84 24 DC 00 00 00 56 8B B4 24 E8 00 00 00 57 FF 15 ? ? ? ? 56 FF 15 ? ? ? ? 8B F0 B9 09 00 00"),
                   xrkgame.sdg("func_get_local_time_1", "83 7C 24 ? 00 74 0C 8D 44 24 04 50 E8 ? ? ? ? EB ? 8D 4C 24 04 51 FF 15"),
                   # 字符串 第%d天 x-ref的第2/3个
                   xrkgame.sdg("func_construct_daily_sign_everyday_gift_view", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 0C 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 20 64 A3 00 00 00 00 8B E9 33 FF 8D B5"),
                   # 字符串 签到%d次 所在函数
                   xrkgame.sdg("func_construct_daily_sign_cnt_tab_panels", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 3C A1 ? ? ? ? 33 C4 89 44 24 38 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 50 64 A3 00 00 00 00 8B D9 33 C0 8D BB"),
                   # 字符串 LinquEd 下第1个虚表，+0xA8偏移
                   xrkgame.sdg("func_show_hide_daily_sign_win", "83 EC 0C 53 8B 5C 24 14 56 53 8B F1 E8"),
                   # 字符串 SeeBabyAttr 下虚表+0xD4
                   xrkgame.sdg("func_construct_tab_panel_item", "56 57 8B F1 E8 ? ? ? ? 8B 8E 40 05 00 00 8B"),
                   xrkgame.sdg("func_recv_293_daily_sign", "51 53 55 56 57 6A 00 6A 00 6A 00 8B"),
                   # 字符串 第%d天 第2个x-ref下面第2个CALL
                   xrkgame.sdg("call_get_daily_sign_every_day_status", "8B 91 0C 05 00 00 8B 44 24 04"),
                   # 字符串 LinquEd x-ref的第1个
                   # xrkgame.sdg("func_construct_daily_sign_cnt_gift_details", "55 8B EC 83 E4 C0 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC E8 04 00 00 A1 ? ? ? ? 33 C4 89 84 24 B0 04 00 00 53 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 F8 04 00 00 64 A3 00 00 00 00 8B D9 8D 83"),
                   # 字符串 SeeBabyAttr 下虚表+0x94
                   xrkgame.sdg("func_enable_disable_ctrl", "83 B9 14 05 00 00 00 77 ? E9 ? ? ? ? C2 04 00"),
                   xrkgame.sdg("call_get_player_level_needed_to_learn_next_level_skill", "83 EC 08 53 55 56 57 8D 71 3C 8D 44 24 1C 50 8D 4C 24 14 51 8B CE E8 ? ? ? ? 8B 7C 24 10 8B 5E 18 8B 36 85 FF 74 ? 3B FE 74 ? 8B 35"),
                   xrkgame.sdg("call_get_max_learn_level_of_skill", "53 66 8B 5C 24 08 55 56 8B F1 8B 46 34 2B 46 30 57 C1 F8 02 33 FF 85 C0 76 ? 8B 2D ? ? ? ? 8B 4E 34 2B 4E 30 C1 F9 02 3B F9 72 ? FF"),
                   xrkgame.sdg("func_login_select_line", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 60 02 00 00 A1 ? ? ? ? 33 C4 89 84 24 5C 02 00 00 56 A1 ? ? ? ? 33 C4 50 8D 84 24 68 02 00 00 64 A3 00 00 00 00 8B F1 C6 05"),
                   # 字符串 Protect_Time_POP_Modify_Fail_1 所在函数
                   xrkgame.sdg("func_change_safe_time", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 54 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 50 01 00 00 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 60 01 00 00 64 A3 00 00 00 00 8B F1 8B 8E"),
                   # 字符串 Protect_Time_POP_Modify_Fail_1 上面第1个movzx指令的操作数
                   # 取BYTE
                   xrkgame.sdg("base_cur_safe_mins", "0F B6 05 x x x x 3B F8 0F 84"),
                   # 字符串 Protect_ItemLock_TipInfo_LockWait x-ref上面第1个CALL
                   xrkgame.sdg("func_format_time", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 70 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 84 00 00 00 64 A3 00 00 00 00 8B 84 24 98 00 00"),
                   # 字符串 #cff33ccff・优质 所在函数
                   xrkgame.sdg("func_switch_zb_color_to_str", "51 8B 44 24 0C 48 56 C7 44 24 04 00 00 00 00 83 F8 0B 0F 87"),
                   # 字符串 #n#r#L10#cff00ff00#Fc15<由%s制造>#n#P0#F?12 所在函数
                   # 这里有当前装备，可以xx
                   xrkgame.sdg("func_construct_item_float_view", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC C8 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 C4 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 DC 01 00 00 64 A3 00 00 00 00 8B AC 24 FC 01"),
                   # 字符串 #r#n%s耐久度 %s%d%s/%d 所在函数
                   # 搜2个，第1个
                   # xrkgame.sdg("func_construct_zhuangbei_naijiudu", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC C4 00 00 00 A1 ? ? ? ? 33 C4 89 84 24 C0 00 00 00 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 D4 00 00 00 64 A3 00 00 00 00 8B B4 24 E4 00 00 00 8B F9 8D 4C 24 2C FF 15 ? ? ? ? 8D 4C 24"),
                   # 字符串 Protect_ItemLock_TipInfo_LockWait 所在函数
                   xrkgame.sdg("func_construct_item_lock", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 5C A1 ? ? ? ? 33 C4 89 44 24 58 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 6C 64 A3 00 00 00 00 8B 7C 24 7C 8B AC 24 80 00 00 00 8B F1 8B 86"),
                   # 字符串 ient_Item::GetReclaimStarInfo 所在函数
                   xrkgame.sdg("func_construct_zhuangbei_gaizao", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 28 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 3C 64 A3 00 00 00 00 8B 74 24 4C 33 DB 89 5C 24"),
                   # 字符串 ContinueAttack 所在函数
                   xrkgame.sdg("func_send_start_auto_attack_packet", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 34 56 A1 ? ? ? ? 33 C4 50 8D 44 24 3C 64 A3 00 00 00 00 8B F1 6A 0B 8D 4C 24 18 B8 B8 00 00"),
                   # 字符串 ClearOpStatus 所在函数
                   # xrkgame.sdg("func_start_auto_attack", "51 D9 EE 56 8B F1 DD 56 28 33 C9 DD 9E B8 00 00 00 B8 FF 00 00 00 89 4E 24 89 8E FC 00 00 00 51 B9"),
                   # 搜两个，第2个貌似是战场的复活什么什么
                   # 字符串 回城 x-ref下面第7个CALL
                   # xrkgame.sdg("func_huicheng_fuhuo", "83 EC 10 DD 05 ? ? ? ? 56 D9 7C 24 06 8B F1 0F B7 44 24 06 0D 00 0C 00 00 89 44 24 08 B9 2A 03 00 00 D9 6C 24 08 6A 0C 8D 54 24 0C 52 C7 05"),
                   # 字符串 回城后，高级抗辐射剂的效果将消失，确定回城吗？（当前原地复活需要消耗%d军 所在函数
                   # 可以看复活是需要军饷还是银币
                   # xrkgame.sdg("func_huicheng_fuhuo_1", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 5C A1 ? ? ? ? 33 C4 89 44 24 58 53 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 6C 64 A3 00 00 00 00 8B 35"),
                   # 字符串 Resurrection 的第3个x-ref
                   # xrkgame.sdg("func_show_hide_fuhuo_context_win", "83 EC 10 53 8B 5C 24 18 56 8B F1 84 DB 0F 84 ? ? ? ? 55 57 68"),
                   # 字符串 DeadWnd x-ref的第1个
                   xrkgame.sdg("ctor_fuhuo_context_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 51 53 56 A1 ? ? ? ? 33 C4 50 8D 44 24 10 64 A3 00 00 00 00 8B F1 89 74 24 0C E8 ? ? ? ? D9 EE 33 DB DD 9E 38 04 00 00"),
                   # 字符串 FIGHT_POPO_RELIVE_TIMELIMT 所在函数
                   xrkgame.sdg("func_yuandi_fuhuo", "83 EC 10 A1 ? ? ? ? 53 32 DB 56 8B F1 89 44 24 08 85 C0 7D ? 83 EC 1C 8B CC 89 64 24 24 68"),
                   # 中间大黄提示：无法原地复活，金钱携带不足
                   # 复活后不会清空
                   # 字符串 FIGHT_RELIVE_COST_RAID_PAY_WNDTEXT 上面第1个cmp指令的操作数
                   xrkgame.sdg("base_silver_needed_to_yuandifuhuo", "3B 05 x x x x 7C ? 56 83 EC 1C 8B CC 89 64 24 28 68"),
                   # 字符串 ContinueChallengeBtn x-ref的第3/4个。函数不一样，但效果是相同的。同样，下面的HEX也能搜两个
                   # xrkgame.sdg("func_fengbao_continue_or_leave", "83 EC 14 56 8B F1 8A 4C 24 1C 6A 13 8D 54 24 08 B8 1E 01 00 00 88 4C 24 12 52 B9 ? ? ? ? 66 89 44 24 0C C7 44 24 0E 13 00 00 00 C7 44 24 17 00 00 00 00 C7 44 24 1B 00 00 00 00 E8"),
                   # 字符串 PIC_STR_CHANNEL_BUTTON_%d 所在函数
                   xrkgame.sdg("func_chat_x", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 94 00 00 00 A1 ? ? ? ? 33 C4 89 84 24 90 00 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 A8 00 00 00 64 A3 00 00 00 00 80 BC"),
                   # 字符串 RumorsChatButton 所在函数
                   xrkgame.sdg("func_chat_channel_btn_names", "56 8B F1 8B 4C 24 08 85 C9 0F 84"),
                   # 字符串 Tex_%d 的x-ref占了10个
                   xrkgame.sdg("func_chat_channel_txts", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 20 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 1C 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 34 01 00 00 64 A3 00 00 00 00 68"),
                   # 字符串 //c 所在函数
                   xrkgame.sdg("func_chat_channel_slashes", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 7C A1 ? ? ? ? 33 C4 89 44 24 78 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 90 00 00 00 64 A3 00 00 00 00 8B B4 24 A0 00 00 00 8B 84 24 C0"),
                   # 字符串 >> 椭圆轨迹线【%s】 下边第2个虚表，是创建角色界面
                   xrkgame.sdg("ctor_create_player_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 51 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 18 64 A3 00 00 00 00 8B F1 89 74 24 14 C7 06 ? ? ? ? C7 86 38 04 00 00 ? ? ? ? C7 44 24 20 08"),
                   # 字符串 STR_CAN_NOT_CREATE_LMR 所在函数
                   xrkgame.sdg("func_create_player", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 90 00 00 00 A1 ? ? ? ? 33 C4 89 84 24 8C 00 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 A4 00 00 00 64 A3 00 00 00 00 33 DB"),
                   xrkgame.sdg("func_show_hide_create_player_win", "83 EC 24 53 8B 5C 24 2C 55 56 57 53 8B E9 E8"),
                   xrkgame.sdg("func_fill_0x193_create_player", "8A 44 24 04 8A 54 24 08 88 41 0A 8A 44 24 0C 88 41"),
                   # 字符串 SkillMenuWnd 下第1张虚表+0x180
                   xrkgame.sdg("func_change_auto_attack_setting", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 20 A1 ? ? ? ? 33 C4 89 44 24 1C 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 2C 64 A3 00 00 00 00 8B F9 8B 4C 24 3C E8 ? ? ? ? 50 8D 4C 24 10 FF 15 ? ? ? ? 81 7C 24 40 01 02 00 00 C7 44 24 34 00 00 00 00 0F 85 ? ? ? ? 83 7C 24 24"),
                   # 字符串 percent = %d x-ref上第4个mov的操作数
                   xrkgame.sdg("base_auto_attack_setting_hp_mp_recover", "0F B6 C0 8D 0C 80 D9 6C 24 0A 89 0D x x x x 8B CE E8"),
                   xrkgame.sdg("func_chat_final_send", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 5C 02 00 00 A1 ? ? ? ? 33 C4 89 84 24 58 02 00 00 56 A1"),
                   # 字符串 微端换地图不能连点 m_CurrOperator.eClickStatus = [%d] 所在函数
                   xrkgame.sdg("func_on_left_button_down_game", "55 8B EC 83 E4 C0 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC E8 00 00 00 53 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 F8 00 00 00 64 A3 00 00 00 00 8B F1 B9"),
                   # xrkgame.sdg("func_left_button_click_mon_attack_or_npc_route", "83 EC 18 56 8B F1 E8 ? ? ? ? 8B C8 E8 ? ? ? ? 85 C0 75"),
                   # 字符串 FIGHT_POPO_NOWEAPON 的第2个x-ref
                   xrkgame.sdg("call_get_left_button_skill", "83 EC 08 53 56 57 8B F9 E8 ? ? ? ? 84 C0 74"),
                   # 字符串 CE_STR_SKILL_DIANYAN 所在函数
                   # code == 1: select object
                   xrkgame.sdg("func_switch_click_pic_effects", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 9C 08 00 00 A1"),
                   # 字符串 CFBClient_Hero::LAttackAnimal 所在函数
                   xrkgame.sdg("call_left_x_mon_with_left_button_skill", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC B8 06 00 00 53 55 56 57 A1"),
                   # 字符串 OperatorStatus::e_RClickPos 所在函数
                   # xrkgame.sdg("func_on_left_button_attack", "55 8B EC 83 E4 C0 83 EC 30 53 55 56 8B F1 57 B9"),
                   # 字符串 GS报错使用技能失败 srcId = %f destId =  x-ref下第1个mov的操作数
                   # xrkgame.sdg("base_player_state", "DC 5B 0A DF E0 F6 C4 44 0F 8A ? ? ? ? A1 x x x x"),
                   # 在函数 _on_left_button_down_game 中switch上面那两个连续的函数
                   xrkgame.sdg("call_update_player_state", "53 55 56 57 6A 00 8B F9 6A 00 B9"),
                   # 函数left_button_click_mon_attack_or_npc_route 中case1/3的第1个函数
                   xrkgame.sdg("call_before_attack", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC F8 00 00 00 A1 ? ? ? ? 33 C4 89 84 24 F4 00 00 00 53 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 08 01 00 00 64 A3 00 00 00 00 8B 84 24 18 01 00"),
                   # 字符串 pLeftSkill!=NULL x-ref上第3个mov的操作数
                   xrkgame.sdg("base_left_btn_skill_id", "8B 06 83 C2 10 83 C6 04 81 FA x x x x"),
                   # 函数 func_change_auto_attack_setting 的case1/2的函数
                   xrkgame.sdg("call_set_left_right_btn_skill_id", "80 7C 24 08 00 56 8B F1 74 ? 8B 44 24 08 89 86"),
                   # 字符串 BuyMaterialBtn x-ref下第6个CALL
                   xrkgame.sdg("func_send_item_tijiao_0x1F6", "81 EC 0C 01 00 00 53 56 57 8B F9 B9 13 00 00 00"),
                   # 字符串 CFBClient_OPState::OnRButtonDown_Game 第2个x-ref
                   xrkgame.sdg("func_on_right_btn_down_game", "83 EC 30 53 55 56 8B F1 57 B9 ? ? ? ? E8 ? ? ? ? 84 C0 0F 84 ? ? ? ? E8"),
                   # 字符串 CFBClient_OPState::OnRButtonDown_Game 第1个x-ref下面第7个CALL
                   # xrkgame.sdg("call_right_click_obj", "53 55 56 8B F1 8A 46 20 88 86 80 00 00 00 8B 4E"),
                   # 字符串 你确定要 x-ref下第7个push的操作数
                   xrkgame.sdg("call_send_0x217_quanbu_xiuli", "83 EC 0C 81 7C 24 10 02 06 00 00 75 ? 83 7C 24 14 01 75 ? 6A 0C 8D 4C 24 04 B8 17 02 00 00"),
                   # 字符串 ValidateWnd 下第1个虚表0x180处
                   # x-ref的第1个
                   # xrkgame.sdg("func_send_pic_validate_answer", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 38 A1 ? ? ? ? 33 C4 89 44 24 34 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 44 64 A3 00 00 00 00 8B F1 8B 4C 24 54 E8"),
                   # 字符串 NetworkEvents.iErrorCode[FD_READ_BIT]  所在函数
                   xrkgame.sdg("func_loop_recv", "83 EC 2C 53 55 56 57 FF 15"),
                   # 字符串 Client MultiThreadSend failed[type=%d,index=%d,key=%s] 所在函数
                   xrkgame.sdg("func_multi_thread_send", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 B8 30"),
                   # 字符串 ShowInfoWnd 所在函数
                   xrkgame.sdg("ctor_right_button_win", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 14 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 28 64 A3 00 00 00 00 8B F1 89 74 24 14 E8 ? ? ? ? 33 ED 8D 8E 48 04 00 00 89 6C 24 30 C7 06"),
                   xrkgame.sdg("apex_start", "68 ? ? ? ? 6A 06 6A 05 E8 ? ? ? ? 68 ? ? ? ? E8 ? ? ? ? 68 ? ? ? ? E8 ? ? ? ? 83 C4 14 68"),
                   xrkgame.sdg("apex_check_dat_file", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 2C A1 ? ? ? ? 33 C4 89 44 24 ? 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 44 24 ? 64 A3 00 00 00 00 8B 74 24 ? 8D 44 24"),
                   xrkgame.sdg("apex_start_sub_1", "55 8B EC 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 51 83 EC 2C 53 56 57 89 65 F0"),
                   xrkgame.sdg("apex_start_sub_2", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 81 EC 50 01 00 00 A1"),
                   # 字符串 MZ 的第2个ref
                   xrkgame.sdg("apex_load_shzip_call_shplain", "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 08 8B 44 24 18 55 57"),
                   xrkgame.sdg("apex_load_pe_1", "83 EC 30 55 8B 6C 24 38 85 ED 56 57 C7 44 24"),
                   xrkgame.sdg("apex_load_pe_1_call_eop", "FF D1 5B 5F 5E 33 C0 5D 83 C4 30"),
                   xrkgame.sdg("apex_decrypt_string", "8B 4C 24 04 53 8A 19 33 D2 84 DB B8 07 00 00 00 74 ? 42 81 FA 04 01 00 00 7F ? 28 01 83 C0 02 41 83 F8 11 7E"),
                   # 字符串 NetSendToGameServer 所在函数
                   xrkgame.sdg("apex_send_by_game", "83 EC 14 A1 ? ? ? ? 33 C4 89 44 24 10 53 8B"),
                   # 可以根据停止apex的代码，看被踢下线之类的包baitan_win
                   xrkgame.sdg("apex_stop", "68 ? ? ? ? 6A 06 6A 05 E8 ? ? ? ? 83 C4 0C C7 05 ? ? ? ? 00 00 00 00 E8")]
    return ny_sdg_list


ny_sdg2_list = [xrkgame.sdg2("base_npc_talk_win",
                             "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC AC 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 A8 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 C0 01 00 00 64 A3 00 00 00 00 8B F1 89 74 24",
                             "8B CE E8 z z z z A3 x x x x 8B 4C 24 10 64 89 0D 00 00 00 00 59 5E 83 C4 14 C3 33 C0 A3"),
                xrkgame.sdg2("base_baitan_win",
                             "6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 81 EC 60 01 00 00 A1 ? ? ? ? 33 C4 89 84 24 5C 01 00 00 53 55 56 57 A1 ? ? ? ? 33 C4 50 8D 84 24 74 01 00 00 64 A3 00 00 00 00 8B F1 89 74 24 50 E8 ? ? ? ? C7 86 68 04 00 00 ? ? ? ? 33 DB 8D 8E 6C 04 00 00 89 9C 24 7C 01 00 00 C7",
                             "8B C8 E8 z z z z A3 x x x x C7 44 24 10 FF FF FF FF EB 16 33 C0 A3 ? ? ? ? C7 44 24 10 FF FF FF FF EB 05")]

"""
__format_1043920
__dget_6CBE80
__get_player_state_9D27F0
"""


# -------------------------------------------------------------------------
# misc interface
# -------------------------------------------------------------------------


def get_ny_sdg(sdg_desc):
    """
        get sdg by sdg_desc from ny_sdg_list
    """
    for sdg in get_ny_sdg_list():
        if sdg.desc == sdg_desc:
            return sdg
    return None


# -------------------------------------------------------------------------
# test
# -------------------------------------------------------------------------


def test_sdg_1by1():
    i = 0
    for sdg in get_ny_sdg_list():
        x = sdg.search()
        if x is not None:
            xrklog.info("%s - %s" % (sdg.desc, type(x)))
            xrklog.info("sdg - %-40s - %.8X" % (sdg.desc, x))
        else:
            xrklog.error("sdg - %-40s - None" % sdg.desc)
        i = i + 1

    return "x"


def test_sdg_all():
    ny_sdg_result_dict = xrkgame.search_sdg_list(get_ny_sdg_list())
    if ny_sdg_result_dict is None:
        xrklog.error("search got None")
    else:
        for (d, x) in ny_sdg_result_dict.items():
            if x is not None:
                xrklog.info("sdg - %-40s - %.8X" % (d, x))
            else:
                xrklog.error("sdg - %-40s - None" % d)


def test_gen_ida_script():
    fails = xrkgame.gen_ida_script_by_sdg_list(get_ny_sdg_list(), r"e:\\ny_sdg_ida_script_%s.txt" % (xrkutil.time_str()))
    xrklog.high("failed sdgs: %d" % len(fails))
    if len(fails) != 0:
        xrklog.highs(fails)


# -------------------------------------------------------------------------
# END OF FILE
# -------------------------------------------------------------------------
