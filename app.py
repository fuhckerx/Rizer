#!/usr/bin/env python3
import os
import io
import json
import time
import base64
import requests
from collections import defaultdict
from threading import Lock

from flask import Flask, request, Response, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from PIL import Image, ImageDraw, ImageFont
from Crypto.Cipher import AES


from google.protobuf import descriptor_pool, message_factory, json_format


_FREEFIRE_DESCRIPTOR = bytes(
    b'\n\x0e\x46reeFire.proto\"c\n\x08LoginReq\x12\x0f\n\x07open_id\x18\x16 \x01(\t\x12\x14\n\x0copen_id_type\x18\x17 \x01(\t\x12\x13\n\x0blogin_token\x18\x1d \x01(\t\x12\x1b\n\x13orign_platform_type\x18\x63 \x01(\t\"]\n\x10\x42lacklistInfoRes\x12\x1e\n\nban_reason\x18\x01 \x01(\x0e\x32\n.BanReason\x12\x17\n\x0f\x65xpire_duration\x18\x02 \x01(\r\x12\x10\n\x08\x62\x61n_time\x18\x03 \x01(\r\"f\n\x0eLoginQueueInfo\x12\r\n\x05\x61llow\x18\x01 \x01(\x08\x12\x16\n\x0equeue_position\x18\x02 \x01(\r\x12\x16\n\x0eneed_wait_secs\x18\x03 \x01(\r\x12\x15\n\rqueue_is_full\x18\x04 \x01(\x08\"\xa0\x03\n\x08LoginRes\x12\x12\n\naccount_id\x18\x01 \x01(\x04\x12\x13\n\x0block_region\x18\x02 \x01(\t\x12\x13\n\x0bnoti_region\x18\x03 \x01(\t\x12\x11\n\tip_region\x18\x04 \x01(\t\x12\x19\n\x11\x61gora_environment\x18\x05 \x01(\t\x12\x19\n\x11new_active_region\x18\x06 \x01(\t\x12\x19\n\x11recommend_regions\x18\x07 \x03(\t\x12\r\n\x05token\x18\x08 \x01(\t\x12\x0b\n\x03ttl\x18\t \x01(\r\x12\x12\n\nserver_url\x18\n \x01(\t\x12\x16\n\x0e\x65mulator_score\x18\x0b \x01(\r\x12$\n\tblacklist\x18\x0c \x01(\x0b\x32\x11.BlacklistInfoRes\x12#\n\nqueue_info\x18\r \x01(\x0b\x32\x0f.LoginQueueInfo\x12\x0e\n\x06tp_url\x18\x0e \x01(\t\x12\x15\n\rapp_server_id\x18\x0f \x01(\r\x12\x0f\n\x07\x61no_url\x18\x10 \x01(\t\x12\x0f\n\x07ip_city\x18\x11 \x01(\t\x12\x16\n\x0eip_subdivision\x18\x12 \x01(\t*\xa8\x01\n\tBanReason\x12\x16\n\x12\x42\x41N_REASON_UNKNOWN\x10\x00\x12\x1b\n\x17\x42\x41N_REASON_IN_GAME_AUTO\x10\x01\x12\x15\n\x11\x42\x41N_REASON_REFUND\x10\x02\x12\x15\n\x11\x42\x41N_REASON_OTHERS\x10\x03\x12\x16\n\x12\x42\x41N_REASON_SKINMOD\x10\x04\x12 \n\x1b\x42\x41N_REASON_IN_GAME_AUTO_NEW\x10\xf6\x07\x62\x06proto3'
)


_MAIN_DESCRIPTOR = bytes(
    b'\n\x0csample.proto\"*\n\x12SearchWorkshopCode\x12\t\n\x01\x61\x18\x01 \x01(\t\x12\t\n\x01\x62\x18\x02 \x01(\x05\"-\n\x15GetPlayerPersonalShow\x12\t\n\x01\x61\x18\x01 \x01(\x03\x12\t\n\x01\x62\x18\x02 \x01(\x05\"\xf8\x08\n\x0cJwtGenerator\x12\x11\n\ttimestamp\x18\x03 \x01(\t\x12\x11\n\tgame_name\x18\x04 \x01(\t\x12\x14\n\x0cversion_code\x18\x05 \x01(\x05\x12\x13\n\x0b\x61pp_version\x18\x07 \x01(\t\x12\x17\n\x0f\x61ndroid_version\x18\x08 \x01(\t\x12\x13\n\x0b\x64\x65vice_type\x18\t \x01(\t\x12\x18\n\x10network_provider\x18\n \x01(\t\x12\x14\n\x0cnetwork_type\x18\x0b \x01(\t\x12\x14\n\x0cscreen_width\x18\x0c \x01(\x05\x12\x15\n\rscreen_height\x18\r \x01(\x05\x12\x0b\n\x03\x64pi\x18\x0e \x01(\t\x12\x10\n\x08\x63pu_info\x18\x0f \x01(\t\x12\x0b\n\x03\x66ps\x18\x10 \x01(\x05\x12\x11\n\tgpu_model\x18\x11 \x01(\t\x12\x16\n\x0eopengl_version\x18\x12 \x01(\t\x12\x11\n\tdevice_id\x18\x13 \x01(\t\x12\x12\n\nip_address\x18\x14 \x01(\t\x12\x10\n\x08language\x18\x15 \x01(\t\x12\x13\n\x0b\x64\x65vice_hash\x18\x16 \x01(\t\x12\x14\n\x0cos_api_level\x18\x17 \x01(\t\x12\x15\n\ros_build_type\x18\x18 \x01(\t\x12\x14\n\x0c\x64\x65vice_model\x18\x19 \x01(\t\x12\x19\n\x11package_signature\x18\x1d \x01(\t\x12\x12\n\nuser_level\x18\x1e \x01(\x05\x12\x14\n\x0c\x63\x61rrier_name\x18) \x01(\t\x12\x1a\n\x12network_generation\x18* \x01(\t\x12\x15\n\rapp_signature\x18\x39 \x01(\t\x12\x11\n\tplayer_id\x18< \x01(\x03\x12\x12\n\nsession_id\x18= \x01(\x03\x12\x10\n\x08match_id\x18> \x01(\x05\x12\r\n\x05score\x18@ \x01(\x03\x12\x13\n\x0btotal_score\x18\x41 \x01(\x03\x12\x12\n\nhigh_score\x18\x42 \x01(\x03\x12\x11\n\tmax_score\x18\x43 \x01(\x03\x12\x13\n\x0bplayer_rank\x18I \x01(\x05\x12\x17\n\x0fnative_lib_path\x18J \x01(\t\x12\x15\n\ris_debuggable\x18L \x01(\x05\x12\x12\n\napp_source\x18M \x01(\t\x12\x0f\n\x07is_beta\x18N \x01(\x05\x12\x11\n\tis_tester\x18O \x01(\x05\x12\x1b\n\x13target_architecture\x18Q \x01(\t\x12\x18\n\x10\x61pp_version_code\x18S \x01(\t\x12\x19\n\x11\x61pp_revision_code\x18U \x01(\x05\x12\x14\n\x0cgraphics_api\x18V \x01(\t\x12\x18\n\x10max_texture_size\x18W \x01(\x05\x12\x17\n\x0fprocessor_count\x18X \x01(\x05\x12\x16\n\x0e\x65ncryption_key\x18Y \x01(\t\x12\x19\n\x11\x66rame_buffer_size\x18\\ \x01(\x05\x12\x15\n\rplatform_type\x18] \x01(\t\x12\x16\n\x0esecurity_token\x18^ \x01(\t\x12\x18\n\x10\x64isplay_settings\x18` \x01(\t\x12\x14\n\x0cis_logged_in\x18\x61 \x01(\x05\x62\x06proto3'
)


_ACCOUNT_DESCRIPTOR = bytes(
    b'\n\x19\x41\x63\x63ountPersonalShow.proto\x12\x08\x66reefire\"\xa9\x02\n\x0e\x41\x63\x63ountPrefers\x12\x1a\n\rhide_my_lobby\x18\x01 \x01(\x08H\x00\x88\x01\x01\x12\x1c\n\x14pregame_show_choices\x18\x02 \x03(\r\x12\x1f\n\x17\x62r_pregame_show_choices\x18\x03 \x03(\r\x12\x1f\n\x12hide_personal_info\x18\x04 \x01(\x08H\x01\x88\x01\x01\x12$\n\x17\x64isable_friend_spectate\x18\x05 \x01(\x08H\x02\x88\x01\x01\x12\x1c\n\x0fhide_occupation\x18\x06 \x01(\x08H\x03\x88\x01\x01\x42\x10\n\x0e_hide_my_lobbyB\x15\n\x13_hide_personal_infoB\x1a\n\x18_disable_friend_spectateB\x12\n\x10_hide_occupation\"\xc4\x01\n\x10\x45xternalIconInfo\x12\x1a\n\rexternal_icon\x18\x01 \x01(\tH\x00\x88\x01\x01\x12\x31\n\x06status\x18\x02 \x01(\x0e\x32\x1c.freefire.ExternalIconStatusH\x01\x88\x01\x01\x12\x36\n\tshow_type\x18\x03 \x01(\x0e\x32\x1e.freefire.ExternalIconShowTypeH\x02\x88\x01\x01\x42\x10\n\x0e_external_iconB\t\n\x07_statusB\x0c\n\n_show_type\"\x92\x01\n\x0fSocialHighLight\x12,\n\nhigh_light\x18\x01 \x01(\x0e\x32\x13.freefire.HighLightH\x00\x88\x01\x01\x12\x16\n\texpire_at\x18\x02 \x01(\x03H\x01\x88\x01\x01\x12\x12\n\x05value\x18\x03 \x01(\rH\x02\x88\x01\x01\x42\r\n\x0b_high_lightB\x0c\n\n_expire_atB\x08\n\x06_value\"\xbb\x03\n\x14WeaponPowerTitleInfo\x12\x13\n\x06region\x18\x01 \x01(\tH\x00\x88\x01\x01\x12\x19\n\x0ctitle_cfg_id\x18\x02 \x01(\rH\x01\x88\x01\x01\x12\x1b\n\x0eleaderboard_id\x18\x03 \x01(\x04H\x02\x88\x01\x01\x12\x16\n\tweapon_id\x18\x04 \x01(\rH\x03\x88\x01\x01\x12\x11\n\x04rank\x18\x05 \x01(\rH\x04\x88\x01\x01\x12\x18\n\x0b\x65xpire_time\x18\x06 \x01(\x03H\x05\x88\x01\x01\x12\x18\n\x0breward_time\x18\x07 \x01(\x03H\x06\x88\x01\x01\x12\x17\n\nRegionName\x18\x08 \x01(\tH\x07\x88\x01\x01\x12>\n\nRegionType\x18\t \x01(\x0e\x32%.freefire.ELeaderBoardTitleRegionTypeH\x08\x88\x01\x01\x12\x11\n\x04IsBr\x18\n \x01(\x08H\t\x88\x01\x01\x42\t\n\x07_regionB\x0f\n\r_title_cfg_idB\x11\n\x0f_leaderboard_idB\x0c\n\n_weapon_idB\x07\n\x05_rankB\x0e\n\x0c_expire_timeB\x0e\n\x0c_reward_timeB\r\n\x0b_RegionNameB\r\n\x0b_RegionTypeB\x07\n\x05_IsBr\"\xc7\x02\n\x11GuildWarTitleInfo\x12\x13\n\x06region\x18\x01 \x01(\tH\x00\x88\x01\x01\x12\x14\n\x07\x63lan_id\x18\x02 \x01(\x04H\x01\x88\x01\x01\x12\x19\n\x0ctitle_cfg_id\x18\x03 \x01(\rH\x02\x88\x01\x01\x12\x1b\n\x0eleaderboard_id\x18\x04 \x01(\x04H\x03\x88\x01\x01\x12\x11\n\x04rank\x18\x05 \x01(\rH\x04\x88\x01\x01\x12\x18\n\x0b\x65xpire_time\x18\x06 \x01(\x03H\x05\x88\x01\x01\x12\x18\n\x0breward_time\x18\x07 \x01(\x03H\x06\x88\x01\x01\x12\x16\n\tclan_name\x18\x08 \x01(\tH\x07\x88\x01\x01\x42\t\n\x07_regionB\n\n\x08_clan_idB\x0f\n\r_title_cfg_idB\x11\n\x0f_leaderboard_idB\x07\n\x05_rankB\x0e\n\x0c_expire_timeB\x0e\n\x0c_reward_timeB\x0c\n\n_clan_name\"\x92\x01\n\x14LeaderboardTitleInfo\x12?\n\x17weapon_power_title_info\x18\x01 \x03(\x0b\x32\x1e.freefire.WeaponPowerTitleInfo\x12\x39\n\x14guild_war_title_info\x18\x02 \x03(\x0b\x32\x1b.freefire.GuildWarTitleInfo\"\xd5\x05\n\x0fSocialBasicInfo\x12\x17\n\naccount_id\x18\x01 \x01(\x04H\x00\x88\x01\x01\x12%\n\x06gender\x18\x02 \x01(\x0e\x32\x10.freefire.GenderH\x01\x88\x01\x01\x12)\n\x08language\x18\x03 \x01(\x0e\x32\x12.freefire.LanguageH\x02\x88\x01\x01\x12.\n\x0btime_online\x18\x04 \x01(\x0e\x32\x14.freefire.TimeOnlineH\x03\x88\x01\x01\x12.\n\x0btime_active\x18\x05 \x01(\x0e\x32\x14.freefire.TimeActiveH\x04\x88\x01\x01\x12/\n\nbattle_tag\x18\x06 \x03(\x0e\x32\x1b.freefire.PlayerBattleTagID\x12\'\n\nsocial_tag\x18\x07 \x03(\x0e\x32\x13.freefire.SocialTag\x12.\n\x0bmode_prefer\x18\x08 \x01(\x0e\x32\x14.freefire.ModePreferH\x05\x88\x01\x01\x12\x16\n\tsignature\x18\t \x01(\tH\x06\x88\x01\x01\x12*\n\trank_show\x18\n \x01(\x0e\x32\x12.freefire.RankShowH\x07\x88\x01\x01\x12\x18\n\x10\x62\x61ttle_tag_count\x18\x0b \x03(\r\x12&\n\x19signature_ban_expire_time\x18\x0c \x01(\x03H\x08\x88\x01\x01\x12?\n\x12leaderboard_titles\x18\r \x01(\x0b\x32\x1e.freefire.LeaderboardTitleInfoH\t\x88\x01\x01\x42\r\n\x0b_account_idB\t\n\x07_genderB\x0b\n\t_languageB\x0e\n\x0c_time_onlineB\x0e\n\x0c_time_activeB\x0e\n\x0c_mode_preferB\x0c\n\n_signatureB\x0c\n\n_rank_showB\x1c\n\x1a_signature_ban_expire_timeB\x15\n\x13_leaderboard_titles\"\xad\x01\n#SocialHighLightsWithSocialBasicInfo\x12\x35\n\x12social_high_lights\x18\x01 \x03(\x0b\x32\x19.freefire.SocialHighLight\x12\x39\n\x11social_basic_info\x18\x02 \x01(\x0b\x32\x19.freefire.SocialBasicInfoH\x00\x88\x01\x01\x42\x14\n\x12_social_basic_info\"\xb6\x01\n\x0eOccupationInfo\x12\x1a\n\roccupation_id\x18\x01 \x01(\rH\x00\x88\x01\x01\x12\x13\n\x06scores\x18\x02 \x01(\x04H\x01\x88\x01\x01\x12\x18\n\x0bproficients\x18\x03 \x01(\x04H\x02\x88\x01\x01\x12\x1a\n\rproficient_lv\x18\x04 \x01(\rH\x03\x88\x01\x01\x42\x10\n\x0e_occupation_idB\t\n\x07_scoresB\x0e\n\x0c_proficientsB\x10\n\x0e_proficient_lv\"\x98\x01\n\x14OccupationSeasonInfo\x12\x16\n\tseason_id\x18\x01 \x01(\rH\x00\x88\x01\x01\x12\x16\n\tgame_mode\x18\x02 \x01(\rH\x01\x88\x01\x01\x12+\n\x04info\x18\x03 \x01(\x0b\x32\x18.freefire.OccupationInfoH\x02\x88\x01\x01\x42\x0c\n\n_season_idB\x0c\n\n_game_modeB\x07\n\x05_info\"5\n\tPrimeInfo\x12\x18\n\x0bprime_level\x18\x02 \x01(\rH\x00\x88\x01\x01\x42\x0e\n\x0c_prime_level\"\xac\x17\n\x10\x41\x63\x63ountInfoBasic\x12\x17\n\naccount_id\x18\x01 \x01(\x04H\x00\x88\x01\x01\x12\x19\n\x0c\x61\x63\x63ount_type\x18\x02 \x01(\rH\x01\x88\x01\x01\x12\x15\n\x08nickname\x18\x03 \x01(\tH\x02\x88\x01\x01\x12\x18\n\x0b\x65xternal_id\x18\x04 \x01(\tH\x03\x88\x01\x01\x12\x13\n\x06region\x18\x05 \x01(\tH\x04\x88\x01\x01\x12\x12\n\x05level\x18\x06 \x01(\rH\x05\x88\x01\x01\x12\x10\n\x03\x65xp\x18\x07 \x01(\rH\x06\x88\x01\x01\x12\x1a\n\rexternal_type\x18\x08 \x01(\rH\x07\x88\x01\x01\x12\x1a\n\rexternal_name\x18\t \x01(\tH\x08\x88\x01\x01\x12\x1a\n\rexternal_icon\x18\n \x01(\tH\t\x88\x01\x01\x12\x16\n\tbanner_id\x18\x0b \x01(\rH\n\x88\x01\x01\x12\x15\n\x08head_pic\x18\x0c \x01(\rH\x0b\x88\x01\x01\x12\x16\n\tclan_name\x18\r \x01(\tH\x0c\x88\x01\x01\x12\x11\n\x04rank\x18\x0e \x01(\rH\r\x88\x01\x01\x12\x1b\n\x0eranking_points\x18\x0f \x01(\rH\x0e\x88\x01\x01\x12\x11\n\x04role\x18\x10 \x01(\rH\x0f\x88\x01\x01\x12\x1b\n\x0ehas_elite_pass\x18\x11 \x01(\x08H\x10\x88\x01\x01\x12\x16\n\tbadge_cnt\x18\x12 \x01(\rH\x11\x88\x01\x01\x12\x15\n\x08\x62\x61\x64ge_id\x18\x13 \x01(\rH\x12\x88\x01\x01\x12\x16\n\tseason_id\x18\x14 \x01(\rH\x13\x88\x01\x01\x12\x12\n\x05liked\x18\x15 \x01(\rH\x14\x88\x01\x01\x12\x17\n\nis_deleted\x18\x16 \x01(\x08H\x15\x88\x01\x01\x12\x16\n\tshow_rank\x18\x17 \x01(\x08H\x16\x88\x01\x01\x12\x1a\n\rlast_login_at\x18\x18 \x01(\x03H\x17\x88\x01\x01\x12\x19\n\x0c\x65xternal_uid\x18\x19 \x01(\x04H\x18\x88\x01\x01\x12\x16\n\treturn_at\x18\x1a \x01(\x03H\x19\x88\x01\x01\x12#\n\x16\x63hampionship_team_name\x18\x1b \x01(\tH\x1a\x88\x01\x01\x12)\n\x1c\x63hampionship_team_member_num\x18\x1c \x01(\rH\x1b\x88\x01\x01\x12!\n\x14\x63hampionship_team_id\x18\x1d \x01(\x04H\x1c\x88\x01\x01\x12\x14\n\x07\x63s_rank\x18\x1e \x01(\rH\x1d\x88\x01\x01\x12\x1e\n\x11\x63s_ranking_points\x18\x1f \x01(\rH\x1e\x88\x01\x01\x12\x19\n\x11weapon_skin_shows\x18  \x03(\r\x12\x13\n\x06pin_id\x18! \x01(\rH\x1f\x88\x01\x01\x12\x1e\n\x11is_cs_ranking_ban\x18\" \x01(\x08H \x88\x01\x01\x12\x15\n\x08max_rank\x18# \x01(\rH!\x88\x01\x01\x12\x18\n\x0b\x63s_max_rank\x18$ \x01(\rH\"\x88\x01\x01\x12\x1f\n\x12max_ranking_points\x18% \x01(\rH#\x88\x01\x01\x12\x1a\n\rgame_bag_show\x18& \x01(\rH$\x88\x01\x01\x12\x1a\n\rpeak_rank_pos\x18\' \x01(\rH%\x88\x01\x01\x12\x1d\n\x10\x63s_peak_rank_pos\x18( \x01(\rH&\x88\x01\x01\x12\x36\n\x0f\x61\x63\x63ount_prefers\x18) \x01(\x0b\x32\x18.freefire.AccountPrefersH\'\x88\x01\x01\x12$\n\x17periodic_ranking_points\x18* \x01(\rH(\x88\x01\x01\x12\x1a\n\rperiodic_rank\x18+ \x01(\rH)\x88\x01\x01\x12\x16\n\tcreate_at\x18, \x01(\x03H*\x88\x01\x01\x12?\n\x16veteran_leave_days_tag\x18- \x01(\x0e\x32\x1a.freefire.VeteranLeaveDaysH+\x88\x01\x01\x12\x1b\n\x13selected_item_slots\x18. \x03(\r\x12=\n\x10pre_veteran_type\x18/ \x01(\x0e\x32\x1e.freefire.PreVeteranActionTypeH,\x88\x01\x01\x12\x12\n\x05title\x18\x30 \x01(\rH-\x88\x01\x01\x12;\n\x12\x65xternal_icon_info\x18\x31 \x01(\x0b\x32\x1a.freefire.ExternalIconInfoH.\x88\x01\x01\x12\x1c\n\x0frelease_version\x18\x32 \x01(\tH/\x88\x01\x01\x12 \n\x13veteran_expire_time\x18\x33 \x01(\x04H0\x88\x01\x01\x12\x19\n\x0cshow_br_rank\x18\x34 \x01(\x08H1\x88\x01\x01\x12\x19\n\x0cshow_cs_rank\x18\x35 \x01(\x08H2\x88\x01\x01\x12\x14\n\x07\x63lan_id\x18\x36 \x01(\x04H3\x88\x01\x01\x12\x1a\n\rclan_badge_id\x18\x37 \x01(\rH4\x88\x01\x01\x12\x1e\n\x11\x63ustom_clan_badge\x18\x38 \x01(\tH5\x88\x01\x01\x12\"\n\x15use_custom_clan_badge\x18\x39 \x01(\x08H6\x88\x01\x01\x12\x1a\n\rclan_frame_id\x18: \x01(\rH7\x88\x01\x01\x12\x1d\n\x10membership_state\x18; \x01(\x08H8\x88\x01\x01\x12:\n\x12select_occupations\x18< \x03(\x0b\x32\x1e.freefire.OccupationSeasonInfo\x12^\n\"social_high_lights_with_basic_info\x18= \x01(\x0b\x32-.freefire.SocialHighLightsWithSocialBasicInfoH9\x88\x01\x01\x12,\n\nprime_info\x18L \x01(\x0b\x32\x13.freefire.PrimeInfoH:\x88\x01\x01\x42\r\n\x0b_account_idB\x0f\n\r_account_typeB\x0b\n\t_nicknameB\x0e\n\x0c_external_idB\t\n\x07_regionB\x08\n\x06_levelB\x06\n\x04_expB\x10\n\x0e_external_typeB\x10\n\x0e_external_nameB\x10\n\x0e_external_iconB\x0c\n\n_banner_idB\x0b\n\t_head_picB\x0c\n\n_clan_nameB\x07\n\x05_rankB\x11\n\x0f_ranking_pointsB\x07\n\x05_roleB\x11\n\x0f_has_elite_passB\x0c\n\n_badge_cntB\x0b\n\t_badge_idB\x0c\n\n_season_idB\x08\n\x06_likedB\r\n\x0b_is_deletedB\x0c\n\n_show_rankB\x10\n\x0e_last_login_atB\x0f\n\r_external_uidB\x0c\n\n_return_atB\x19\n\x17_championship_team_nameB\x1f\n\x1d_championship_team_member_numB\x17\n\x15_championship_team_idB\n\n\x08_cs_rankB\x14\n\x12_cs_ranking_pointsB\t\n\x07_pin_idB\x14\n\x12_is_cs_ranking_banB\x0b\n\t_max_rankB\x0e\n\x0c_cs_max_rankB\x15\n\x13_max_ranking_pointsB\x10\n\x0e_game_bag_showB\x10\n\x0e_peak_rank_posB\x13\n\x11_cs_peak_rank_posB\x12\n\x10_account_prefersB\x1a\n\x18_periodic_ranking_pointsB\x10\n\x0e_periodic_rankB\x0c\n\n_create_atB\x19\n\x17_veteran_leave_days_tagB\x13\n\x11_pre_veteran_typeB\x08\n\x06_titleB\x15\n\x13_external_icon_infoB\x12\n\x10_release_versionB\x16\n\x14_veteran_expire_timeB\x0f\n\r_show_br_rankB\x0f\n\r_show_cs_rankB\n\n\x08_clan_idB\x10\n\x0e_clan_badge_idB\x14\n\x12_custom_clan_badgeB\x18\n\x16_use_custom_clan_badgeB\x10\n\x0e_clan_frame_idB\x13\n\x11_membership_stateB%\n#_social_high_lights_with_basic_infoB\r\n\x0b_prime_info\"\x9a\x01\n\x0f\x41vatarSkillSlot\x12\x14\n\x07slot_id\x18\x01 \x01(\x04H\x00\x88\x01\x01\x12\x15\n\x08skill_id\x18\x02 \x01(\x04H\x01\x88\x01\x01\x12\x30\n\x0c\x65quip_source\x18\x03 \x01(\x0e\x32\x15.freefire.EquipSourceH\x02\x88\x01\x01\x42\n\n\x08_slot_idB\x0b\n\t_skill_idB\x0f\n\r_equip_source\"\x98\x05\n\rAvatarProfile\x12\x16\n\tavatar_id\x18\x01 \x01(\rH\x00\x88\x01\x01\x12\x17\n\nskin_color\x18\x03 \x01(\rH\x01\x88\x01\x01\x12\x0f\n\x07\x63lothes\x18\x04 \x03(\r\x12\x16\n\x0e\x65quiped_skills\x18\x05 \x03(\r\x12\x18\n\x0bis_selected\x18\x06 \x01(\x08H\x02\x88\x01\x01\x12\x1f\n\x12pve_primary_weapon\x18\x07 \x01(\rH\x03\x88\x01\x01\x12\x1f\n\x12is_selected_awaken\x18\x08 \x01(\x08H\x04\x88\x01\x01\x12\x15\n\x08\x65nd_time\x18\t \x01(\rH\x05\x88\x01\x01\x12.\n\x0bunlock_type\x18\n \x01(\x0e\x32\x14.freefire.UnlockTypeH\x06\x88\x01\x01\x12\x18\n\x0bunlock_time\x18\x0b \x01(\rH\x07\x88\x01\x01\x12\x1b\n\x0eis_marked_star\x18\x0c \x01(\x08H\x08\x88\x01\x01\x12\x1e\n\x16\x63lothes_tailor_effects\x18\r \x03(\r\x12\x10\n\x03top\x18\x0e \x01(\rH\t\x88\x01\x01\x12\x13\n\x06\x62ottom\x18\x0f \x01(\rH\n\x88\x01\x01\x12\x11\n\x04mask\x18\x10 \x01(\rH\x0b\x88\x01\x01\x12\x16\n\tfacepaint\x18\x11 \x01(\rH\x0c\x88\x01\x01\x12\x12\n\x05shoes\x18\x12 \x01(\rH\r\x88\x01\x01\x42\x0c\n\n_avatar_idB\r\n\x0b_skin_colorB\x0e\n\x0c_is_selectedB\x15\n\x13_pve_primary_weaponB\x15\n\x13_is_selected_awakenB\x0b\n\t_end_timeB\x0e\n\x0c_unlock_typeB\x0e\n\x0c_unlock_timeB\x11\n\x0f_is_marked_starB\x06\n\x04_topB\t\n\x07_bottomB\x07\n\x05_maskB\x0c\n\n_facepaintB\x08\n\x06_shoes\"\xd8\x02\n\x12\x41\x63\x63ountNewsContent\x12\x10\n\x08item_ids\x18\x01 \x03(\r\x12\x11\n\x04rank\x18\x02 \x01(\rH\x00\x88\x01\x01\x12\x17\n\nmatch_mode\x18\x03 \x01(\rH\x01\x88\x01\x01\x12\x13\n\x06map_id\x18\x04 \x01(\rH\x02\x88\x01\x01\x12\x16\n\tgame_mode\x18\x05 \x01(\rH\x03\x88\x01\x01\x12\x17\n\ngroup_mode\x18\x06 \x01(\rH\x04\x88\x01\x01\x12\x1b\n\x0etreasurebox_id\x18\x07 \x01(\rH\x05\x88\x01\x01\x12\x19\n\x0c\x63ommodity_id\x18\x08 \x01(\rH\x06\x88\x01\x01\x12\x15\n\x08store_id\x18\t \x01(\rH\x07\x88\x01\x01\x42\x07\n\x05_rankB\r\n\x0b_match_modeB\t\n\x07_map_idB\x0c\n\n_game_modeB\r\n\x0b_group_modeB\x11\n\x0f_treasurebox_idB\x0f\n\r_commodity_idB\x0b\n\t_store_id\"\xa7\x01\n\x0b\x41\x63\x63ountNews\x12%\n\x04type\x18\x01 \x01(\x0e\x32\x12.freefire.NewsTypeH\x00\x88\x01\x01\x12\x32\n\x07\x63ontent\x18\x02 \x01(\x0b\x32\x1c.freefire.AccountNewsContentH\x01\x88\x01\x01\x12\x18\n\x0bupdate_time\x18\x03 \x01(\x03H\x02\x88\x01\x01\x42\x07\n\x05_typeB\n\n\x08_contentB\x0e\n\x0c_update_time\"\x99\x02\n\x0b\x42\x61sicEPInfo\x12\x18\n\x0b\x65p_event_id\x18\x01 \x01(\rH\x00\x88\x01\x01\x12\x17\n\nowned_pass\x18\x02 \x01(\x08H\x01\x88\x01\x01\x12\x15\n\x08\x65p_badge\x18\x03 \x01(\rH\x02\x88\x01\x01\x12\x16\n\tbadge_cnt\x18\x04 \x01(\rH\x03\x88\x01\x01\x12\x14\n\x07\x62p_icon\x18\x05 \x01(\tH\x04\x88\x01\x01\x12\x16\n\tmax_level\x18\x06 \x01(\rH\x05\x88\x01\x01\x12\x17\n\nevent_name\x18\x07 \x01(\tH\x06\x88\x01\x01\x42\x0e\n\x0c_ep_event_idB\r\n\x0b_owned_passB\x0b\n\t_ep_badgeB\x0c\n\n_badge_cntB\n\n\x08_bp_iconB\x0c\n\n_max_levelB\r\n\x0b_event_name\"\x9d\x02\n\rClanInfoBasic\x12\x14\n\x07\x63lan_id\x18\x01 \x01(\x04H\x00\x88\x01\x01\x12\x16\n\tclan_name\x18\x02 \x01(\tH\x01\x88\x01\x01\x12\x17\n\ncaptain_id\x18\x03 \x01(\x04H\x02\x88\x01\x01\x12\x17\n\nclan_level\x18\x04 \x01(\rH\x03\x88\x01\x01\x12\x15\n\x08\x63\x61pacity\x18\x05 \x01(\rH\x04\x88\x01\x01\x12\x17\n\nmember_num\x18\x06 \x01(\rH\x05\x88\x01\x01\x12\x18\n\x0bhonor_point\x18\x07 \x01(\rH\x06\x88\x01\x01\x42\n\n\x08_clan_idB\x0c\n\n_clan_nameB\r\n\x0b_captain_idB\r\n\x0b_clan_levelB\x0b\n\t_capacityB\r\n\x0b_member_numB\x0e\n\x0c_honor_point\"|\n\x0cPetSkillInfo\x12\x13\n\x06pet_id\x18\x01 \x01(\rH\x00\x88\x01\x01\x12\x15\n\x08skill_id\x18\x02 \x01(\rH\x01\x88\x01\x01\x12\x18\n\x0bskill_level\x18\x03 \x01(\rH\x02\x88\x01\x01\x42\t\n\x07_pet_idB\x0b\n\t_skill_idB\x0e\n\x0c_skill_level\"\x84\x03\n\x07PetInfo\x12\x0f\n\x02id\x18\x01 \x01(\rH\x00\x88\x01\x01\x12\x11\n\x04name\x18\x02 \x01(\tH\x01\x88\x01\x01\x12\x12\n\x05level\x18\x03 \x01(\rH\x02\x88\x01\x01\x12\x10\n\x03\x65xp\x18\x04 \x01(\rH\x03\x88\x01\x01\x12\x18\n\x0bis_selected\x18\x05 \x01(\x08H\x04\x88\x01\x01\x12\x14\n\x07skin_id\x18\x06 \x01(\rH\x05\x88\x01\x01\x12\x0f\n\x07\x61\x63tions\x18\x07 \x03(\r\x12&\n\x06skills\x18\x08 \x03(\x0b\x32\x16.freefire.PetSkillInfo\x12\x1e\n\x11selected_skill_id\x18\t \x01(\rH\x06\x88\x01\x01\x12\x1b\n\x0eis_marked_star\x18\n \x01(\x08H\x07\x88\x01\x01\x12\x15\n\x08\x65nd_time\x18\x0b \x01(\rH\x08\x88\x01\x01\x42\x05\n\x03_idB\x07\n\x05_nameB\x08\n\x06_levelB\x06\n\x04_expB\x0e\n\x0c_is_selectedB\n\n\x08_skin_idB\x14\n\x12_selected_skill_idB\x11\n\x0f_is_marked_starB\x0b\n\t_end_time\"<\n\x0e\x44iamondCostRes\x12\x19\n\x0c\x64iamond_cost\x18\x01 \x01(\rH\x00\x88\x01\x01\x42\x0f\n\r_diamond_cost\"\xfd\x03\n\x14\x43reditScoreInfoBasic\x12\x19\n\x0c\x63redit_score\x18\x01 \x01(\rH\x00\x88\x01\x01\x12\x14\n\x07is_init\x18\x02 \x01(\x08H\x01\x88\x01\x01\x12\x30\n\x0creward_state\x18\x03 \x01(\x0e\x32\x15.freefire.RewardStateH\x02\x88\x01\x01\x12&\n\x19periodic_summary_like_cnt\x18\x04 \x01(\rH\x03\x88\x01\x01\x12)\n\x1cperiodic_summary_illegal_cnt\x18\x05 \x01(\rH\x04\x88\x01\x01\x12\x1d\n\x10weekly_match_cnt\x18\x06 \x01(\rH\x05\x88\x01\x01\x12(\n\x1bperiodic_summary_start_time\x18\x07 \x01(\x03H\x06\x88\x01\x01\x12&\n\x19periodic_summary_end_time\x18\x08 \x01(\x03H\x07\x88\x01\x01\x42\x0f\n\r_credit_scoreB\n\n\x08_is_initB\x0f\n\r_reward_stateB\x1c\n\x1a_periodic_summary_like_cntB\x1f\n\x1d_periodic_summary_illegal_cntB\x13\n\x11_weekly_match_cntB\x1e\n\x1c_periodic_summary_start_timeB\x1c\n\x1a_periodic_summary_end_time\"L\n\x0c\x45quipAchInfo\x12\x13\n\x06\x61\x63h_id\x18\x01 \x01(\rH\x00\x88\x01\x01\x12\x12\n\x05level\x18\x02 \x01(\rH\x01\x88\x01\x01\x42\t\n\x07_ach_idB\x08\n\x06_level\"\xfa\x06\n\x17\x41\x63\x63ountPersonalShowInfo\x12\x33\n\nbasic_info\x18\x01 \x01(\x0b\x32\x1a.freefire.AccountInfoBasicH\x00\x88\x01\x01\x12\x32\n\x0cprofile_info\x18\x02 \x01(\x0b\x32\x17.freefire.AvatarProfileH\x01\x88\x01\x01\x12$\n\x17ranking_leaderboard_pos\x18\x03 \x01(\x05H\x02\x88\x01\x01\x12#\n\x04news\x18\x04 \x03(\x0b\x32\x15.freefire.AccountNews\x12.\n\x0fhistory_ep_info\x18\x05 \x03(\x0b\x32\x15.freefire.BasicEPInfo\x12\x35\n\x0f\x63lan_basic_info\x18\x06 \x01(\x0b\x32\x17.freefire.ClanInfoBasicH\x03\x88\x01\x01\x12;\n\x12\x63\x61ptain_basic_info\x18\x07 \x01(\x0b\x32\x1a.freefire.AccountInfoBasicH\x04\x88\x01\x01\x12(\n\x08pet_info\x18\x08 \x01(\x0b\x32\x11.freefire.PetInfoH\x05\x88\x01\x01\x12\x33\n\x0bsocial_info\x18\t \x01(\x0b\x32\x19.freefire.SocialBasicInfoH\x06\x88\x01\x01\x12\x37\n\x10\x64iamond_cost_res\x18\n \x01(\x0b\x32\x18.freefire.DiamondCostResH\x07\x88\x01\x01\x12>\n\x11\x63redit_score_info\x18\x0b \x01(\x0b\x32\x1e.freefire.CreditScoreInfoBasicH\x08\x88\x01\x01\x12=\n\x10pre_veteran_type\x18\x0c \x01(\x0e\x32\x1e.freefire.PreVeteranActionTypeH\t\x88\x01\x01\x12,\n\x0c\x65quipped_ach\x18\r \x03(\x0b\x32\x16.freefire.EquipAchInfoB\r\n\x0b_basic_infoB\x0f\n\r_profile_infoB\x1a\n\x18_ranking_leaderboard_posB\x12\n\x10_clan_basic_infoB\x15\n\x13_captain_basic_infoB\x0b\n\t_pet_infoB\x0e\n\x0c_social_infoB\x13\n\x11_diamond_cost_resB\x14\n\x12_credit_score_infoB\x13\n\x11_pre_veteran_type*\xa0\x01\n\x10VeteranLeaveDays\x12\x19\n\x15VeteranLeaveDays_NONE\x10\x00\x12\x1a\n\x16VeteranLeaveDays_SHORT\x10\x01\x12\x1b\n\x17VeteranLeaveDays_NORMAL\x10\x02\x12\x19\n\x15VeteranLeaveDays_LONG\x10\x03\x12\x1d\n\x19VeteranLeaveDays_VERYLONG\x10\x04*w\n\x14PreVeteranActionType\x12\x1d\n\x19PreVeteranActionType_NONE\x10\x00\x12!\n\x1dPreVeteranActionType_ACTIVITY\x10\x01\x12\x1d\n\x19PreVeteranActionType_BUFF\x10\x02*s\n\x12\x45xternalIconStatus\x12\x1b\n\x17\x45xternalIconStatus_NONE\x10\x00\x12!\n\x1d\x45xternalIconStatus_NOT_IN_USE\x10\x01\x12\x1d\n\x19\x45xternalIconStatus_IN_USE\x10\x02*t\n\x14\x45xternalIconShowType\x12\x1d\n\x19\x45xternalIconShowType_NONE\x10\x00\x12\x1f\n\x1b\x45xternalIconShowType_FRIEND\x10\x01\x12\x1c\n\x18\x45xternalIconShowType_ALL\x10\x02*\xf0\x02\n\tHighLight\x12\x12\n\x0eHighLight_NONE\x10\x00\x12\x14\n\x10HighLight_BR_WIN\x10\x01\x12\x14\n\x10HighLight_CS_MVP\x10\x02\x12\x1b\n\x17HighLight_BR_STREAK_WIN\x10\x03\x12\x1b\n\x17HighLight_CS_STREAK_WIN\x10\x04\x12#\n\x1fHighLight_CS_RANK_GROUP_UPGRADE\x10\x05\x12\x16\n\x12HighLight_TEAM_ACE\x10\x06\x12 \n\x1cHighLight_WEAPON_POWER_TITLE\x10\x07\x12#\n\x1fHighLight_BR_RANK_GROUP_UPGRADE\x10\t\x12&\n\"HighLight_BR_STREAK_WIN_EXECELLENT\x10\n\x12&\n\"HighLight_CS_STREAK_WIN_EXECELLENT\x10\x0b\x12\x15\n\x11HighLight_VETERAN\x10\x0c*T\n\x06Gender\x12\x0f\n\x0bGender_NONE\x10\x00\x12\x0f\n\x0bGender_MALE\x10\x01\x12\x11\n\rGender_FEMALE\x10\x02\x12\x15\n\x10Gender_UNLIMITED\x10\xe7\x07*\xf5\x03\n\x08Language\x12\x11\n\rLanguage_NONE\x10\x00\x12\x0f\n\x0bLanguage_EN\x10\x01\x12\x1a\n\x16Language_CN_SIMPLIFIED\x10\x02\x12\x1b\n\x17Language_CN_TRADITIONAL\x10\x03\x12\x11\n\rLanguage_Thai\x10\x04\x12\x17\n\x13Language_VIETNAMESE\x10\x05\x12\x17\n\x13Language_INDONESIAN\x10\x06\x12\x17\n\x13Language_PORTUGUESE\x10\x07\x12\x14\n\x10Language_SPANISH\x10\x08\x12\x14\n\x10Language_RUSSIAN\x10\t\x12\x13\n\x0fLanguage_KOREAN\x10\n\x12\x13\n\x0fLanguage_FRENCH\x10\x0b\x12\x13\n\x0fLanguage_GERMAN\x10\x0c\x12\x14\n\x10Language_TURKISH\x10\r\x12\x12\n\x0eLanguage_HINDI\x10\x0e\x12\x15\n\x11Language_JAPANESE\x10\x0f\x12\x15\n\x11Language_ROMANIAN\x10\x10\x12\x13\n\x0fLanguage_ARABIC\x10\x11\x12\x14\n\x10Language_BURMESE\x10\x12\x12\x11\n\rLanguage_URDU\x10\x13\x12\x14\n\x10Language_BENGALI\x10\x14\x12\x17\n\x12Language_UNLIMITED\x10\xe7\x07*l\n\nTimeOnline\x12\x13\n\x0fTimeOnline_NONE\x10\x00\x12\x16\n\x12TimeOnline_WORKDAY\x10\x01\x12\x16\n\x12TimeOnline_WEEKEND\x10\x02\x12\x19\n\x14TimeOnline_UNLIMITED\x10\xe7\x07*\x84\x01\n\nTimeActive\x12\x13\n\x0fTimeActive_NONE\x10\x00\x12\x16\n\x12TimeActive_MORNING\x10\x01\x12\x18\n\x14TimeActive_AFTERNOON\x10\x02\x12\x14\n\x10TimeActive_NIGHT\x10\x03\x12\x19\n\x14TimeActive_UNLIMITED\x10\xe7\x07*\xf6\x02\n\x11PlayerBattleTagID\x12\x1a\n\x16PlayerBattleTagID_NONE\x10\x00\x12!\n\x1cPlayerBattleTagID_DOMINATION\x10\xcd\x08\x12\x1e\n\x19PlayerBattleTagID_UNCROWN\x10\xce\x08\x12\"\n\x1dPlayerBattleTagID_BESTPARTNER\x10\xcf\x08\x12\x1d\n\x18PlayerBattleTagID_SNIPER\x10\xd0\x08\x12\x1c\n\x17PlayerBattleTagID_MELEE\x10\xd1\x08\x12!\n\x1cPlayerBattleTagID_PEACEMAKER\x10\xd2\x08\x12\x1d\n\x18PlayerBattleTagID_AMBUSH\x10\xd3\x08\x12 \n\x1bPlayerBattleTagID_SHORTSTOP\x10\xd4\x08\x12\x1e\n\x19PlayerBattleTagID_RAMPAGE\x10\xd5\x08\x12\x1d\n\x18PlayerBattleTagID_LEADER\x10\xd6\x08*\xe4\x01\n\tSocialTag\x12\x12\n\x0eSocialTag_NONE\x10\x00\x12\x16\n\x11SocialTag_FASHION\x10\xb5\x10\x12\x15\n\x10SocialTag_SOCIAL\x10\xb6\x10\x12\x16\n\x11SocialTag_VETERAN\x10\xb7\x10\x12\x15\n\x10SocialTag_NEWBIE\x10\xb8\x10\x12\x19\n\x14SocialTag_PLAYFORWIN\x10\xb9\x10\x12\x19\n\x14SocialTag_PLAYFORFUN\x10\xba\x10\x12\x16\n\x11SocialTag_VOICEON\x10\xbb\x10\x12\x17\n\x12SocialTag_VOICEOFF\x10\xbc\x10*\x80\x01\n\nModePrefer\x12\x13\n\x0fModePrefer_NONE\x10\x00\x12\x11\n\rModePrefer_BR\x10\x01\x12\x11\n\rModePrefer_CS\x10\x02\x12\x1c\n\x18ModePrefer_ENTERTAINMENT\x10\x03\x12\x19\n\x14ModePrefer_UNLIMITED\x10\xe7\x07*X\n\x08RankShow\x12\x11\n\rRankShow_NONE\x10\x00\x12\x0f\n\x0bRankShow_BR\x10\x01\x12\x0f\n\x0bRankShow_CS\x10\x02\x12\x17\n\x12RankShow_UNLIMITED\x10\xe7\x07*L\n\x1b\x45LeaderBoardTitleRegionType\x12\x08\n\x04None\x10\x00\x12\x0b\n\x07\x43ountry\x10\x01\x12\x0c\n\x08Province\x10\x02\x12\x08\n\x04\x43ity\x10\x03*6\n\nUnlockType\x12\x13\n\x0fUnlockType_NONE\x10\x00\x12\x13\n\x0fUnlockType_LINK\x10\x01*E\n\x0b\x45quipSource\x12\x14\n\x10\x45quipSource_SELF\x10\x00\x12 \n\x1c\x45quipSource_CONFIDANT_FRIEND\x10\x01*\xfa\x01\n\x08NewsType\x12\x11\n\rNewsType_NONE\x10\x00\x12\x11\n\rNewsType_RANK\x10\x01\x12\x14\n\x10NewsType_LOTTERY\x10\x02\x12\x15\n\x11NewsType_PURCHASE\x10\x03\x12\x18\n\x14NewsType_TREASUREBOX\x10\x04\x12\x16\n\x12NewsType_ELITEPASS\x10\x05\x12\x1a\n\x16NewsType_EXCHANGESTORE\x10\x06\x12\x13\n\x0fNewsType_BUNDLE\x10\x07\x12#\n\x1fNewsType_LOTTERYSPECIALEXCHANGE\x10\x08\x12\x13\n\x0fNewsType_OTHERS\x10\t*]\n\x0bRewardState\x12\x18\n\x14REWARD_STATE_INVALID\x10\x00\x12\x1a\n\x16REWARD_STATE_UNCLAIMED\x10\x01\x12\x18\n\x14REWARD_STATE_CLAIMED\x10\x02\x62\x06proto3'
)


_pool = descriptor_pool.DescriptorPool()
_pool.AddSerializedFile(_FREEFIRE_DESCRIPTOR)
_pool.AddSerializedFile(_MAIN_DESCRIPTOR)
_pool.AddSerializedFile(_ACCOUNT_DESCRIPTOR)


LoginReq = message_factory.GetMessageClass(_pool.FindMessageTypeByName('LoginReq'))
LoginRes = message_factory.GetMessageClass(_pool.FindMessageTypeByName('LoginRes'))
GetPlayerPersonalShow = message_factory.GetMessageClass(_pool.FindMessageTypeByName('GetPlayerPersonalShow'))
AccountPersonalShowInfo = message_factory.GetMessageClass(_pool.FindMessageTypeByName('freefire.AccountPersonalShowInfo'))

# ========================= Configuration =========================
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB53"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}


AVATAR_ZOOM = 1.26
AVATAR_SHIFT_Y = 0
AVATAR_SHIFT_X = 0
BANNER_START_X = 0.25
BANNER_START_Y = 0.29
BANNER_END_X = 0.81
BANNER_END_Y = 0.65


IMAGE_CDN = base64.b64decode("aHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L2doL1NoYWhHQ3JlYXRvci9pY29uQG1haW4vUE5H").decode("utf-8")


FONT_FILE = "arial_unicode_bold.otf"
FONT_CHEROKEE = "NotoSansCherokee.ttf"


app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
uid_region_cache = {}
cached_tokens = defaultdict(dict)
token_lock = Lock()


def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def json_to_proto(json_data: str, proto_message):
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def decode_protobuf(encoded_data: bytes, message_class):
    instance = message_class()
    instance.ParseFromString(encoded_data)
    return instance

def get_account_credentials(region: str) -> str:
    r = region.upper()
    if r == "IND":
        return "uid=4363983977&password=ISHITA_0AFN5_BY_SPIDEERIO_GAMING_UY12H"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=4682784982&password=GHOST_TNVW1_RIZER_QTFT0"
    else:
        return "uid=4418979127&password=RIZER_K4CY1_RIZER_WNX02"

def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    resp = requests.post(url, data=payload, headers=headers, timeout=15)
    if resp.status_code == 200:
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")
    return "0", "0"

def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = get_access_token(account)
    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = json_to_proto(body, LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1",
               'X-GA': "v1 1", 'ReleaseVersion': RELEASEVERSION}
    resp = requests.post(url, data=payload, headers=headers, timeout=15)
    msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, LoginRes)))
    with token_lock:
        cached_tokens[region] = {
            'token': f"Bearer {msg.get('token','0')}",
            'region': msg.get('lockRegion','0'),
            'server_url': msg.get('serverUrl','0'),
            'expires_at': time.time() + 25200
        }

def get_token_info(region: str):
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

def get_account_information(uid, unk, region, endpoint):
    payload = json_to_proto(json.dumps({'a': uid, 'b': unk}), GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = get_token_info(region)
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue",
               'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
               'ReleaseVersion': RELEASEVERSION}
    resp = requests.post(server + endpoint, data=data_enc, headers=headers, timeout=15)
    return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShowInfo)))


def load_unicode_font(size, font_file=FONT_FILE):
    try:
        font_path = os.path.join(os.path.dirname(__file__), font_file)
        if os.path.exists(font_path):
            return ImageFont.truetype(font_path, size)
    except:
        pass
    return ImageFont.load_default()

def fetch_image_bytes(item_id):
    if not item_id or str(item_id) == "0":
        return None
    try:
        url = f"{IMAGE_CDN}/{item_id}.png"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.content
    except:
        pass
    return None

def bytes_to_image(img_bytes):
    if img_bytes:
        return Image.open(io.BytesIO(img_bytes)).convert("RGBA")

    return Image.new("RGBA", (100, 100), (0, 0, 0, 0))

def process_banner_image(data, avatar_bytes, banner_bytes, pin_bytes):
    avatar_img = bytes_to_image(avatar_bytes)
    banner_img = bytes_to_image(banner_bytes)
    pin_img = bytes_to_image(pin_bytes)

    level = str(data.get("AccountLevel") or "0")
    name = str(data.get("AccountName") or "Unknown")
    guild = str(data.get("GuildName") or "")

    TARGET_HEIGHT = 400
    zoom_size = int(TARGET_HEIGHT * AVATAR_ZOOM)
    avatar_img = avatar_img.resize((zoom_size, zoom_size), Image.LANCZOS)

    c = zoom_size // 2
    h = TARGET_HEIGHT // 2
    avatar_img = avatar_img.crop((
        c - h - AVATAR_SHIFT_X,
        c - h - AVATAR_SHIFT_Y,
        c + h - AVATAR_SHIFT_X,
        c + h - AVATAR_SHIFT_Y
    ))

    banner_img = banner_img.rotate(3, expand=True)
    bw, bh = banner_img.size
    banner_img = banner_img.crop((
        bw * BANNER_START_X,
        bh * BANNER_START_Y,
        bw * BANNER_END_X,
        bh * BANNER_END_Y
    ))

    bw, bh = banner_img.size
    banner_img = banner_img.resize(
        (int(TARGET_HEIGHT * (bw / bh) * 2), TARGET_HEIGHT),
        Image.LANCZOS
    )

    final = Image.new("RGBA", (avatar_img.width + banner_img.width, TARGET_HEIGHT))
    final.paste(avatar_img, (0, 0))
    final.paste(banner_img, (avatar_img.width, 0))

    draw = ImageDraw.Draw(final)

    font_big = load_unicode_font(125)
    font_big_c = load_unicode_font(125, FONT_CHEROKEE)
    font_small = load_unicode_font(95)
    font_small_c = load_unicode_font(95, FONT_CHEROKEE)
    font_lvl = load_unicode_font(50)

    def is_cherokee(c):
        return 0x13A0 <= ord(c) <= 0x13FF or 0xAB70 <= ord(c) <= 0xABBF

    def draw_text(x, y, text, f_main, f_alt, stroke):
        text = text or ""
        cx = x
        for ch in text:
            f = f_alt if is_cherokee(ch) else f_main
            for dx in range(-stroke, stroke + 1):
                for dy in range(-stroke, stroke + 1):
                    draw.text((cx + dx, y + dy), ch, font=f, fill="black")
            draw.text((cx, y), ch, font=f, fill="white")
            cx += f.getlength(ch)

    draw_text(avatar_img.width + 65, 40, name, font_big, font_big_c, 4)
    draw_text(avatar_img.width + 65, 220, guild, font_small, font_small_c, 3)

    # Pin image (optional)
    if pin_img.size != (100, 100):
        pin_img = pin_img.resize((130, 130))
        final.paste(pin_img, (0, TARGET_HEIGHT - 130), pin_img)

    lvl = f"Lvl.{level}"
    bbox = draw.textbbox((0, 0), lvl, font=font_lvl)
    w = bbox[2] - bbox[0]
    h = bbox[3] - bbox[1]
    draw.rectangle(
        [final.width - w - 60, TARGET_HEIGHT - h - 50, final.width, TARGET_HEIGHT],
        fill="black"
    )
    draw.text(
        (final.width - w - 30, TARGET_HEIGHT - h - 40),
        lvl,
        font=font_lvl,
        fill="white"
    )

    out = io.BytesIO()
    final.save(out, "PNG")
    out.seek(0)
    return out


@app.route('/')
def home():
    return jsonify({"status": "FreeFire Banner API running", "endpoint": "/rizer?uid=UID"})

@app.route('/rizer')
def get_banner():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Missing uid parameter"}), 400


    region = uid_region_cache.get(uid)
    if region:
        try:
            data = get_account_information(uid, "7", region, "/GetPlayerPersonalShow")

            basic = data.get("basicInfo", {})
            profile = data.get("profileInfo", {})
            clan = data.get("clanBasicInfo", {})

            avatar_id = basic.get("headPic")      
            banner_id = basic.get("bannerId")

            pin_id = basic.get("pinId")

            avatar_bytes = fetch_image_bytes(avatar_id) if avatar_id else None
            banner_bytes = fetch_image_bytes(banner_id) if banner_id else None
            pin_bytes = fetch_image_bytes(pin_id) if pin_id else None

            img_io = process_banner_image(
                {
                    "AccountLevel": basic.get("level"),
                    "AccountName": basic.get("nickname"),
                    "GuildName": clan.get("clanName", "")
                },
                avatar_bytes, banner_bytes, pin_bytes
            )
            return Response(img_io.getvalue(), mimetype="image/png")
        except Exception as e:

            pass


    for reg in SUPPORTED_REGIONS:
        try:
            data = get_account_information(uid, "7", reg, "/GetPlayerPersonalShow")
            uid_region_cache[uid] = reg
            basic = data.get("basicInfo", {})
            profile = data.get("profileInfo", {})
            clan = data.get("clanBasicInfo", {})

            avatar_id = basic.get("headPic")
            banner_id = basic.get("bannerId")
            pin_id = basic.get("pinId")

            avatar_bytes = fetch_image_bytes(avatar_id) if avatar_id else None
            banner_bytes = fetch_image_bytes(banner_id) if banner_id else None
            pin_bytes = fetch_image_bytes(pin_id) if pin_id else None

            img_io = process_banner_image(
                {
                    "AccountLevel": basic.get("level"),
                    "AccountName": basic.get("nickname"),
                    "GuildName": clan.get("clanName", "")
                },
                avatar_bytes, banner_bytes, pin_bytes
            )
            return Response(img_io.getvalue(), mimetype="image/png")
        except Exception:
            continue

    return jsonify({"error": "UID not found in any region"}), 404

@app.route('/refresh-tokens', methods=['POST'])
def refresh_tokens():
    for region in SUPPORTED_REGIONS:
        create_jwt(region)
    return jsonify({"message": "Tokens refreshed for all regions"}), 200


def initialize_all_tokens():
    for region in SUPPORTED_REGIONS:
        try:
            create_jwt(region)
        except Exception as e:
            print(f"Failed to init token for {region}: {e}")

if __name__ == '__main__':
    initialize_all_tokens()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)