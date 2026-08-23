#ifndef POKERED_VERIFICATION_PORT_STATE_H
#define POKERED_VERIFICATION_PORT_STATE_H

typedef unsigned char port_u8;
typedef unsigned short port_u16;
typedef unsigned int port_u32;

enum port_flag {
	PORT_FLAG_C = 0x10,
	PORT_FLAG_H = 0x20,
	PORT_FLAG_N = 0x40,
	PORT_FLAG_Z = 0x80,
};

/*
 * Canonical live state for StringCmp. The flag byte uses the SM83 layout,
 * irrespective of the architecture used to compile the C implementation.
 */
struct string_cmp_state {
	port_u8 a;
	port_u8 f;
	port_u8 c;
	port_u8 reserved;
	port_u16 de;
	port_u16 hl;
};

struct accumulator_state {
	port_u8 a;
	port_u8 f;
};

struct binary_accumulator_state {
	port_u8 a;
	port_u8 f;
	port_u8 b;
	port_u8 reserved;
};

struct cpu_register_state {
	port_u8 a;
	port_u8 f;
	port_u8 b;
	port_u8 c;
	port_u8 d;
	port_u8 e;
	port_u8 h;
	port_u8 l;
};

struct script_reset_state {
	struct cpu_register_state registers;
	port_u8 joy_ignore;
	port_u8 current_script;
	port_u8 current_map_script;
};

struct zero_stores_state {
	struct cpu_register_state registers;
	port_u8 memory[4];
};

struct memory_predicate_state {
	struct cpu_register_state registers;
	port_u8 value;
};

struct memory_transfer_state {
	struct cpu_register_state registers;
	port_u8 memory[3];
};

struct misc_flags_state {
	struct cpu_register_state registers;
	port_u8 misc_flags;
};

struct empty_list_state {
	struct cpu_register_state registers;
	port_u8 first;
	port_u8 terminator;
};

struct stat_mod_reset_state {
	struct cpu_register_state registers;
	port_u8 modifiers[8];
};

struct clear_sprites_state {
	struct cpu_register_state registers;
	port_u8 oam[160];
};

struct pointer_store_state {
	struct cpu_register_state registers;
	port_u8 destination;
};

struct computed_load_state {
	struct cpu_register_state registers;
	port_u8 fetched;
};

struct indexed_load_state {
	struct cpu_register_state registers;
	port_u8 value;
	port_u8 fetched;
};

struct register_memory_state {
	struct cpu_register_state registers;
	port_u8 memory[8];
};

struct species_load_state {
	struct cpu_register_state registers;
	port_u8 data_location;
	port_u8 fetched;
	port_u8 species;
};

struct trainer_position_state {
	struct cpu_register_state registers;
	port_u8 sprite_offset;
	port_u8 fetched_y;
	port_u8 fetched_x;
	port_u8 screen_y;
	port_u8 screen_x;
};

struct trainer_sight_state {
	struct cpu_register_state registers;
	port_u8 engage_distance;
	port_u8 facing_direction;
	port_u8 screen_y;
	port_u8 screen_x;
};

struct sprite_anim_counter_state {
	struct cpu_register_state registers;
	port_u8 current_sprite_offset;
	port_u8 intra_frame_counter;
	port_u8 animation_frame_counter;
	port_u8 output_frame_counter;
};

struct blackout_map_state {
	struct cpu_register_state registers;
	port_u8 current_map;
	port_u8 last_map;
	port_u8 last_blackout_map;
	port_u8 fetched;
};

struct match_check_state {
	struct cpu_register_state registers;
	port_u8 de_value;
	port_u8 bc_value;
	port_u8 hl_value;
};

struct button_reset_state {
	struct cpu_register_state registers;
	port_u8 memory[5];
};

struct copy_string_step_state {
	struct cpu_register_state registers;
	port_u8 written;
};

struct slot_wheel_entry_state {
	struct cpu_register_state registers;
	port_u8 base_x;
};

struct auto_text_box_state {
	struct cpu_register_state registers;
	port_u8 auto_text_box_drawing_control;
	port_u8 do_not_wait_for_button_press;
};

struct init_options_state {
	struct cpu_register_state registers;
	port_u8 letter_printing_delay_flags;
	port_u8 options;
};

struct discard_buttons_state {
	struct cpu_register_state registers;
	port_u8 joy_held;
	port_u8 joy_pressed;
	port_u8 joy_released;
};

struct serial_counter_state {
	struct cpu_register_state registers;
	port_u8 counter_low;
	port_u8 counter_high;
};

struct yes_no_parameters_state {
	struct cpu_register_state registers;
	port_u8 two_option_menu_id;
};

struct reset_strength_state {
	struct cpu_register_state registers;
	port_u8 status_flags1;
};

struct teleport_delay_state {
	struct cpu_register_state registers;
	port_u8 on_sgb;
};

struct restore_facing_state {
	struct cpu_register_state registers;
	port_u8 saved_screen_y;
	port_u8 sprite_y_pixels;
	port_u8 saved_facing_direction;
	port_u8 sprite_image_index;
};

struct ignore_input_state {
	struct cpu_register_state registers;
	port_u8 ignore_input_counter;
	port_u8 status_flags5;
	port_u8 joy_pressed;
	port_u8 joy_held;
};

struct npc_movement_end_state {
	struct cpu_register_state registers;
	port_u8 status_flags5;
	port_u8 status_flags4;
	port_u8 movement_flags;
	port_u8 script_sprite_offset;
	port_u8 script_pointer_table_num;
	port_u8 script_function_num;
	port_u8 override_simulated_joypad_index;
	port_u8 simulated_joypad_index;
	port_u8 simulated_joypad_end;
};

struct coin_load_state {
	struct cpu_register_state registers;
	port_u8 which_prize;
	port_u8 unused_coins_byte;
	port_u8 coins_high;
	port_u8 coins_low;
	port_u8 fetched_high;
	port_u8 fetched_low;
};

struct vending_load_state {
	struct cpu_register_state registers;
	port_u8 current_menu_item;
	port_u8 item;
	port_u8 price[3];
	port_u8 fetched[4];
};

struct prize_level_state {
	struct cpu_register_state registers;
	port_u8 species;
	port_u8 enemy_level;
	port_u8 fetched_species;
	port_u8 fetched_level;
};

struct movement_direction_state {
	struct cpu_register_state registers;
	port_u8 fetched_direction;
	port_u8 fetched_mask;
};

struct init_list_state {
	struct cpu_register_state registers;
	port_u8 init_list_type;
	port_u8 name_list_type;
	port_u8 list_pointer[2];
	port_u8 unused_name_pointer[2];
	port_u8 item_prices[2];
};

struct machine_price_state {
	struct cpu_register_state registers;
	port_u8 current_item;
	port_u8 item_price[3];
	port_u8 fetched;
};

struct volatile_status_state {
	struct cpu_register_state registers;
	port_u8 memory[3];
};

struct target_substitute_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_status2;
	port_u8 enemy_status2;
};

struct title_ball_y_state {
	struct cpu_register_state registers;
	port_u8 output_y;
	port_u8 fetched;
};

struct random_state {
	struct cpu_register_state registers;
	port_u8 random_add;
	port_u8 random_sub;
	port_u8 div_first;
	port_u8 div_second;
};

struct scale_pixels_state {
	struct cpu_register_state registers;
	port_u8 written_first;
	port_u8 written_second;
};

struct sprite_sheet_data_state {
	struct cpu_register_state registers;
	port_u8 fetched[4];
};

struct text_box_coords_state {
	struct cpu_register_state registers;
	port_u8 fetched[4];
};

struct text_box_search_state {
	struct cpu_register_state registers;
	port_u8 fetched;
};

struct status_pp_state {
	struct cpu_register_state registers;
	port_u8 written[2];
};

struct trade_oam_step_state {
	struct cpu_register_state registers;
	port_u8 base_y;
	port_u8 base_x;
	port_u8 y;
	port_u8 x;
};

struct trade_oam_state {
	struct cpu_register_state registers;
	port_u8 base_y;
	port_u8 base_x;
	port_u8 oam[80];
};

struct copy_byte_step_state {
	struct cpu_register_state registers;
	port_u8 fetched;
	port_u8 written;
};

struct slot_machine_wheel_setup_state {
	struct cpu_register_state registers;
	port_u8 offset;
	port_u8 written;
};

struct menu_cursor_store_state {
	struct cpu_register_state registers;
	port_u8 cursor_low;
	port_u8 cursor_high;
	port_u8 destination;
};

struct rival_trainer_lookup_state {
	struct cpu_register_state registers;
	port_u8 starter;
	port_u8 fetched_key;
	port_u8 fetched_value;
	port_u8 trainer_no;
};

struct intro_nidorino_oam_state {
	struct cpu_register_state registers;
	port_u8 base_tile;
	port_u8 base_y;
	port_u8 base_x;
	port_u8 fetched_y;
	port_u8 fetched_x;
	port_u8 written_y;
	port_u8 written_x;
	port_u8 written_tile;
	port_u8 oam[1024];
};

struct pokeball_oam_state {
	struct cpu_register_state registers;
	port_u8 base_y;
	port_u8 base_x;
	port_u8 offset_x;
	port_u8 fetched_tile;
	port_u8 written_y;
	port_u8 written_x;
	port_u8 written_tile;
	port_u8 written_attributes;
	port_u8 buffer[6];
	port_u8 oam[24];
};

struct smoke_drift_state {
	struct cpu_register_state registers;
	port_u8 drift_amount;
	port_u8 fetched;
	port_u8 written;
	port_u8 saved_b;
	port_u8 saved_c;
	port_u8 saved_d;
	port_u8 saved_e;
	port_u8 oam[1024];
};

struct init_intro_oam_state {
	struct cpu_register_state registers;
	port_u8 base_y;
	port_u8 base_x;
	port_u8 written_y;
	port_u8 written_x;
	port_u8 written_tile;
	port_u8 written_attributes;
	port_u8 saved_b;
	port_u8 saved_c;
};

struct pick_pokeball_state {
	struct cpu_register_state registers;
	port_u8 hp_high;
	port_u8 hp_low;
	port_u8 status;
	port_u8 written;
};

struct asymmetric_oam_state {
	struct cpu_register_state registers;
	port_u8 base_tile;
	port_u8 output[16];
};

struct symmetric_oam_state {
	struct cpu_register_state registers;
	port_u8 base_tile;
	port_u8 attributes;
	port_u8 output[16];
};

struct hidden_index_state {
	struct cpu_register_state registers;
	port_u8 hidden_y;
	port_u8 hidden_x;
	port_u8 current_map;
	port_u8 fetched_map;
	port_u8 fetched_y;
	port_u8 fetched_x;
};

struct duplicate_scan_state {
	struct cpu_register_state registers;
	port_u8 fetched_outer;
	port_u8 fetched_inner;
	port_u8 written;
	port_u8 did_write;
};

struct town_map_entry_state {
	struct cpu_register_state registers;
	port_u8 fetched_compare;
	port_u8 fetched_coordinate;
	port_u8 fetched_name_low;
	port_u8 fetched_name_high;
	port_u8 written;
};

struct next_input_byte_state {
	struct cpu_register_state registers;
	port_u8 pointer_low;
	port_u8 pointer_high;
	port_u8 source;
};

struct slot_ball_tiles_state {
	struct cpu_register_state registers;
	port_u8 new_tile;
	port_u8 destination[4];
};

struct slot_ball_cascade_state {
	struct cpu_register_state registers;
	port_u8 new_tile;
	port_u8 bet;
	port_u8 destination[20];
};

struct bike_allowed_state {
	struct cpu_register_state registers;
	port_u8 current_map;
	port_u8 current_tileset;
	port_u8 fetched;
};

struct coords_front_match_state {
	struct cpu_register_state registers;
	port_u8 facing;
	port_u8 y;
	port_u8 x;
	port_u8 output;
};

struct tile_front_state {
	struct cpu_register_state registers;
	port_u8 y;
	port_u8 x;
	port_u8 facing;
	port_u8 tile_down;
	port_u8 tile_up;
	port_u8 tile_left;
	port_u8 tile_right;
	port_u8 output;
};

struct split_sprite_set_state {
	struct cpu_register_state registers;
	port_u8 direction;
	port_u8 dividing_line;
	port_u8 first_set;
	port_u8 second_set;
	port_u8 y;
	port_u8 x;
};

struct move_grammar_state {
	struct cpu_register_state registers;
	port_u8 grammar;
	port_u8 fetched;
	port_u8 saved_b;
	port_u8 saved_c;
};

struct ai_type_effectiveness_state {
	struct cpu_register_state registers;
	port_u8 enemy_move_type;
	port_u8 player_type_1;
	port_u8 player_type_2;
	port_u8 effectiveness;
	port_u8 fetched_attack_type;
	port_u8 fetched_defense_type;
	port_u8 fetched_multiplier;
};

struct one_hit_ko_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_speed_high;
	port_u8 player_speed_low;
	port_u8 enemy_speed_high;
	port_u8 enemy_speed_low;
	port_u8 damage_high;
	port_u8 damage_low;
	port_u8 critical_or_ohko;
	port_u8 move_missed;
};

struct tile_sprite_stands_on_state {
	struct cpu_register_state registers;
	port_u8 current_sprite_offset;
	port_u8 y_pixels;
	port_u8 x_pixels;
};

struct selected_stats_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_mask;
	port_u8 enemy_mask;
	port_u8 stat_high;
	port_u8 stat_low;
};

struct standing_on_warp_state {
	struct cpu_register_state registers;
	port_u8 number_of_warps;
	port_u8 y;
	port_u8 x;
	port_u8 destination_warp;
	port_u8 destination_map;
	port_u8 movement_flags;
	port_u8 fetched_y;
	port_u8 fetched_x;
	port_u8 fetched_warp;
	port_u8 fetched_map;
};

struct warp_pad_hole_state {
	struct cpu_register_state registers;
	port_u8 current_tileset;
	port_u8 coordinate_tile;
	port_u8 standing_value;
	port_u8 fetched_tileset;
	port_u8 fetched_tile;
	port_u8 fetched_value;
};

struct dust_animation_offsets_state {
	struct cpu_register_state registers;
	port_u8 y_pixels;
	port_u8 x_pixels;
	port_u8 direction;
	port_u8 which_offsets;
	port_u8 fetched_x_offset;
	port_u8 fetched_y_offset;
};

struct boulder_dust_pointer_state {
	struct cpu_register_state registers;
	port_u8 facing_direction;
	port_u8 coordinate_adjustment;
	port_u8 fetched_adjustment;
	port_u8 fetched_oam_offset;
	port_u8 fetched_pointer_low;
	port_u8 fetched_pointer_high;
};

struct sprite_screen_xy_state {
	struct cpu_register_state registers;
	port_u8 memory[6];
};

struct tile_two_steps_state {
	struct cpu_register_state registers;
	port_u8 y;
	port_u8 x;
	port_u8 facing;
	port_u8 tile_down;
	port_u8 tile_up;
	port_u8 tile_left;
	port_u8 tile_right;
	port_u8 player_facing_bits;
	port_u8 collision_result;
	port_u8 tile_in_front;
};

struct trainer_front_state {
	struct cpu_register_state registers;
	port_u8 current_map;
	port_u8 trainer_offset;
	port_u8 trainer_facing;
	port_u8 fetched_y;
	port_u8 fetched_x;
	port_u8 trainer_screen_y;
	port_u8 trainer_screen_x;
};

struct predef_pointer_state {
	struct cpu_register_state registers;
	port_u8 predef_id;
	port_u8 saved_h;
	port_u8 saved_l;
	port_u8 saved_d;
	port_u8 saved_e;
	port_u8 saved_b;
	port_u8 saved_c;
	port_u8 predef_bank;
	port_u8 fetched_bank;
	port_u8 fetched_pointer_low;
	port_u8 fetched_pointer_high;
};

struct init_sprite_screen_state {
	struct cpu_register_state registers;
	port_u8 current_offset;
	port_u8 player_y;
	port_u8 player_x;
	port_u8 map_y;
	port_u8 map_x;
	port_u8 screen_y;
	port_u8 screen_x;
};

struct sprite_facing_delay_state {
	struct cpu_register_state registers;
	port_u8 current_offset;
	port_u8 movement_delay;
	port_u8 facing_direction;
	port_u8 animation_frame;
	port_u8 intra_animation_frame;
	port_u8 image_index;
	port_u8 movement_status;
};

struct wavy_scx_state {
	struct cpu_register_state registers;
	port_u8 stat;
	port_u8 scx;
	port_u8 fetched_offset;
	port_u8 fetched_next;
};

struct scanline_scx_state {
	struct cpu_register_state registers;
	port_u8 ly;
	port_u8 scx;
};

struct menu_save_tiles_state {
	struct cpu_register_state registers;
	port_u8 fetched;
	port_u8 written;
};

struct option_cursor_state {
	struct cpu_register_state registers;
	port_u8 text_speed_cursor;
	port_u8 battle_animation_cursor;
	port_u8 battle_style_cursor;
	port_u8 options;
	port_u8 fetched_compare;
	port_u8 fetched_value;
};

struct copy_tile_ids_state {
	struct cpu_register_state registers;
	port_u8 base_tile;
	port_u8 auto_transfer;
	port_u8 fetched;
	port_u8 written;
	port_u8 saved_b;
	port_u8 saved_c;
	port_u8 saved_h;
	port_u8 saved_l;
	port_u8 original_h;
	port_u8 original_l;
	port_u8 whose_turn;
	port_u8 predef_h;
	port_u8 predef_l;
	port_u8 predef_d;
	port_u8 predef_e;
	port_u8 predef_b;
	port_u8 predef_c;
	port_u8 downscaled_size;
};

struct call_function_table_state {
	struct cpu_register_state registers;
	port_u8 fetched_low;
	port_u8 fetched_high;
	port_u8 saved_h;
	port_u8 saved_l;
	port_u8 saved_d;
	port_u8 saved_e;
	port_u8 saved_b;
	port_u8 saved_c;
};

struct update_sprite_image_state {
	struct cpu_register_state registers;
	port_u8 current_offset;
	port_u8 player_tile;
	port_u8 animation_frame;
	port_u8 facing_direction;
	port_u8 image_index;
};

struct status_ailment_text_state {
	struct cpu_register_state registers;
	port_u8 memory[4];
};

struct make_npc_face_state {
	struct cpu_register_state registers;
	port_u8 memory[9];
};

struct flag_action_state {
	struct cpu_register_state registers;
	port_u8 value;
};

struct box_sram_location_state {
	struct cpu_register_state registers;
	port_u8 current_box;
	port_u8 fetched_low;
	port_u8 fetched_high;
};

struct table_string_copy_state {
	struct cpu_register_state registers;
	port_u8 selector;
	port_u8 pointer_low;
	port_u8 pointer_high;
	port_u8 fetched;
	port_u8 written;
};

struct boost_exp_state {
	struct cpu_register_state registers;
	port_u8 quotient_high;
	port_u8 quotient_low;
};

struct init_sprite_status_state {
	struct cpu_register_state registers;
	port_u8 current_offset;
	port_u8 memory[4];
};

struct wake_party_state {
	struct cpu_register_state registers;
	port_u8 were_asleep;
	port_u8 fetched;
	port_u8 written;
	port_u8 statuses[6];
};

struct fill_memory_state {
	struct cpu_register_state registers;
	port_u8 saved_d;
	port_u8 saved_e;
	port_u8 written;
};

struct screen_coords_state {
	struct cpu_register_state registers;
	port_u8 saved_b;
	port_u8 saved_c;
};

struct serial_send_state {
	struct cpu_register_state registers;
	port_u8 send_data;
	port_u8 connection_status;
	port_u8 serial_control;
};

struct map_mon_state {
	struct cpu_register_state registers;
	port_u8 pokedex_num;
	port_u8 fetched;
	port_u8 written;
	port_u8 matched;
};

struct bit_count_state {
	struct cpu_register_state registers;
	port_u8 num_set_bits;
	port_u8 fetched;
};

struct divide_bytes_state {
	struct cpu_register_state registers;
	port_u8 dividend;
	port_u8 divisor;
	port_u8 quotient;
	port_u8 saved_h;
	port_u8 saved_l;
};

struct clear_screen_area_state {
	struct cpu_register_state registers;
	port_u8 saved_h;
	port_u8 saved_l;
	port_u8 saved_b;
	port_u8 saved_c;
	port_u8 written;
};

struct daycare_exp_state {
	struct cpu_register_state registers;
	port_u8 in_use;
	port_u8 exp_high;
	port_u8 exp_mid;
	port_u8 exp_low;
};

struct music_bank_state {
	struct cpu_register_state registers;
	port_u8 map_bank;
	port_u8 audio_bank;
	port_u8 saved_bank;
};

struct player_control_state {
	struct cpu_register_state registers;
	port_u8 npc_script;
	port_u8 movement_flags;
	port_u8 status_flags5;
};

struct event_bit_state {
	struct cpu_register_state registers;
	port_u8 source;
	port_u8 event_byte;
};

struct card_key_door_state {
	struct cpu_register_state registers;
	port_u8 card_y;
	port_u8 card_x;
	port_u8 unlocked;
	port_u8 fetched_y;
	port_u8 fetched_x;
};

struct elevator_warp_state {
	struct cpu_register_state registers;
	port_u8 source_warp;
	port_u8 source_map;
	port_u8 destinations[4];
};

struct gate_movement_state {
	struct cpu_register_state registers;
	port_u8 status_flags5;
	port_u8 joypad_end;
	port_u8 joypad_index;
	port_u8 movement_byte1;
	port_u8 override_mask;
};

struct ai_count_state {
	struct cpu_register_state registers;
	port_u8 ai_count;
};

struct checksum_result_state {
	struct cpu_register_state registers;
	port_u8 bank_mode;
	port_u8 ram_gate;
};

struct checksum_loop_state {
	struct cpu_register_state registers;
	port_u8 fetched;
};

struct low_health_alarm_state {
	struct cpu_register_state registers;
	port_u8 low_health_alarm;
	port_u8 channel5_sound_id;
	port_u8 low_health_alarm_disabled;
};

struct battle_attack_count_state {
	struct cpu_register_state registers;
	port_u8 player_attacks_left;
	port_u8 player_battle_status1;
	port_u8 enemy_attacks_left;
	port_u8 enemy_battle_status1;
};

struct hyper_beam_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_battle_status2;
	port_u8 enemy_battle_status2;
};

struct party_alive_state {
	struct cpu_register_state registers;
	port_u8 party_count;
	port_u8 party_hp[12];
};

struct transition_opponent_state {
	struct cpu_register_state registers;
	port_u8 current_opponent;
};

struct transition_dungeon_state {
	struct cpu_register_state registers;
	port_u8 current_map;
};

struct black_screen_state {
	struct cpu_register_state registers;
	port_u8 background_palette;
	port_u8 object_palette0;
	port_u8 object_palette1;
};

struct transition_level_state {
	struct cpu_register_state registers;
	port_u8 party_hp[12];
	port_u8 party_levels[6];
	port_u8 enemy_level;
	port_u8 spiral_direction;
};

struct status_penalty_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_status;
	port_u8 enemy_status;
	port_u8 player_stat_high;
	port_u8 player_stat_low;
	port_u8 enemy_stat_high;
	port_u8 enemy_stat_low;
};

struct combined_penalty_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_status;
	port_u8 enemy_status;
	port_u8 player_speed_high;
	port_u8 player_speed_low;
	port_u8 enemy_speed_high;
	port_u8 enemy_speed_low;
	port_u8 player_attack_high;
	port_u8 player_attack_low;
	port_u8 enemy_attack_high;
	port_u8 enemy_attack_low;
};

struct slide_player_head_state {
	struct cpu_register_state registers;
	port_u8 x_coordinates[21];
};

struct swap_levels_state {
	struct cpu_register_state registers;
	port_u8 player_level;
	port_u8 enemy_level;
};

struct subanimation_transform_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
};

struct cry_move_state {
	struct cpu_register_state registers;
	port_u8 animation_id;
};

struct anim_copy_row_state {
	struct cpu_register_state registers;
	port_u8 tiles[8];
};

struct animation_palette_state {
	struct cpu_register_state registers;
	port_u8 on_sgb;
	port_u8 animation_palette;
	port_u8 animation_id;
	port_u8 object_palette0;
	port_u8 object_palette1;
};

struct falling_object_movement_state {
	struct cpu_register_state registers;
	port_u8 movement_byte;
};

struct share_move_animation_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 animation_id;
};

struct call_with_turn_flipped_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 saved_a;
	port_u8 saved_f;
};

struct applying_attack_animation_state {
	struct cpu_register_state registers;
	port_u8 animation_type;
	port_u8 fetched_low;
	port_u8 fetched_high;
	port_u8 dispatched;
};

struct music_low_health_alarm_state {
	struct cpu_register_state registers;
	port_u8 low_health_alarm;
	port_u8 channel5_sound_id;
	port_u8 audio1_registers[5];
};

struct jump_move_effect_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_move_effect;
	port_u8 enemy_move_effect;
	port_u8 fetched_low;
	port_u8 fetched_high;
	port_u8 dispatched;
};

struct init_battle_dispatch_state {
	struct cpu_register_state registers;
	port_u8 current_opponent;
	port_u8 current_party_species;
	port_u8 enemy_species2;
	port_u8 destination;
};

struct print_type_state {
	struct cpu_register_state registers;
	port_u8 fetched_low;
	port_u8 fetched_high;
	port_u8 saved_h;
	port_u8 saved_l;
	port_u8 dispatched;
};

struct default_music_fade_state {
	struct cpu_register_state registers;
	port_u8 status_flags4;
	port_u8 last_music_sound_id;
	port_u8 dispatched;
	port_u8 low_health_alarm;
	port_u8 channel_sound_ids[3];
};

struct play_music_state {
	struct cpu_register_state registers;
	port_u8 new_sound_id;
	port_u8 fade_out_control;
	port_u8 audio_rom_bank;
	port_u8 saved_audio_rom_bank;
	port_u8 dispatched;
};

struct bankswitch_state {
	struct cpu_register_state registers;
	port_u8 loaded_rom_bank;
	port_u8 mapper_bank;
	port_u8 saved_a;
	port_u8 saved_f;
};

struct far_copy_double_state {
	struct cpu_register_state registers;
	port_u8 rom_bank_temp;
	port_u8 loaded_rom_bank;
	port_u8 mapper_bank;
	port_u8 saved_a;
	port_u8 saved_f;
	port_u8 memory[3];
};

struct load_gb_pal_state {
	struct cpu_register_state registers;
	port_u8 map_pal_offset;
	port_u8 fetched[3];
	port_u8 background_palette;
	port_u8 object_palette0;
	port_u8 object_palette1;
};

struct down_arrow_blink_state {
	struct cpu_register_state registers;
	port_u8 tile;
	port_u8 blink_count1;
	port_u8 blink_count2;
};

struct dma_code_copy_state {
	struct cpu_register_state registers;
	port_u8 hram[10];
};

struct dma_routine_state {
	struct cpu_register_state registers;
	port_u8 dma_register;
};

struct read_joypad_state {
	struct cpu_register_state registers;
	port_u8 direction_read;
	port_u8 button_read;
	port_u8 joypad_register;
	port_u8 joy_input;
};

struct disable_lcd_state {
	struct cpu_register_state registers;
	port_u8 interrupt_flags;
	port_u8 interrupt_enable;
	port_u8 lcd_control;
};

struct print_level_state {
	struct cpu_register_state registers;
	port_u8 loaded_level;
	port_u8 destination_tile;
	port_u8 temp_byte;
	port_u8 dispatched;
};

struct print_status_condition_state {
	struct cpu_register_state registers;
	port_u8 hp_high;
	port_u8 hp_low;
	port_u8 destination_tiles[3];
	port_u8 dispatched;
};

struct check_coords_state {
	struct cpu_register_state registers;
	port_u8 coord_index;
	port_u8 fetched_y;
	port_u8 fetched_x;
};

struct safari_zone_check_state {
	struct cpu_register_state registers;
	port_u8 event_flags;
	port_u8 safari_balls;
	port_u8 destination;
};

struct mansion_block_loader_state {
	struct cpu_register_state registers;
	port_u8 new_tile_block_id;
	port_u8 dispatched;
};

struct vermilion_ss_anne_state {
	struct cpu_register_state registers;
	port_u8 event_flags;
	port_u8 current_script;
};

struct victory_road_reset_state {
	struct cpu_register_state registers;
	port_u8 event_flags;
	port_u8 dispatched;
};

struct current_move_animation_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_move;
	port_u8 enemy_move;
	port_u8 animation_id;
	port_u8 animation_type;
	port_u8 dispatched;
};

struct uncompressed_pic_copy_state {
	struct cpu_register_state registers;
	port_u8 sprite_flipped;
	port_u8 predef_h;
	port_u8 predef_l;
	port_u8 start_tile_id;
	port_u8 writes[49];
};

struct slot_winning_symbol_state {
	struct cpu_register_state registers;
	port_u8 winning_symbol;
	port_u8 writes[5];
};

struct draw_line_box_state {
	struct cpu_register_state registers;
	port_u8 written;
};

struct cant_lower_pop_state {
	struct cpu_register_state registers;
	port_u8 popped_d;
	port_u8 popped_e;
	port_u8 popped_h;
	port_u8 popped_l;
	port_u8 pointed_value;
	port_u8 dispatched;
};

struct trade_circled_mon_state {
	struct cpu_register_state registers;
	port_u8 background_palette;
	port_u8 tile_ids[20];
};

struct force_party_anim_speed_state {
	struct cpu_register_state registers;
	port_u8 current_menu_item;
	port_u8 dispatched;
};

struct mon_party_gfx_entry_state {
	struct cpu_register_state registers;
	port_u8 dispatched;
};

struct show_object_state {
	struct cpu_register_state registers;
	port_u8 toggleable_object_index;
	port_u8 stage;
};

struct sgb_border_copy_state {
	struct cpu_register_state registers;
	port_u8 fetched;
	port_u8 written;
};

struct init_cgb_palettes_state {
	struct cpu_register_state registers;
	port_u8 background_palette_index;
	port_u8 background_palette_data;
	port_u8 fetched_index;
	port_u8 fetched_palette;
};

struct determine_palette_id_state {
	struct cpu_register_state registers;
	port_u8 fetched_species;
	port_u8 pokedex_num;
	port_u8 fetched_palette;
	port_u8 dispatched;
};

struct player_name_sram_state {
	struct cpu_register_state registers;
	port_u8 ram_enable;
	port_u8 bank_mode;
	port_u8 ram_bank;
	port_u8 name[11];
};

struct serial_exchange_nybble_state {
	struct cpu_register_state registers;
	port_u8 send_data;
	port_u8 temp_receive_data;
	port_u8 receive_data;
	port_u8 connection_status;
	port_u8 serial_send_data;
	port_u8 serial_receive_data;
	port_u8 serial_control;
};

struct wait_for_sound_state {
	struct cpu_register_state registers;
	port_u8 low_health_alarm;
	port_u8 channel_sound_ids[3];
};

struct play_sound_state {
	struct cpu_register_state registers;
	port_u8 new_sound_id;
	port_u8 audio_rom_bank;
	port_u8 fade_control;
	port_u8 fade_reload;
	port_u8 fade_counter;
	port_u8 last_music_sound_id;
	port_u8 channel_sound_ids[4];
	port_u8 saved_rom_bank;
	port_u8 loaded_rom_bank;
	port_u8 rom_bank;
	port_u8 dispatch_called;
	port_u8 low_health_alarm;
	port_u8 audio_saved_rom_bank;
};

struct fade_out_audio_state {
	struct play_sound_state sound;
	port_u8 status_flags2;
	port_u8 audio_volume;
};

struct align_sprite_data_state {
	struct cpu_register_state registers;
	port_u8 sprite_offset;
	port_u8 sprite_width;
	port_u8 sprite_height;
	port_u8 fetched;
	port_u8 written;
	port_u8 saved_a;
	port_u8 saved_f;
	port_u8 saved_h;
	port_u8 saved_l;
};

struct write_oam_block_state {
	struct cpu_register_state registers;
	port_u8 source[8];
	port_u8 oam[16];
};

struct sprite_movement_delay_state {
	struct cpu_register_state registers;
	port_u8 current_offset;
	port_u8 movement_byte;
	port_u8 movement_delay;
	port_u8 movement_status;
	port_u8 animation_frame;
	port_u8 dispatched;
};

struct exploding_animation_state {
	struct cpu_register_state registers;
	port_u8 whose_turn;
	port_u8 player_move;
	port_u8 enemy_move;
	port_u8 enemy_type1;
	port_u8 enemy_type2;
	port_u8 player_type1;
	port_u8 player_type2;
	port_u8 enemy_status1;
	port_u8 move_missed;
	port_u8 animation_type;
	port_u8 dispatched;
};

struct restore_stat_modifier_state {
	struct cpu_register_state registers;
	port_u8 popped_h;
	port_u8 popped_l;
	port_u8 pointed_value;
	port_u8 dispatched;
};

struct trainer_pic_column_state {
	struct cpu_register_state registers;
	port_u8 writes[7];
};

struct stat_write_entry_state {
	struct cpu_register_state registers;
	port_u8 product_high;
	port_u8 product_low;
	port_u8 written_high;
	port_u8 written_low;
	port_u8 popped_d;
	port_u8 popped_e;
	port_u8 popped_h;
	port_u8 popped_l;
	port_u8 dispatched;
};

struct tile_pair_entry_state {
	struct cpu_register_state registers;
	port_u8 fetched_tile;
	port_u8 standing_tile;
	port_u8 dispatched;
};

struct battle_enemy_parameters_state {
	struct cpu_register_state registers;
	port_u8 engaged_class;
	port_u8 engaged_set;
	port_u8 current_opponent;
	port_u8 enemy_class;
	port_u8 trainer_number;
	port_u8 enemy_level;
};

struct column_redraw_copy_state {
	struct cpu_register_state registers;
	port_u8 reads[36];
	port_u8 writes[36];
};

struct load_item_list_state {
	struct cpu_register_state registers;
	port_u8 update_sprites_enabled;
	port_u8 item_list_pointer[2];
	port_u8 fetched;
	port_u8 written;
};

struct trainer_header_info_state {
	struct cpu_register_state registers;
	port_u8 header_high;
	port_u8 header_low;
	port_u8 flag_bit;
	port_u8 fetched_first;
	port_u8 fetched_second;
};

struct multiply_state {
	struct cpu_register_state registers;
	port_u8 product[4];
	port_u8 multiplier;
	port_u8 buffer[4];
};

struct divide_bcd_by10_state {
	struct cpu_register_state registers;
	port_u8 divisor[3];
};

struct sub_bcd_state {
	struct cpu_register_state registers;
	port_u8 fetched_left;
	port_u8 fetched_right;
	port_u8 written;
};

struct divide_state {
	struct cpu_register_state registers;
	port_u8 dividend[4];
	port_u8 divisor;
	port_u8 buffer[5];
};

struct differential_decode_state {
	struct cpu_register_state registers;
	port_u8 flipped;
	port_u8 table0_low;
	port_u8 table0_high;
	port_u8 table1_low;
	port_u8 table1_high;
	port_u8 fetched;
};

struct write_sprite_bits_state {
	struct cpu_register_state registers;
	port_u8 bit_offset;
	port_u8 pointer_low;
	port_u8 pointer_high;
	port_u8 pointed_byte;
};

struct remove_inventory_state {
	struct cpu_register_state registers;
	port_u8 which_item;
	port_u8 item_quantity;
	port_u8 max_item_quantity;
	port_u8 current_quantity;
	port_u8 fetched_next;
	port_u8 written;
	port_u8 list_scroll_offset;
	port_u8 current_menu_item;
	port_u8 bag_saved_menu_item;
	port_u8 saved_list_scroll_offset;
	port_u8 inventory_count;
	port_u8 list_count;
	port_u8 max_menu_item;
	port_u8 saved_h;
	port_u8 saved_l;
};

struct slot_wheel_match_state {
	struct cpu_register_state registers;
	port_u8 wheel1[3];
	port_u8 wheel2[3];
};

struct add_inventory_state {
	struct cpu_register_state registers;
	port_u8 cur_item;
	port_u8 item_quantity;
	port_u8 inventory_count;
	port_u8 fetched_item;
	port_u8 fetched_marker;
	port_u8 existing_quantity;
	port_u8 count_written;
	port_u8 item_written;
	port_u8 quantity_written;
	port_u8 terminator_written;
	port_u8 quantity_write_valid;
	port_u8 add_write_valid;
	port_u8 saved_a;
	port_u8 saved_f;
	port_u8 saved_b;
	port_u8 saved_c;
	port_u8 saved_d;
	port_u8 saved_e;
	port_u8 saved_h;
	port_u8 saved_l;
};

struct delay_frame_state {
	struct cpu_register_state registers;
	port_u8 vblank_occurred;
	port_u8 observed_vblank;
};

struct flash_screen_long_delay_state {
	struct cpu_register_state registers;
	port_u8 counter;
	port_u8 frames_waited;
};

struct trade_delay_state {
	struct cpu_register_state registers;
	port_u8 frames_waited;
};

struct connection_tilemap_state {
	struct cpu_register_state registers;
	port_u8 strip_width;
	port_u8 north_south_width;
	port_u8 east_west_width;
	port_u8 map_width;
	port_u8 fetched;
	port_u8 written;
	port_u8 saved_d;
	port_u8 saved_e;
	port_u8 saved_h;
	port_u8 saved_l;
};

struct boulder_sprite_collision_state {
	struct cpu_register_state registers;
	port_u8 boulder_index;
	port_u8 boulder_y;
	port_u8 boulder_x;
	port_u8 num_sprites;
	port_u8 facing;
	port_u8 player_y;
	port_u8 player_x;
	port_u8 sprite_y;
	port_u8 sprite_x;
};

struct sprite_in_front_state {
	struct cpu_register_state registers;
	port_u8 facing_direction;
	port_u8 player_direction;
	port_u8 num_sprites;
	port_u8 sprite_image;
	port_u8 sprite_visibility;
	port_u8 sprite_y;
	port_u8 sprite_x;
	port_u8 movement_status;
	port_u8 text_id;
};

struct outward_spiral_step_state {
	struct cpu_register_state registers;
	port_u8 pointer_high;
	port_u8 pointer_low;
	port_u8 direction;
	port_u8 probed;
	port_u8 written;
	port_u8 write_h;
	port_u8 write_l;
};

struct circle_transition_state {
	struct cpu_register_state registers;
	port_u8 quadrant_y;
	port_u8 quadrant_x;
	port_u8 fetched;
	port_u8 written;
	port_u8 write_h;
	port_u8 write_l;
	port_u8 saved_h;
	port_u8 saved_l;
};

struct tile_pair_collision_state {
	struct cpu_register_state registers;
	port_u8 front_tile;
	port_u8 current_tileset;
	port_u8 standing_tile;
	port_u8 entry_tileset;
	port_u8 first_tile;
	port_u8 second_tile;
};

struct fly_locations_state {
	struct cpu_register_state registers;
	port_u8 visited_low;
	port_u8 visited_high;
	port_u8 written;
	port_u8 write_h;
	port_u8 write_l;
};

struct moving_bg_tiles_state {
	struct cpu_register_state registers;
	port_u8 tile_animations;
	port_u8 counter1;
	port_u8 counter2;
	port_u8 left;
	port_u8 fetched;
	port_u8 written;
	port_u8 write_h;
	port_u8 write_l;
};

struct vblank_copy_bg_state {
	struct cpu_register_state registers;
	port_u8 sp_high;
	port_u8 sp_low;
	port_u8 temp_high;
	port_u8 temp_low;
	port_u8 source_low;
	port_u8 source_high;
	port_u8 dest_low;
	port_u8 dest_high;
	port_u8 num_rows;
	port_u8 source_bytes[20];
	port_u8 written[20];
	port_u8 write_h[20];
	port_u8 write_l[20];
};

struct vblank_copy_double_state {
	struct cpu_register_state registers;
	port_u8 sp_high;
	port_u8 sp_low;
	port_u8 temp_high;
	port_u8 temp_low;
	port_u8 source_low;
	port_u8 source_high;
	port_u8 dest_low;
	port_u8 dest_high;
	port_u8 size;
	port_u8 source_bytes[8];
	port_u8 written[16];
	port_u8 write_h[16];
	port_u8 write_l[16];
};

struct vblank_copy_state {
	struct cpu_register_state registers;
	port_u8 sp_high;
	port_u8 sp_low;
	port_u8 temp_high;
	port_u8 temp_low;
	port_u8 source_low;
	port_u8 source_high;
	port_u8 dest_low;
	port_u8 dest_high;
	port_u8 size;
	port_u8 source_bytes[16];
	port_u8 written[16];
	port_u8 write_h[16];
	port_u8 write_l[16];
};

struct auto_bg_transfer_state {
	struct cpu_register_state registers;
	port_u8 sp_high;
	port_u8 sp_low;
	port_u8 temp_high;
	port_u8 temp_low;
	port_u8 enabled;
	port_u8 portion;
	port_u8 dest_low;
	port_u8 dest_high;
	port_u8 source_bytes[20];
	port_u8 written[20];
	port_u8 write_h[20];
	port_u8 write_l[20];
};

struct redraw_row_column_state {
	struct cpu_register_state registers;
	port_u8 mode;
	port_u8 dest_low;
	port_u8 dest_high;
	port_u8 fetched0;
	port_u8 fetched1;
	port_u8 written0;
	port_u8 written1;
	port_u8 write_h0;
	port_u8 write_l0;
	port_u8 write_h1;
	port_u8 write_l1;
	port_u8 saved_d;
	port_u8 saved_e;
};

struct interrupt_return_state {
	struct cpu_register_state registers;
	port_u8 sp_high;
	port_u8 sp_low;
	port_u8 return_low;
	port_u8 return_high;
	port_u8 ime;
};

struct draw_tile_block_state {
	struct cpu_register_state registers;
	port_u8 blocks_low;
	port_u8 blocks_high;
	port_u8 fetched[4];
	port_u8 written[4];
	port_u8 write_h[4];
	port_u8 write_l[4];
	port_u8 saved_h;
	port_u8 saved_l;
};

struct replace_tree_block_state {
	struct cpu_register_state registers;
	port_u8 map_width;
	port_u8 map_pointer_low;
	port_u8 map_pointer_high;
	port_u8 facing;
	port_u8 x_block;
	port_u8 y_block;
	port_u8 target_tile;
	port_u8 fetched_match;
	port_u8 replacement;
	port_u8 written;
	port_u8 write_h;
	port_u8 write_l;
};

struct transition_copy_tiles2_state {
	struct cpu_register_state registers;
	port_u8 offset_low;
	port_u8 offset_high;
	port_u8 fetched;
	port_u8 written;
	port_u8 write_h;
	port_u8 write_l;
	port_u8 saved_b;
	port_u8 saved_c;
	port_u8 saved_h;
	port_u8 saved_l;
	port_u8 saved_d;
	port_u8 saved_e;
};

struct badge_stat_boost_state {
	struct cpu_register_state registers;
	port_u8 link_state;
	port_u8 badges;
	port_u8 stat_high;
	port_u8 stat_low;
};

struct draw_hp_bar_state {
	struct cpu_register_state registers;
	port_u8 hp_bar_type;
	port_u8 written0;
	port_u8 written1;
	port_u8 write_h;
	port_u8 write_l;
	port_u8 saved_b;
	port_u8 saved_c;
	port_u8 saved_d;
	port_u8 saved_e;
	port_u8 saved_h;
	port_u8 saved_l;
};

struct pewter_guys_state {
	struct cpu_register_state registers;
	port_u8 joypad_index;
	port_u8 which_guy;
	port_u8 y_coord;
	port_u8 x_coord;
	port_u8 entry_y;
	port_u8 entry_x;
	port_u8 entry_low;
	port_u8 entry_high;
	port_u8 movement;
	port_u8 written;
	port_u8 write_h;
	port_u8 write_l;
};

struct text_box_border_state {
	struct cpu_register_state registers;
	port_u8 written;
	port_u8 write_h;
	port_u8 write_l;
	port_u8 saved_h;
	port_u8 saved_l;
};

struct animate_party_mon_state {
	struct cpu_register_state registers;
	port_u8 current_menu_item;
	port_u8 on_sgb;
	port_u8 anim_counter;
	port_u8 hp_color;
	port_u8 speed_value;
	port_u8 fetched;
	port_u8 written;
	port_u8 write_h;
	port_u8 write_l;
	port_u8 saved_b;
	port_u8 saved_c;
	port_u8 delay_dispatched;
};

struct place_menu_cursor_state {
	struct cpu_register_state registers;
	port_u8 top_y;
	port_u8 top_x;
	port_u8 last_item;
	port_u8 current_item;
	port_u8 layout_flags;
	port_u8 tile_behind;
	port_u8 fetched;
	port_u8 written;
	port_u8 write_h;
	port_u8 write_l;
	port_u8 cursor_low;
	port_u8 cursor_high;
	port_u8 saved_h;
	port_u8 saved_l;
};

struct serial_interrupt_state {
	struct cpu_register_state registers;
	port_u8 connection_status;
	port_u8 serial_data;
	port_u8 receive_data;
	port_u8 send_data;
	port_u8 serial_control;
	port_u8 divider;
	port_u8 observed_divider;
	port_u8 received_new_data;
	struct cpu_register_state saved_registers;
};

struct special_warp_state {
	struct cpu_register_state registers;
	port_u8 cable_destination;
	port_u8 serial_status;
	port_u8 status6;
	port_u8 status3;
	port_u8 last_map;
	port_u8 last_blackout_map;
	port_u8 destination_map;
	port_u8 dungeon_destination;
	port_u8 which_dungeon_warp;
	port_u8 dungeon_entry_size;
	port_u8 current_map;
	port_u8 current_tileset;
	port_u8 y_offset;
	port_u8 x_offset;
	port_u8 destination_warp_id;
	port_u8 fetched0;
	port_u8 fetched1;
	port_u8 written;
	port_u8 write_h;
	port_u8 write_l;
};

struct trainer_move_choice_state {
	struct cpu_register_state registers;
	port_u8 disabled_move;
	port_u8 trainer_class;
	port_u8 modification;
	port_u8 fetched_move;
	port_u8 fetched_score;
	port_u8 written;
	port_u8 write_h;
	port_u8 write_l;
	port_u8 buffer[4];
	port_u8 enemy_moves[4];
	port_u8 saved_h;
	port_u8 saved_l;
	port_u8 dispatched;
	port_u8 battle_mon_status;
	port_u8 layer2_encouragement;
	port_u8 move_powers[4];
	port_u8 move_effects[4];
	port_u8 move_types[4];
	port_u8 type_effectivenesses[4];
	port_u8 read_move_called;
	port_u8 effectiveness_called;
};

struct trainer_ai_mod_state {
	struct cpu_register_state registers;
	port_u8 battle_mon_status;
	port_u8 layer2_encouragement;
	port_u8 move;
	port_u8 move_power;
	port_u8 move_effect;
	port_u8 type_effectiveness;
	port_u8 enemy_move_type;
	port_u8 score;
	port_u8 written;
	port_u8 write_h;
	port_u8 write_l;
	port_u8 read_move_called;
	port_u8 effectiveness_called;
	port_u8 moves[4];
	port_u8 move_powers[4];
	port_u8 move_effects[4];
	port_u8 move_types[4];
	port_u8 type_effectivenesses[4];
	port_u8 scores[4];
};

struct print_number_state {
	struct cpu_register_state registers;
	port_u8 past_leading_zeroes;
	port_u8 number[3];
	port_u8 power[3];
	port_u8 saved_number[3];
	port_u8 source[3];
	port_u8 written;
	port_u8 did_write;
	port_u8 write_h;
	port_u8 write_l;
	port_u8 saved_b;
	port_u8 saved_c;
	port_u8 saved_d;
	port_u8 saved_e;
};

struct evolution_after_battle_state {
	struct cpu_register_state registers;
	port_u8 tile_animations;
	port_u8 evolution_occurred;
	port_u8 which_pokemon;
	port_u8 party_species;
	port_u8 evo_old_species;
	port_u8 can_evolve;
	port_u8 link_state;
	port_u8 force_evolution;
	port_u8 loaded_mon_level;
	port_u8 evolution_type;
	port_u8 requirement;
	port_u8 level_requirement;
	port_u8 cur_item;
	port_u8 is_in_battle;
	port_u8 music_called;
	port_u8 cur_enemy_level;
	port_u8 evo_new_species;
	port_u8 fetched_species;
	port_u8 saved_entry_h;
	port_u8 saved_entry_l;
	port_u8 old_max_hp_high;
	port_u8 old_max_hp_low;
	port_u8 loaded_max_hp_high;
	port_u8 loaded_max_hp_low;
	port_u8 loaded_hp_high;
	port_u8 loaded_hp_low;
	port_u8 saved_copy_b;
	port_u8 saved_copy_c;
	struct cpu_register_state saved_registers;
	port_u8 evolution_cancelled;
	port_u8 auto_bg_transfer_enabled;
	port_u8 update_sprites_enabled;
	port_u8 cur_species;
	port_u8 loaded_mon_species;
	port_u8 name_list_type;
	port_u8 predef_bank;
	port_u8 pokedex_num;
	port_u8 mon_h_index;
	port_u8 mon_data_location;
	port_u8 party_species_write;
	port_u8 is_evolving_text_called;
	port_u8 evolved_text_called;
	port_u8 stopped_text_called;
	port_u8 into_text_called;
	port_u8 evolve_mon_called;
	port_u8 clear_screen_called;
	port_u8 clear_sprites_called;
	port_u8 rename_called;
	port_u8 calc_stats_called;
	port_u8 learn_move_called;
	port_u8 set_types_called;
	port_u8 reload_called;
	port_u8 owned_flag_called;
	port_u8 seen_flag_called;
	port_u8 saved_pokedex_num;
	port_u8 saved_pokedex_f;
	port_u8 saved_party_struct_h;
	port_u8 saved_party_struct_l;
	port_u8 copied_party_end_h;
	port_u8 copied_party_end_l;
	port_u8 saved_party_list_h;
	port_u8 saved_party_list_l;
	port_u8 index_to_pokedex_called;
	port_u8 copy_header_called;
	port_u8 copy_party_called;
};

struct evolution_reload_tileset_state {
	struct cpu_register_state registers;
	port_u8 link_state;
	port_u8 reload_called;
};

struct rename_evolved_mon_state {
	struct cpu_register_state registers;
	port_u8 cur_species;
	port_u8 mon_h_index;
	port_u8 name_list_index;
	port_u8 which_pokemon;
	port_u8 candidate_char;
	port_u8 standard_char;
	port_u8 saved_a;
	port_u8 saved_f;
	port_u8 loaded_rom_bank;
	port_u8 get_name_called;
	port_u8 copy_called;
	port_u8 copy_source_h;
	port_u8 copy_source_l;
	port_u8 copy_destination_h;
	port_u8 copy_destination_l;
	port_u8 candidate_name[11];
	port_u8 old_standard_name[11];
};

struct falling_x_init_state {
	struct cpu_register_state registers;
	port_u8 num_objects;
	port_u8 oam[80];
};

struct falling_movement_init_state {
	struct cpu_register_state registers;
	port_u8 num_objects;
	port_u8 movement[20];
};

struct falling_oam_update_state {
	struct cpu_register_state registers;
	port_u8 movement_byte;
	port_u8 oam_entry[4];
};

struct adjust_oam_block_state {
	struct cpu_register_state registers;
	port_u8 adjustment;
	port_u8 oam[16];
};

struct battle_anim_oam_entry_state {
	struct cpu_register_state registers;
	port_u8 base_x;
	port_u8 oam_entry[4];
};

struct audio_is_cry_state {
	struct cpu_register_state registers;
	port_u8 channel5_sound_id;
};

struct audio_battle_sfx_state {
	struct cpu_register_state registers;
	port_u8 channel5_sound_id;
	port_u8 channel8_sound_id;
};

struct audio_channel_output_state {
	struct cpu_register_state registers;
	port_u8 audio_terminal;
	port_u8 stereo_panning;
	port_u8 sfx_sound_ids[4];
};

struct audio_duty_pattern_state {
	struct cpu_register_state registers;
	port_u8 duty_patterns[8];
	port_u8 hardware_duty_registers[4];
};

struct audio_duty_length_state {
	struct cpu_register_state registers;
	port_u8 note_delays[8];
	port_u8 duty_cycles[8];
	port_u8 hardware_duty_registers[4];
};

struct audio_cry_modifiers_state {
	struct cpu_register_state registers;
	port_u8 low_health_alarm;
	port_u8 frequency_modifier;
	port_u8 tempo_modifier;
};

struct audio_sfx_tempo_state {
	struct cpu_register_state registers;
	port_u8 channel5_sound_id;
	port_u8 channel8_sound_id;
	port_u8 tempo_modifier;
	port_u8 sfx_tempo_high;
	port_u8 sfx_tempo_low;
};

struct audio_frequency_modifier_state {
	struct cpu_register_state registers;
	port_u8 channel5_sound_id;
	port_u8 channel8_sound_id;
	port_u8 frequency_modifier;
	port_u8 hardware_frequency_registers[8];
};

struct audio_wave_frequency_state {
	struct cpu_register_state registers;
	port_u8 music_wave_instrument;
	port_u8 sfx_wave_instrument;
	port_u8 channel5_sound_id;
	port_u8 channel8_sound_id;
	port_u8 frequency_modifier;
	port_u8 audio3_enable;
	port_u8 wave_ram[16];
	port_u8 hardware_frequency_registers[8];
};

struct audio_command_rewind_state {
	struct cpu_register_state registers;
	port_u8 channel5_sound_id;
	port_u8 command_pointers[16];
};

struct audio_next_music_byte_state {
	struct cpu_register_state registers;
	port_u8 command_pointers[16];
	port_u8 command_byte;
};

struct audio_pitch_slide_state {
	struct cpu_register_state registers;
	port_u8 flags1[8];
	port_u8 frequency_steps[8];
	port_u8 frequency_steps_fractional[8];
	port_u8 current_frequency_fractional[8];
	port_u8 current_frequency_high[8];
	port_u8 current_frequency_low[8];
	port_u8 target_frequency_high[8];
	port_u8 target_frequency_low[8];
	port_u8 hardware_frequency_registers[8];
};

struct audio_init_pitch_slide_state {
	struct cpu_register_state registers;
	port_u8 flags1[8];
	port_u8 note_delays[8];
	port_u8 length_modifiers[8];
	port_u8 frequency_steps[8];
	port_u8 frequency_steps_fractional[8];
	port_u8 current_frequency_fractional[8];
	port_u8 current_frequency_high[8];
	port_u8 current_frequency_low[8];
	port_u8 target_frequency_high[8];
	port_u8 target_frequency_low[8];
};

enum audio_handler_continuation {
	AUDIO_CONTINUE_SOUND_RET = 1,
	AUDIO_CONTINUE_OCTAVE = 2,
	AUDIO_CONTINUE_SFX_NOTE = 3,
	AUDIO_CONTINUE_TEMPO = 4,
	AUDIO_CONTINUE_UNKNOWN_EF = 5,
	AUDIO_CONTINUE_EXECUTE_MUSIC = 6,
	AUDIO_CONTINUE_VOLUME = 7,
	AUDIO_CONTINUE_VIBRATO = 8,
	AUDIO_CONTINUE_STEREO_PANNING = 9,
	AUDIO_CONTINUE_PITCH_SLIDE = 10,
	AUDIO_CONTINUE_NOTE = 11,
	AUDIO_CONTINUE_DUTY_CYCLE = 12,
	AUDIO_CONTINUE_NOTE_LENGTH = 13,
	AUDIO_CONTINUE_TOGGLE_PERFECT_PITCH = 14,
	AUDIO_CONTINUE_SOUND_LOOP = 15,
	AUDIO_CONTINUE_NOTE_TYPE = 16,
	AUDIO_CONTINUE_RETURN = 17,
	AUDIO_CONTINUE_NOTE_PITCH = 18,
	AUDIO_CONTINUE_SOUND_CALL = 19,
	AUDIO_CONTINUE_PITCH_SWEEP = 20,
	AUDIO_CONTINUE_PLAY_NEXT_NOTE = 21,
	AUDIO_CONTINUE_APPLY_PITCH_SLIDE = 22,
	AUDIO_CONTINUE_APPLY_MUSIC_AFFECTS = 23,
	AUDIO_CONTINUE_DUTY_CYCLE_PATTERN = 24,
};

struct audio_execute_music_state {
	struct cpu_register_state registers;
	port_u8 flags2[8];
	port_u8 continuation;
};

struct audio_octave_state {
	struct cpu_register_state registers;
	port_u8 octaves[8];
	port_u8 continuation;
};

struct audio_duty_cycle_command_state {
	struct cpu_register_state registers;
	port_u8 command_pointers[16];
	port_u8 command_byte;
	port_u8 duty_cycles[8];
	port_u8 continuation;
};

struct audio_byte_command_state {
	struct cpu_register_state registers;
	port_u8 command_pointers[16];
	port_u8 command_byte;
	port_u8 value;
	port_u8 continuation;
};

struct audio_duty_pattern_command_state {
	struct cpu_register_state registers;
	port_u8 command_pointers[16];
	port_u8 command_byte;
	port_u8 duty_patterns[8];
	port_u8 duty_cycles[8];
	port_u8 flags1[8];
	port_u8 continuation;
};

struct audio_tempo_command_state {
	struct cpu_register_state registers;
	port_u8 command_pointers[16];
	port_u8 command_bytes[2];
	port_u8 music_tempo[2];
	port_u8 sfx_tempo[2];
	port_u8 fractional_note_delays[8];
	port_u8 continuation;
};

struct audio_toggle_perfect_pitch_state {
	struct cpu_register_state registers;
	port_u8 flags1[8];
	port_u8 continuation;
};

struct audio_vibrato_command_state {
	struct cpu_register_state registers;
	port_u8 command_pointers[16];
	port_u8 command_bytes[2];
	port_u8 delay_counters[8];
	port_u8 delay_reloads[8];
	port_u8 extents[8];
	port_u8 rates[8];
	port_u8 continuation;
};

struct audio_pitch_sweep_state {
	struct cpu_register_state registers;
	port_u8 command_pointers[16];
	port_u8 command_byte;
	port_u8 flags2[8];
	port_u8 sweep;
	port_u8 continuation;
};

struct audio_pitch_slide_command_state {
	struct cpu_register_state registers;
	port_u8 command_pointers[16];
	port_u8 command_bytes[3];
	port_u8 length_modifiers[8];
	port_u8 target_frequency_high[8];
	port_u8 target_frequency_low[8];
	port_u8 flags1[8];
	port_u8 continuation;
};

struct audio_note_type_state {
	struct cpu_register_state registers;
	port_u8 command_pointers[16];
	port_u8 command_byte;
	port_u8 note_speeds[8];
	port_u8 volumes[8];
	port_u8 music_wave_instrument;
	port_u8 sfx_wave_instrument;
	port_u8 continuation;
};

struct audio_sound_call_state {
	struct cpu_register_state registers;
	port_u8 command_pointers[16];
	port_u8 command_bytes[2];
	port_u8 return_addresses[16];
	port_u8 flags1[8];
	port_u8 continuation;
};

struct audio_sound_loop_state {
	struct cpu_register_state registers;
	port_u8 command_pointers[16];
	port_u8 command_bytes[3];
	port_u8 loop_counters[8];
	port_u8 continuation;
};

struct audio_note_length_state {
	struct cpu_register_state registers;
	port_u8 note_speeds[8];
	port_u8 music_tempo[2];
	port_u8 sfx_tempo[2];
	port_u8 fractional_note_delays[8];
	port_u8 note_delays[8];
	port_u8 flags2[8];
	port_u8 flags1[8];
	port_u8 channel5_sound_id;
	port_u8 channel8_sound_id;
	port_u8 tempo_modifier;
	port_u8 saved_a;
	port_u8 saved_f;
	port_u8 continuation;
};

struct audio_note_pitch_state {
	struct cpu_register_state registers;
	port_u8 saved_a;
	port_u8 saved_f;
	port_u8 octaves[8];
	port_u8 flags1[8];
	port_u8 sfx_sound_ids[4];
	port_u8 volumes[8];
	port_u8 note_delays[8];
	port_u8 duty_cycles[8];
	port_u8 hardware_volume_envelopes[4];
	port_u8 hardware_duty_registers[4];
	port_u8 audio_terminal;
	port_u8 stereo_panning;
	port_u8 frequency_low_bytes[8];
	port_u8 music_wave_instrument;
	port_u8 sfx_wave_instrument;
	port_u8 channel5_sound_id;
	port_u8 channel8_sound_id;
	port_u8 frequency_modifier;
	port_u8 audio3_enable;
	port_u8 wave_ram[16];
	port_u8 hardware_frequency_registers[8];
	port_u8 length_modifiers[8];
	port_u8 frequency_steps[8];
	port_u8 frequency_steps_fractional[8];
	port_u8 current_frequency_fractional[8];
	port_u8 current_frequency_high[8];
	port_u8 current_frequency_low[8];
	port_u8 target_frequency_high[8];
	port_u8 target_frequency_low[8];
};

struct audio_play_next_note_state {
	struct cpu_register_state registers;
	port_u8 vibrato_delay_reloads[8];
	port_u8 vibrato_delay_counters[8];
	port_u8 flags1[8];
	port_u8 low_health_alarm;
	port_u8 continuation;
};

struct audio_sound_ret_state {
	struct cpu_register_state registers;
	port_u8 command_pointers[16];
	port_u8 command_bytes[2];
	port_u8 return_addresses[16];
	port_u8 flags1[8];
	port_u8 flags2[8];
	port_u8 disable_channel_output;
	port_u8 audio3_enable;
	port_u8 audio_terminal;
	port_u8 sound_ids[8];
	port_u8 saved_volume;
	port_u8 audio_volume;
	port_u8 continuation;
};

struct audio_sfx_note_state {
	struct cpu_register_state registers;
	port_u8 command_pointers[16];
	port_u8 command_bytes[3];
	port_u8 note_speeds[8];
	port_u8 music_tempo[2];
	port_u8 sfx_tempo[2];
	port_u8 fractional_note_delays[8];
	port_u8 note_delays[8];
	port_u8 flags2[8];
	port_u8 flags1[8];
	port_u8 sound_ids[8];
	port_u8 tempo_modifier;
	port_u8 duty_cycles[8];
	port_u8 hardware_volume_envelopes[4];
	port_u8 hardware_duty_registers[4];
	port_u8 audio_terminal;
	port_u8 stereo_panning;
	port_u8 music_wave_instrument;
	port_u8 sfx_wave_instrument;
	port_u8 frequency_modifier;
	port_u8 audio3_enable;
	port_u8 wave_ram[16];
	port_u8 hardware_frequency_registers[8];
	port_u8 continuation;
};

struct audio_apply_music_affects_state {
	struct cpu_register_state registers;
	port_u8 note_delays[8];
	port_u8 sound_ids[8];
	port_u8 flags1[8];
	port_u8 flags2[8];
	port_u8 duty_patterns[8];
	port_u8 hardware_duty_registers[4];
	port_u8 vibrato_delay_counters[8];
	port_u8 vibrato_extents[8];
	port_u8 vibrato_rates[8];
	port_u8 frequency_low_bytes[8];
	port_u8 hardware_frequency_low_registers[4];
	port_u8 continuation;
};

struct audio_update_music_state {
	struct cpu_register_state registers;
	port_u8 sound_ids[8];
	port_u8 mute_audio_and_pause_music;
	port_u8 audio_terminal;
	port_u8 audio3_enable;
	port_u8 continuation;
};

struct audio_play_sound_state {
	struct cpu_register_state registers;
	port_u8 audio_ram[243];
	port_u8 hardware_audio[23];
	port_u8 header_rom[784];
};

struct audio_unknown_ef_state {
	struct cpu_register_state registers;
	port_u8 audio_ram[243];
	port_u8 hardware_audio[23];
	port_u8 header_rom[784];
	port_u8 command_byte;
	port_u8 continuation;
};

struct audio_note_state {
	struct cpu_register_state registers;
	port_u8 audio_ram[243];
	port_u8 hardware_audio[23];
	port_u8 header_rom[784];
	port_u8 command_byte;
	port_u8 continuation;
};

_Static_assert(sizeof(port_u8) == 1, "port_u8 must be 8 bits");
_Static_assert(sizeof(port_u16) == 2, "port_u16 must be 16 bits");
_Static_assert(sizeof(port_u32) == 4, "port_u32 must be 32 bits");
_Static_assert(sizeof(struct string_cmp_state) == 8, "unexpected ABI padding");
_Static_assert(sizeof(struct accumulator_state) == 2, "unexpected ABI padding");
_Static_assert(sizeof(struct binary_accumulator_state) == 4, "unexpected ABI padding");
_Static_assert(sizeof(struct cpu_register_state) == 8, "unexpected ABI padding");
_Static_assert(sizeof(struct auto_text_box_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct init_options_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct discard_buttons_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct serial_counter_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct yes_no_parameters_state) == 9, "unexpected ABI padding");
_Static_assert(sizeof(struct reset_strength_state) == 9, "unexpected ABI padding");
_Static_assert(sizeof(struct teleport_delay_state) == 9, "unexpected ABI padding");
_Static_assert(sizeof(struct restore_facing_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct ignore_input_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct npc_movement_end_state) == 17, "unexpected ABI padding");
_Static_assert(sizeof(struct coin_load_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct vending_load_state) == 17, "unexpected ABI padding");
_Static_assert(sizeof(struct prize_level_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct movement_direction_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct init_list_state) == 16, "unexpected ABI padding");
_Static_assert(sizeof(struct machine_price_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct volatile_status_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct target_substitute_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct title_ball_y_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct random_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct scale_pixels_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct sprite_sheet_data_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct text_box_coords_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct text_box_search_state) == 9, "unexpected ABI padding");
_Static_assert(sizeof(struct status_pp_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct trade_oam_step_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct trade_oam_state) == 90, "unexpected ABI padding");
_Static_assert(sizeof(struct copy_byte_step_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct slot_machine_wheel_setup_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct menu_cursor_store_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct rival_trainer_lookup_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct intro_nidorino_oam_state) == 1040, "unexpected ABI padding");
_Static_assert(sizeof(struct pokeball_oam_state) == 46, "unexpected ABI padding");
_Static_assert(sizeof(struct smoke_drift_state) == 1039, "unexpected ABI padding");
_Static_assert(sizeof(struct init_intro_oam_state) == 16, "unexpected ABI padding");
_Static_assert(sizeof(struct pick_pokeball_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct asymmetric_oam_state) == 25, "unexpected ABI padding");
_Static_assert(sizeof(struct symmetric_oam_state) == 26, "unexpected ABI padding");
_Static_assert(sizeof(struct hidden_index_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct duplicate_scan_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct town_map_entry_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct next_input_byte_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct slot_ball_tiles_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct slot_ball_cascade_state) == 30, "unexpected ABI padding");
_Static_assert(sizeof(struct bike_allowed_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct coords_front_match_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct tile_front_state) == 16, "unexpected ABI padding");
_Static_assert(sizeof(struct split_sprite_set_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct move_grammar_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct ai_type_effectiveness_state) == 15, "unexpected ABI padding");
_Static_assert(sizeof(struct one_hit_ko_state) == 17, "unexpected ABI padding");
_Static_assert(sizeof(struct tile_sprite_stands_on_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct selected_stats_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct standing_on_warp_state) == 18, "unexpected ABI padding");
_Static_assert(sizeof(struct warp_pad_hole_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct dust_animation_offsets_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct boulder_dust_pointer_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct sprite_screen_xy_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct tile_two_steps_state) == 18, "unexpected ABI padding");
_Static_assert(sizeof(struct trainer_front_state) == 15, "unexpected ABI padding");
_Static_assert(sizeof(struct predef_pointer_state) == 19, "unexpected ABI padding");
_Static_assert(sizeof(struct init_sprite_screen_state) == 15, "unexpected ABI padding");
_Static_assert(sizeof(struct sprite_facing_delay_state) == 15, "unexpected ABI padding");
_Static_assert(sizeof(struct wavy_scx_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct scanline_scx_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct menu_save_tiles_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct option_cursor_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct copy_tile_ids_state) == 26, "unexpected ABI padding");
_Static_assert(sizeof(struct call_function_table_state) == 16, "unexpected ABI padding");
_Static_assert(sizeof(struct update_sprite_image_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct status_ailment_text_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct make_npc_face_state) == 17, "unexpected ABI padding");
_Static_assert(sizeof(struct call_with_turn_flipped_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct applying_attack_animation_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct music_low_health_alarm_state) == 15, "unexpected ABI padding");
_Static_assert(sizeof(struct jump_move_effect_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct init_battle_dispatch_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct print_type_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct default_music_fade_state) == 15, "unexpected ABI padding");
_Static_assert(sizeof(struct play_music_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct bankswitch_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct far_copy_double_state) == 16, "unexpected ABI padding");
_Static_assert(sizeof(struct load_gb_pal_state) == 15, "unexpected ABI padding");
_Static_assert(sizeof(struct down_arrow_blink_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct dma_code_copy_state) == 18, "unexpected ABI padding");
_Static_assert(sizeof(struct dma_routine_state) == 9, "unexpected ABI padding");
_Static_assert(sizeof(struct read_joypad_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct disable_lcd_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct print_level_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct print_status_condition_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct check_coords_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct safari_zone_check_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct mansion_block_loader_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct vermilion_ss_anne_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct victory_road_reset_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct current_move_animation_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct uncompressed_pic_copy_state) == 61, "unexpected ABI padding");
_Static_assert(sizeof(struct slot_winning_symbol_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct draw_line_box_state) == 9, "unexpected ABI padding");
_Static_assert(sizeof(struct cant_lower_pop_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct trade_circled_mon_state) == 29, "unexpected ABI padding");
_Static_assert(sizeof(struct force_party_anim_speed_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct mon_party_gfx_entry_state) == 9, "unexpected ABI padding");
_Static_assert(sizeof(struct show_object_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct sgb_border_copy_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct init_cgb_palettes_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct determine_palette_id_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct player_name_sram_state) == 22, "unexpected ABI padding");
_Static_assert(sizeof(struct serial_exchange_nybble_state) == 15, "unexpected ABI padding");
_Static_assert(sizeof(struct wait_for_sound_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct play_sound_state) == 24, "unexpected ABI padding");
_Static_assert(sizeof(struct fade_out_audio_state) == 26, "unexpected ABI padding");
_Static_assert(sizeof(struct align_sprite_data_state) == 17, "unexpected ABI padding");
_Static_assert(sizeof(struct write_oam_block_state) == 32, "unexpected ABI padding");
_Static_assert(sizeof(struct sprite_movement_delay_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct exploding_animation_state) == 19, "unexpected ABI padding");
_Static_assert(sizeof(struct restore_stat_modifier_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct trainer_pic_column_state) == 15, "unexpected ABI padding");
_Static_assert(sizeof(struct stat_write_entry_state) == 17, "unexpected ABI padding");
_Static_assert(sizeof(struct tile_pair_entry_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct battle_enemy_parameters_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct column_redraw_copy_state) == 80, "unexpected ABI padding");
_Static_assert(sizeof(struct load_item_list_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct trainer_header_info_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct multiply_state) == 17, "unexpected ABI padding");
_Static_assert(sizeof(struct divide_bcd_by10_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct sub_bcd_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct divide_state) == 18, "unexpected ABI padding");
_Static_assert(sizeof(struct differential_decode_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct write_sprite_bits_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct remove_inventory_state) == 23, "unexpected ABI padding");
_Static_assert(sizeof(struct slot_wheel_match_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct add_inventory_state) == 28, "unexpected ABI padding");
_Static_assert(sizeof(struct delay_frame_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct flash_screen_long_delay_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct trade_delay_state) == 9, "unexpected ABI padding");
_Static_assert(sizeof(struct connection_tilemap_state) == 18, "unexpected ABI padding");
_Static_assert(sizeof(struct boulder_sprite_collision_state) == 17, "unexpected ABI padding");
_Static_assert(sizeof(struct sprite_in_front_state) == 17, "unexpected ABI padding");
_Static_assert(sizeof(struct outward_spiral_step_state) == 15, "unexpected ABI padding");
_Static_assert(sizeof(struct circle_transition_state) == 16, "unexpected ABI padding");
_Static_assert(sizeof(struct tile_pair_collision_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct fly_locations_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct moving_bg_tiles_state) == 16, "unexpected ABI padding");
_Static_assert(sizeof(struct vblank_copy_bg_state) == 97, "unexpected ABI padding");
_Static_assert(sizeof(struct vblank_copy_double_state) == 73, "unexpected ABI padding");
_Static_assert(sizeof(struct vblank_copy_state) == 81, "unexpected ABI padding");
_Static_assert(sizeof(struct auto_bg_transfer_state) == 96, "unexpected ABI padding");
_Static_assert(sizeof(struct redraw_row_column_state) == 21, "unexpected ABI padding");
_Static_assert(sizeof(struct interrupt_return_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct draw_tile_block_state) == 28, "unexpected ABI padding");
_Static_assert(sizeof(struct replace_tree_block_state) == 20, "unexpected ABI padding");
_Static_assert(sizeof(struct transition_copy_tiles2_state) == 20, "unexpected ABI padding");
_Static_assert(sizeof(struct badge_stat_boost_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct draw_hp_bar_state) == 19, "unexpected ABI padding");
_Static_assert(sizeof(struct pewter_guys_state) == 20, "unexpected ABI padding");
_Static_assert(sizeof(struct text_box_border_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct animate_party_mon_state) == 20, "unexpected ABI padding");
_Static_assert(sizeof(struct place_menu_cursor_state) == 22, "unexpected ABI padding");
_Static_assert(sizeof(struct serial_interrupt_state) == 24, "unexpected ABI padding");
_Static_assert(sizeof(struct special_warp_state) == 28, "unexpected ABI padding");
_Static_assert(sizeof(struct trainer_move_choice_state) == 47, "unexpected ABI padding");
_Static_assert(sizeof(struct trainer_ai_mod_state) == 45, "unexpected ABI padding");
_Static_assert(sizeof(struct print_number_state) == 29, "unexpected ABI padding");
_Static_assert(sizeof(struct evolution_after_battle_state) == 80, "unexpected ABI padding");
_Static_assert(sizeof(struct evolution_reload_tileset_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct rename_evolved_mon_state) == 45, "unexpected ABI padding");
_Static_assert(sizeof(struct flag_action_state) == 9, "unexpected ABI padding");
_Static_assert(sizeof(struct box_sram_location_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct table_string_copy_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct boost_exp_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct init_sprite_status_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct wake_party_state) == 17, "unexpected ABI padding");
_Static_assert(sizeof(struct fill_memory_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct screen_coords_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct serial_send_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct map_mon_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct bit_count_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct divide_bytes_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct clear_screen_area_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct daycare_exp_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct music_bank_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct player_control_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct event_bit_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct card_key_door_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct elevator_warp_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct gate_movement_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct ai_count_state) == 9, "unexpected ABI padding");
_Static_assert(sizeof(struct checksum_result_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct checksum_loop_state) == 9, "unexpected ABI padding");
_Static_assert(sizeof(struct low_health_alarm_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct battle_attack_count_state) == 12, "unexpected ABI padding");
_Static_assert(sizeof(struct hyper_beam_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct party_alive_state) == 21, "unexpected ABI padding");
_Static_assert(sizeof(struct transition_opponent_state) == 9, "unexpected ABI padding");
_Static_assert(sizeof(struct transition_dungeon_state) == 9, "unexpected ABI padding");
_Static_assert(sizeof(struct black_screen_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct transition_level_state) == 28, "unexpected ABI padding");
_Static_assert(sizeof(struct status_penalty_state) == 15, "unexpected ABI padding");
_Static_assert(sizeof(struct combined_penalty_state) == 19, "unexpected ABI padding");
_Static_assert(sizeof(struct slide_player_head_state) == 29, "unexpected ABI padding");
_Static_assert(sizeof(struct swap_levels_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct subanimation_transform_state) == 9, "unexpected ABI padding");
_Static_assert(sizeof(struct cry_move_state) == 9, "unexpected ABI padding");
_Static_assert(sizeof(struct anim_copy_row_state) == 16, "unexpected ABI padding");
_Static_assert(sizeof(struct animation_palette_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct falling_object_movement_state) == 9, "unexpected ABI padding");
_Static_assert(sizeof(struct share_move_animation_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct falling_x_init_state) == 89, "unexpected ABI padding");
_Static_assert(sizeof(struct falling_movement_init_state) == 29, "unexpected ABI padding");
_Static_assert(sizeof(struct falling_oam_update_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct adjust_oam_block_state) == 25, "unexpected ABI padding");
_Static_assert(sizeof(struct battle_anim_oam_entry_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_is_cry_state) == 9, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_battle_sfx_state) == 10, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_channel_output_state) == 14, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_duty_pattern_state) == 20, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_duty_length_state) == 28, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_cry_modifiers_state) == 11, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_sfx_tempo_state) == 13, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_frequency_modifier_state) == 19, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_wave_frequency_state) == 38, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_command_rewind_state) == 25, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_next_music_byte_state) == 25, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_pitch_slide_state) == 80, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_init_pitch_slide_state) == 88, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_execute_music_state) == 17, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_octave_state) == 17, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_duty_cycle_command_state) == 34, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_byte_command_state) == 27, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_duty_pattern_command_state) == 50, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_tempo_command_state) == 39, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_toggle_perfect_pitch_state) == 17, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_vibrato_command_state) == 59, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_pitch_sweep_state) == 35, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_pitch_slide_command_state) == 60, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_note_type_state) == 44, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_sound_call_state) == 51, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_sound_loop_state) == 36, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_note_length_state) == 58, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_note_pitch_state) == 166, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_play_next_note_state) == 34, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_sound_ret_state) == 72, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_sfx_note_state) == 127, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_apply_music_affects_state) == 89, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_update_music_state) == 20, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_play_sound_state) == 1058, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_unknown_ef_state) == 1060, "unexpected ABI padding");
_Static_assert(sizeof(struct audio_note_state) == 1060, "unexpected ABI padding");

struct set_pal_game_freak_intro_state {
	struct cpu_register_state registers;
	port_u8 default_palette_command;
};

struct safari_zone_game_still_going_state {
	struct cpu_register_state registers;
	port_u8 safari_zone_game_over;
};

#endif
