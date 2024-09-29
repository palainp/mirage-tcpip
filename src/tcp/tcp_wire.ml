let sizeof_tcp = 20

let src_port_off = 0
let dst_port_off = 2
let sequence_off = 4
let ack_off = 8
let dataoff_off = 12
let flags_off = 13
let window_off = 14
let checksum_off = 16
let urg_ptr_off = 18

let get_src_port buf = Bytes.get_uint16_be buf src_port_off
let set_src_port buf v = Bytes.set_uint16_be buf src_port_off v

let get_dst_port buf = Bytes.get_uint16_be buf dst_port_off
let set_dst_port buf v = Bytes.set_uint16_be buf dst_port_off v

let get_sequence buf = Bytes.get_uint32_be buf sequence_off
let set_sequence buf v = Bytes.set_uint32_be buf sequence_off v

let get_ack_number buf = Bytes.get_uint32_be buf ack_off
let set_ack_number buf v = Bytes.set_uint32_be buf ack_off v

let get_flags buf = Bytes.get_uint8 buf flags_off
let set_flags buf v = Bytes.set_uint8 buf flags_off v

let get_window buf = Bytes.get_uint16_be buf window_off
let set_window buf v = Bytes.set_uint16_be buf window_off v

let get_checksum buf = Bytes.get_uint16_be buf checksum_off
let set_checksum buf value = Bytes.set_uint16_be buf checksum_off value

let get_urg_ptr buf = Bytes.get_uint16_be buf urg_ptr_off
let set_urg_ptr buf value = Bytes.set_uint16_be buf urg_ptr_off value

(* XXX note that we overwrite the lower half of dataoff
 * with 0, so be careful when implemented CWE flag which
 * sits there *)
let get_data_offset buf = ((Bytes.get_uint8 buf dataoff_off) lsr 4) * 4
let set_data_offset buf v = Bytes.set_uint8 buf dataoff_off (v lsl 4)

let get_fin buf = ((Bytes.get_uint8 buf flags_off) land (1 lsl 0)) > 0
let get_syn buf = ((Bytes.get_uint8 buf flags_off) land (1 lsl 1)) > 0
let get_rst buf = ((Bytes.get_uint8 buf flags_off) land (1 lsl 2)) > 0
let get_psh buf = ((Bytes.get_uint8 buf flags_off) land (1 lsl 3)) > 0
let get_ack buf = ((Bytes.get_uint8 buf flags_off) land (1 lsl 4)) > 0
let get_urg buf = ((Bytes.get_uint8 buf flags_off) land (1 lsl 5)) > 0
let _get_ece buf = ((Bytes.get_uint8 buf flags_off) land (1 lsl 6)) > 0
let _get_cwr buf = ((Bytes.get_uint8 buf flags_off) land (1 lsl 7)) > 0

let set_fin buf =
  Cstruct.set_uint8 buf flags_off ((Bytes.get_uint8 buf flags_off) lor (1 lsl 0))
let set_syn buf =
  Cstruct.set_uint8 buf flags_off ((Bytes.get_uint8 buf flags_off) lor (1 lsl 1))
let set_rst buf =
  Cstruct.set_uint8 buf flags_off ((Bytes.get_uint8 buf flags_off) lor (1 lsl 2))
let set_psh buf =
  Cstruct.set_uint8 buf flags_off ((Bytes.get_uint8 buf flags_off) lor (1 lsl 3))
let set_ack buf =
  Cstruct.set_uint8 buf flags_off ((Bytes.get_uint8 buf flags_off) lor (1 lsl 4))
let set_urg buf =
  Cstruct.set_uint8 buf flags_off ((Bytes.get_uint8 buf flags_off) lor (1 lsl 5))
let _set_ece buf =
  Cstruct.set_uint8 buf flags_off ((Bytes.get_uint8 buf flags_off) lor (1 lsl 6))
let _set_cwr buf =
  Cstruct.set_uint8 buf flags_off ((Bytes.get_uint8 buf flags_off) lor (1 lsl 7))
