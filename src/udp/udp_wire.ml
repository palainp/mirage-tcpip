let sizeof_udp = 8

let src_port_offset = 0
let dst_port_offset = 2
let length_offset = 4
let checksum_offset = 6

let get_src_port buf = Bytes.get_uint16_be buf src_port_offset
let set_src_port buf v = Bytes.set_uint16_be buf src_port_offset v

let get_dst_port buf = Bytes.get_uint16_be buf dst_port_offset
let set_dst_port buf v = Bytes.set_uint16_be buf dst_port_offset v

let get_length buf = Bytes.get_uint16_be buf length_offset
let set_length buf v = Bytes.set_uint16_be buf length_offset v

let get_checksum buf = Bytes.get_uint16_be buf checksum_offset
let set_checksum buf value = Bytes.set_uint16_be buf checksum_offset value
