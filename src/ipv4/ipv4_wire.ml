let sizeof_ipv4 = 20

let hlen_version_off = 0
let _tos_off = 1
let len_off = 2
let id_off = 4
let off_off = 6
let ttl_off = 8
let proto_off = 9
let csum_off = 10
let src_off = 12
let dst_off = 16

let get_hlen_version buf = Bytes.get_uint8 buf hlen_version_off
let set_hlen_version buf v = Bytes.set_uint8 buf hlen_version_off v

let get_len buf = Bytes.get_uint16_be buf len_off
let set_len buf v = Bytes.set_uint16_be buf len_off v

let get_id buf = Bytes.get_uint16_be buf id_off
let set_id buf v = Bytes.set_uint16_be buf id_off v

let get_off buf = Bytes.get_uint16_be buf off_off
let set_off buf v = Bytes.set_uint16_be buf off_off v

let get_ttl buf = Bytes.get_uint8 buf ttl_off
let set_ttl buf v = Bytes.set_uint8 buf ttl_off v

let get_proto buf = Bytes.get_uint8 buf proto_off
let set_proto buf v = Bytes.set_uint8 buf proto_off v

let get_checksum buf = Bytes.get_uint16_be buf csum_off
let set_checksum buf value = Bytes.set_uint16_be buf csum_off value

let get_src buf = Ipaddr.V4.of_int32 (Bytes.get_uint32_be buf src_off)
let set_src buf v = Bytes.set_uint32_be buf src_off (Ipaddr.V4.to_int32 v)

let get_dst buf = Ipaddr.V4.of_int32 (Bytes.get_uint32_be buf dst_off)
let set_dst buf v = Bytes.set_uint32_be buf dst_off (Ipaddr.V4.to_int32 v)
