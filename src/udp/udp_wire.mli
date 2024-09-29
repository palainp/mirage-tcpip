val sizeof_udp : int

val get_src_port : Bytes.t -> int
val set_src_port : Bytes.t -> int -> unit

val get_dst_port : Bytes.t -> int
val set_dst_port : Bytes.t -> int -> unit

val get_length : Bytes.t -> int
val set_length : Bytes.t -> int -> unit

val get_checksum : Bytes.t -> int
val set_checksum : Bytes.t -> int -> unit
