val sizeof_tcp : int

val get_src_port : Bytes.t -> int
val set_src_port : Bytes.t -> int -> unit

val get_dst_port : Bytes.t -> int
val set_dst_port : Bytes.t -> int -> unit

val get_sequence : Bytes.t -> int32
val set_sequence : Bytes.t -> int32 -> unit

val get_ack_number : Bytes.t -> int32
val set_ack_number : Bytes.t -> int32 -> unit

val get_flags : Bytes.t -> int
val set_flags : Bytes.t -> int -> unit

val get_window : Bytes.t -> int
val set_window : Bytes.t -> int -> unit

val get_checksum : Bytes.t -> int
val set_checksum : Bytes.t -> int -> unit

val get_urg_ptr : Bytes.t -> int
val set_urg_ptr : Bytes.t -> int -> unit

val get_data_offset : Bytes.t -> int
val set_data_offset : Bytes.t -> int -> unit

val get_fin : Bytes.t -> bool
val get_syn : Bytes.t -> bool
val get_rst : Bytes.t -> bool
val get_psh : Bytes.t -> bool
val get_ack : Bytes.t -> bool
val get_urg : Bytes.t -> bool

val set_fin : Bytes.t -> unit
val set_syn : Bytes.t -> unit
val set_rst : Bytes.t -> unit
val set_psh : Bytes.t -> unit
val set_ack : Bytes.t -> unit
val set_urg : Bytes.t -> unit
