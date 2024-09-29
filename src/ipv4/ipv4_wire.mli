val sizeof_ipv4 : int

val get_hlen_version : Bytes.t -> int
val set_hlen_version : Bytes.t -> int -> unit

val get_len : Bytes.t -> int
val set_len : Bytes.t -> int -> unit

val get_id : Bytes.t -> int
val set_id : Bytes.t -> int -> unit

val get_off : Bytes.t -> int
val set_off : Bytes.t -> int -> unit

val get_ttl : Bytes.t -> int
val set_ttl : Bytes.t -> int -> unit

val get_proto : Bytes.t -> int
val set_proto : Bytes.t -> int -> unit

val get_checksum : Bytes.t -> int
val set_checksum : Bytes.t -> int -> unit

val get_src : Bytes.t -> Ipaddr.V4.t
val set_src : Bytes.t -> Ipaddr.V4.t -> unit

val get_dst : Bytes.t -> Ipaddr.V4.t
val set_dst : Bytes.t -> Ipaddr.V4.t -> unit
