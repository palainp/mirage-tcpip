type ty =
  | Echo_reply
  | Destination_unreachable
  | Source_quench
  | Redirect
  | Echo_request
  | Time_exceeded
  | Parameter_problem
  | Timestamp_request
  | Timestamp_reply
  | Information_request
  | Information_reply

val ty_to_string : ty -> string
val int_to_ty : int -> ty option
val ty_to_int : ty -> int

type unreachable_reason =
  | Network_unreachable
  | Host_unreachable
  | Protocol_unreachable
  | Port_unreachable
  | Would_fragment
  | Source_route_failed
  | Destination_network_unknown
  | Destination_host_unknown
  | Source_host_isolated
  | Destination_net_prohibited
  | Destination_host_prohibited
  | TOS_network_unreachable
  | TOS_host_unreachable
  | Communication_prohibited
  | Host_precedence_violation
  | Precedence_insufficient

val unreachable_reason_to_int : unreachable_reason -> int

val sizeof_icmpv4 : int

val get_ty : Bytes.t -> int
val set_ty : Bytes.t -> int -> unit

val get_code : Bytes.t -> int
val set_code : Bytes.t -> int -> unit

val get_checksum : Bytes.t -> int
val set_checksum : Bytes.t -> int -> unit
