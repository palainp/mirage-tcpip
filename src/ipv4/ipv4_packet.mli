type t = {
  src     : Ipaddr.V4.t;
  dst     : Ipaddr.V4.t;
  id      : int;
  off     : int;
  ttl     : int;
  proto   : int;
  options : Bytes.t;
}

val pp : Format.formatter -> t -> unit
val equal : t -> t -> bool

type protocol = [
  | `ICMP
  | `TCP
  | `UDP ]

module Unmarshal : sig
  type error = string

  val int_to_protocol : int -> protocol option

  val of_bytes : Bytes.t -> (t * Bytes.t, error) result
  val header_of_bytes : Bytes.t -> ((t * int), error) result
(** [header_of_bytes buf] attempts to return [t, offset] where [offset]
    is the first byte of the payload in [buf]. *)

  val verify_transport_checksum : proto:([`TCP | `UDP]) -> ipv4_header:t ->
      transport_packet:Bytes.t -> bool
end

module Marshal : sig
  type error = string

  val protocol_to_int : protocol -> int

  val pseudoheader : src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> proto:protocol
    -> int -> Bytes.t
    (** [pseudoheader src dst proto len] constructs a pseudoheader, suitable for inclusion in transport-layer checksum calculations, including the information supplied.  [len] should be the total length of the transport-layer header and payload.  *)

(** [into_bytes ~payload_len t buf] attempts to write a header representing [t] (including
    [t.options]) into [buf] at offset 0.
    If there is insufficient space to represent [t], an error will be returned. *)
  val into_bytes : payload_len:int -> t -> Bytes.t -> (unit, error) result

  (** [make_bytes ~payload_len t] allocates, fills, and returns a buffer
      representing the IPV4 header corresponding to [t].
      If [t.options] is non-empty, [t.options] will be
      concatenated onto the result. A variable amount of memory (at least 20 bytes
      for a zero-length options field) will be allocated.
      Note: no space is allocated for the payload. *)
  val make_bytes : payload_len:int -> t -> Bytes.t
end
