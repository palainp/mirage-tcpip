type subheader =
  | Id_and_seq of int * int
  | Next_hop_mtu of int
  | Pointer of int
  | Address of Ipaddr.V4.t
  | Unused

type t = {
  code : int;
  ty : Icmpv4_wire.ty;
  subheader : subheader;
}

val pp : Format.formatter -> t -> unit
val equal : t -> t -> bool

module Unmarshal : sig
  type error = string

  val subheader_of_bytes : Icmpv4_wire.ty -> Bytes.t -> subheader

  val of_bytes : Bytes.t -> (t * Bytes.t, error) result
end
module Marshal : sig
  type error = string

  (** [into_bytes t buf ~payload] generates an ICMPv4 header from [t] and
      writes it into [buf] at offset 0. [payload] is used to calculate the ICMPv4 header
      checksum, but is not included in the generated buffer. [into_bytes] may
      fail if the buffer is of insufficient size. *)
  val into_bytes : t -> Bytes.t -> payload:Bytes.t -> (unit, error) result

  (** [make_bytes t ~payload] allocates, fills, and returns a Bytes.t with the header
      information from [t].  The payload is used to calculate the ICMPv4 header
      checksum, but is not included in the generated buffer.  [make_bytes] allocates
      8 bytes for the ICMPv4 header. *)
  val make_bytes : t -> payload:Bytes.t -> Bytes.t
end
