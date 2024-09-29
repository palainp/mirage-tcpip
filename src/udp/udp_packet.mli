type t = {
  src_port : int;
  dst_port : int;
}

val pp : Format.formatter -> t -> unit
val equal : t -> t -> bool

module Unmarshal : sig

  type error = string

(** [of_bytes buf] attempts to interpret [buf] as a UDP header.  If
    successful, it returns [Ok (header, payload)], although [payload] may be an
    empty Bytes.t . *)
  val of_bytes : Bytes.t -> (t * Bytes.t, error) result
end
module Marshal : sig

  type error = string

  (** [into_bytes ~pseudoheader ~payload t buf] attempts to
      assemble a UDP header in [buf] with [t.src_port] and [t.dst_port] set,
      along with the correct length and checksum.
      It does not write [pseudoheader] or [payload] into the buffer,
      but requires them to calculate the correct checksum. *)
  val into_bytes :
    pseudoheader:Bytes.t  ->
    payload:Bytes.t       ->
    t -> Bytes.t ->
    (unit, error) result

  (** [make_bytes ~pseudoheader ~payload t] allocates, fills, and and returns a buffer
      representing the UDP header corresponding to [t].  [make_bytes] will
      allocate 8 bytes for the UDP header.
      [payload] and [pseudoheader] are not directly represented in the output,
      and are required for correct computation of the UDP checksum only.
      The checksum will be properly set to reflect the pseudoheader, header, and payload. *)
  val make_bytes : pseudoheader:Bytes.t -> payload:Bytes.t -> t -> Bytes.t
end
