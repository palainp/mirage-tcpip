type t = {
  urg : bool;
  ack : bool;
  psh : bool;
  rst : bool;
  syn : bool;
  fin : bool;
  window : int;
  options : Options.t list;
  sequence : Sequence.t;
  ack_number : Sequence.t;
  src_port : int;
  dst_port : int;
}

val pp : Format.formatter -> t -> unit
val equal : t -> t -> bool

module Unmarshal : sig
  type error = string

  val of_cstruct : Bytes.t -> (t * Bytes.t, error) result
end

module Marshal : sig
  type error = string

  (** [into_cstruct ~pseudoheader ~payload t buf] attempts to write a valid TCP
      header representing [t] into [buf] at offset 0.  [pseudoheader] and
      [payload] are required to calculate a correct checksum but are not
      otherwise reflected in the data written into [buf] -- [buf] will contain
      only a TCP header after a call to [into_cstruct].
      Returns either the number of bytes written into the buffer on success; if
      the buffer supplied is too small to write the entire header, an error is
      returned. *)
  val into_bytes :
    pseudoheader:Bytes.t ->
    payload:Bytes.t      ->
    t -> Bytes.t ->
    (int, error) result

  (** [make_cstruct ~pseudoheader ~payload t] allocates, fills, and and returns a buffer
      representing the TCP header corresponding to [t].  If [t.options] is
      non-empty, [t.options] will be concatenated onto the result as part of the
      header.
      A variable amount of memory (at least 20 bytes, and at most 60) will be allocated, but
      [] is not represented in the output.  The checksum will be properly
      set to reflect the pseudoheader, header, options, and payload. *)
  val make_bytes : pseudoheader:Bytes.t -> payload:Bytes.t -> t -> Bytes.t
end
