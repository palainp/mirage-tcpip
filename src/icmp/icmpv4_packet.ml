open Icmpv4_wire

(* second 4 bytes of the message have varying interpretations *)
type subheader =
  | Id_and_seq of int * int
  | Next_hop_mtu of int
  | Pointer of int
  | Address of Ipaddr.V4.t
  | Unused

type t = {
  code : int;
  ty : ty;
  subheader : subheader;
}

let pp fmt t =
  let say = Format.fprintf in
  let pp_subheader fmt = function
    | Id_and_seq (id, seq) -> say fmt "subheader: id: %d, sequence %d" id seq
    | Next_hop_mtu mtu -> say fmt "subheader: MTU %d" mtu
    | Pointer pt -> say fmt "subheader: pointer to byte %d" pt
    | Address addr -> say fmt "subheader: ip %a" Ipaddr.V4.pp addr
    | Unused -> ()
  in
  say fmt "ICMP type %s, code %d, subheader [%a]" (ty_to_string t.ty)
    t.code pp_subheader t.subheader

let subheader_eq = function
  | Unused, Unused -> true
  | Id_and_seq (a, b), Id_and_seq (p, q) -> a = p && b = q
  | Next_hop_mtu a, Next_hop_mtu b-> a = b
  | Pointer a, Pointer b -> a = b
  | Address a, Address b -> Ipaddr.V4.compare a b = 0
  | _ -> false

let equal {code; ty; subheader} q =
  code = q.code &&
  ty = q.ty &&
  subheader_eq (subheader, q.subheader)

let ( let* ) = Result.bind

module Unmarshal = struct

  type error = string

  let subheader_of_bytes ty buf =
    match ty with
    | Echo_request | Echo_reply
    | Timestamp_request | Timestamp_reply
    | Information_request | Information_reply ->
      Id_and_seq (Bytes.get_uint16_be buf 0, Bytes.get_uint16_be buf 2)
    | Destination_unreachable -> Next_hop_mtu (Bytes.get_uint16_be buf 2)
    | Time_exceeded
    | Source_quench -> Unused
    | Redirect -> Address (Ipaddr.V4.of_int32 (Bytes.get_uint32_be buf 0))
    | Parameter_problem -> Pointer (Bytes.get_uint8 buf 0)

  let of_bytes buf =
    let len = Bytes.length buf in
    let check_len () =
      if len < sizeof_icmpv4 then
        Error "packet too short for ICMPv4 header"
      else Ok () in
    let check_ty () =
      match int_to_ty (get_ty buf) with
      | None -> Error "unrecognized ICMPv4 type"
      | Some ty -> Ok ty
    in
    (* TODO: check checksum as well, and return an error if it's invalid *)
    let* () = check_len () in
    let* ty = check_ty () in
    let code = get_code buf in
    let buf = Bytes.sub buf 4 (len-4) in
    let len = len-4 in
    let subheader = subheader_of_bytes ty buf in
    let payload = Bytes.sub buf sizeof_icmpv4 (len-sizeof_icmpv4) in
    Ok ({ code; ty; subheader}, payload)
end

module Marshal = struct

  type error = string

  let subheader_into_bytes ~buf sh =
    match sh with
    | Id_and_seq (id, seq) -> Bytes.set_uint16_be buf 0 id; Bytes.set_uint16_be buf 2 seq
    | Next_hop_mtu mtu -> Bytes.set_uint16_be buf 0 0; Bytes.set_uint16_be buf 2 mtu
    | Pointer byte -> Bytes.set_uint32_be buf 0 Int32.zero; Bytes.set_uint8 buf 0 byte;
    | Address addr -> Bytes.set_uint32_be buf 0 (Ipaddr.V4.to_int32 addr)
    | Unused -> set_uint32 buf 0 Int32.zero

  let unsafe_fill {ty; code; subheader} buf ~payload =
    set_ty buf (ty_to_int ty);
    set_code buf code;
    set_checksum buf 0x0000;
    let len = Bytes.length buf in
    let buf = Bytes.sub buf 4 (len-4) in
    subheader_into_cstruct ~buf:buf subheader;
    let packets = [(Bytes.sub buf 0 sizeof_icmpv4); payload] in
    set_checksum buf (Tcpip_checksum.ones_complement_list packets)

  let check_len buf =
    if Bytes.length buf < sizeof_icmpv4 then
      Error "Not enough space for ICMP header"
    else Ok ()

  let into_bytes t buf ~payload =
    let* () = check_len buf in
    unsafe_fill t buf ~payload;
    Ok ()

  let make_bytes t ~payload =
    let buf = Bytes.create sizeof_icmpv4 in
    unsafe_fill t buf ~payload;
    buf
end
