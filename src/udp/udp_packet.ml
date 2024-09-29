type t = {
  src_port : int;
  dst_port : int;
}

let equal {src_port; dst_port} q =
  src_port = q.src_port &&
  dst_port = q.dst_port

let pp fmt t =
  Format.fprintf fmt "UDP port %d -> %d" t.src_port t.dst_port

module Unmarshal = struct

  type error = string

  let ( let* ) = Result.bind

  let of_bytes buf =
    let open Udp_wire in
    let check_header_length () =
      if Bytes.length buf < sizeof_udp then Error "UDP header too short" else Ok ()
    in
    let check_payload_length length_from_header length_of_buffer =
      if length_from_header < sizeof_udp then
        Error "UDP header claimed a total length < the size of just the header"
      else begin
        let payload_len = length_from_header - sizeof_udp in
        if payload_len > (length_of_buffer - sizeof_udp)
        then Error (Printf.sprintf
	      "UDP header claimed a payload longer than the supplied buffer: %d vs %d."
              payload_len length_of_buffer)
        else Ok payload_len
      end
    in
    let* () = check_header_length () in
    let total_length_from_header = get_length buf in
    let* payload_len = check_payload_length total_length_from_header (Bytes.length buf) in
    let src_port = get_src_port buf in
    let dst_port = get_dst_port buf in
    let payload = Bytes.sub buf sizeof_udp payload_len in
    Ok ({ src_port; dst_port; }, payload)
end
module Marshal = struct
  type error = string

  let unsafe_fill ~pseudoheader ~payload {src_port; dst_port} udp_buf len =
    let open Udp_wire in
    let udp_buf = Bytes.sub udp_buf 0 sizeof_udp in
    set_src_port udp_buf src_port;
    set_dst_port udp_buf dst_port;
    set_length udp_buf len;
    set_checksum udp_buf 0;
    (* if we've been passed a buffer larger than sizeof_udp, make sure we
     * consider only the portion which will actually contain the header
     * when calculating this bit of the checksum *)
    let csum = Tcpip_checksum.ones_complement_list [ pseudoheader ; udp_buf ; payload ] in
    (* Convert zero checksum to the equivalent 0xffff, to prevent it
     * seeming like no checksum at all. From RFC768: "If the computed
     * checksum is zero, it is transmitted as all ones (the equivalent
     * in one's complement arithmetic)."  *)
    let csum = if csum = 0 then 0xffff else csum in
    set_checksum udp_buf csum

  let into_bytes ~pseudoheader ~payload t udp_buf =
    let open Udp_wire in
    let check_header_len () =
      if Bytes.length udp_buf < sizeof_udp then
        Error "Not enough space for a UDP header"
      else
        Ok ()
    in
    Result.bind (check_header_len ())
      (fun () ->
         let len = Bytes.length payload + sizeof_udp in
         let buf = Bytes.sub udp_buf 0 sizeof_udp in
         unsafe_fill ~pseudoheader ~payload t buf len;
         Ok ())

  let make_bytes ~pseudoheader ~payload t =
    let buf = Bytes.create Udp_wire.sizeof_udp in
    let len = Udp_wire.sizeof_udp + Bytes.length payload in
    unsafe_fill ~pseudoheader ~payload t buf len;
    buf
end
