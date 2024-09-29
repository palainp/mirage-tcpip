type t = {
  src     : Ipaddr.V4.t;
  dst     : Ipaddr.V4.t;
  id      : int;
  off     : int;
  ttl     : int;
  proto   : int;
  options : Bytes.t;
}

type protocol = [
  | `ICMP
  | `TCP
  | `UDP ]

let pp fmt t =
  Format.fprintf fmt "IPv4 packet %a -> %a: id %04x, off %d proto %d, ttl %d, options %a"
    Ipaddr.V4.pp t.src Ipaddr.V4.pp t.dst t.id t.off t.proto t.ttl Ohex.pp (Bytes.to_string t.options)

let equal {src; dst; id; off; ttl; proto; options} q =
  src = q.src &&
  dst = q.dst &&
  id = q.id &&
  off = q.off &&
  ttl = q.ttl &&
  proto = q.proto &&
  Bytes.equal options q.options

module Marshal = struct
  open Ipv4_wire

  type error = string

  let protocol_to_int = function
    | `ICMP   -> 1
    | `TCP    -> 6
    | `UDP    -> 17

  let pseudoheader ~src ~dst ~proto len =
    (* should we do sth about id or off (assert false?) *)
    let proto = protocol_to_int proto in
    let ph = Bytes.create 12 in
    let numify = Ipaddr.V4.to_int32 in
    Bytes.set_uint32_be ph 0 (numify src);
    Bytes.set_uint32_be ph 4 (numify dst);
    Bytes.set_uint8 ph 8 0;
    Bytes.set_uint8 ph 9 proto;
    Bytes.set_uint16_be ph 10 len;
    ph

  let unsafe_fill ~payload_len t buf =
    let nearest_4 n = match n mod 4 with
      | 0 -> n
      | k -> (4 - k) + n
    in
    let options_len = nearest_4 @@ Bytes.length t.options in
    set_hlen_version buf ((4 lsl 4) + 5 + (options_len / 4));
    set_id buf t.id;
    set_off buf t.off;
    set_ttl buf t.ttl;
    set_proto buf t.proto;
    set_src buf t.src;
    set_dst buf t.dst;
    Bytes.blit t.options 0 buf sizeof_ipv4 (Bytes.length t.options);
    set_len buf (sizeof_ipv4 + options_len + payload_len);
    let checksum = Tcpip_checksum.ones_complement @@ Bytes.sub buf 0 (20 + options_len) in
    set_checksum buf checksum


  let into_bytes ~payload_len t buf =
    if Bytes.length buf < (sizeof_ipv4 + Bytes.length t.options) then
      Error "Not enough space for IPv4 header"
    else
      Ok (unsafe_fill ~payload_len t buf)

  let make_bytes ~payload_len t =
    let nearest_4 n = match n mod 4 with
      | 0 -> n
      | k -> (4 - k) + n
    in
    let options_len = nearest_4 @@ Bytes.length t.options in
    let buf = Bytes.make (sizeof_ipv4 + options_len) '\000' in
    (* The initialisation with '\000' should be removable in the future *)
    unsafe_fill ~payload_len t buf;
    buf
end
module Unmarshal = struct
  type error = string

  let int_to_protocol = function
    | 1  -> Some `ICMP
    | 6  -> Some `TCP
    | 17 -> Some `UDP
    | _  -> None

  let ( let* ) = Result.bind

  let header_of_bytes buf =
    let open Ipv4_wire in
    let check_version buf =
      let version n = (n land 0xf0) in
      match get_hlen_version buf |> version with
      | 0x40 -> Ok ()
      | n -> Error (Printf.sprintf "IPv4 presented with a packet that claims a different IP version: %x" n)
    in
    let size_check buf =
      if (Bytes.length buf < sizeof_ipv4) then Error "buffer sent to IPv4 parser had size < 20"
      else Ok ()
    in
    let get_header_length buf =
      let length_of_hlen_version n = (n land 0x0f) * 4 in
      let hlen = get_hlen_version buf |> length_of_hlen_version in
      let len = get_len buf in
      if len < sizeof_ipv4 then
        Error (Printf.sprintf
                 "total length %d is smaller than minimum header length" len)
      else if len < hlen then
        Error (Printf.sprintf
                 "total length %d is smaller than stated header length %d"
                 len hlen)
      else if hlen < sizeof_ipv4 then
        Error (Printf.sprintf "IPv4 header claimed to have size < 20: %d" hlen)
      else if Bytes.length buf < hlen then
        Error (Printf.sprintf "IPv4 packet w/length %d claimed to have header of size %d" (Bytes.length buf) hlen)
      else Ok hlen
    in
    let parse buf options_end =
      let src = get_src buf
      and dst = get_dst buf
      and id = get_id buf
      and off = get_off buf
      and ttl = get_ttl buf
      and proto = get_proto buf
      in
      let options =
        if options_end > sizeof_ipv4 then (Bytes.sub buf sizeof_ipv4 (options_end - sizeof_ipv4))
        else (Bytes.empty)
      in
       Ok ({src; dst; id; off; ttl; proto; options;}, options_end)
    in
    let* () = size_check buf in
    let* () = check_version buf in
    let* hl = get_header_length buf in
    parse buf hl

  let of_bytes buf =
    let parse buf options_end =
      let payload_len = Ipv4_wire.get_len buf - options_end in
      let payload_available = Bytes.length buf - options_end in
      if payload_available < payload_len then (
        Error (Printf.sprintf "Payload buffer (%d bytes) too small to contain payload (of size %d from header)" payload_available payload_len)
      ) else (
        let payload = Bytes.sub buf options_end payload_len in
        Ok payload
      )
    in
    let* header, options_end = header_of_bytes buf in
    let* payload = parse buf options_end in
    Ok (header, payload)

  let verify_transport_checksum ~proto ~ipv4_header ~transport_packet =
    (* note: it's not necessary to ensure padding to integral number of 16-bit fields here; ones_complement_list does this for us *)
    let check ~proto ipv4_header len =
      try
        let ph = Marshal.pseudoheader ~src:ipv4_header.src ~dst:ipv4_header.dst ~proto len in
        let calculated_checksum = Tcpip_checksum.ones_complement_list [ph ; transport_packet] in
        0 = compare 0x0000 calculated_checksum
      with
      | Invalid_argument _ -> false
    in
    match proto with
    | `TCP -> (* checksum isn't optional in tcp, but pkt must be long enough *)
      check ipv4_header ~proto (Bytes.length transport_packet)
    | `UDP ->
      match Udp_wire.get_checksum transport_packet with
      | n when (=) 0 @@ compare n 0x0000 -> true (* no checksum supplied, so the check trivially passes *)
      | _ ->
        check ipv4_header ~proto (Bytes.length transport_packet)

end
