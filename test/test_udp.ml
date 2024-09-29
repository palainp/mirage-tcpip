open Common

module Time = Vnetif_common.Time
module B = Basic_backend.Make
module V = Vnetif.Make(B)
module E = Ethernet.Make(V)
module Static_arp = Static_arp.Make(E)(Time)
module Ip = Static_ipv4.Make(Mirage_crypto_rng)(Mclock)(E)(Static_arp)
module Udp = Udp.Make(Ip)(Mirage_crypto_rng)

type stack = {
  backend : B.t;
  netif : V.t;
  ethif : E.t;
  arp : Static_arp.t;
  ip : Ip.t;
  udp : Udp.t;
}

let get_stack ?(backend = B.create ~use_async_readers:true
                  ~yield:(fun() -> Lwt.pause ()) ()) ip =
  let open Lwt.Infix in
  let cidr = Ipaddr.V4.Prefix.make 24 ip in
  V.connect backend >>= fun netif ->
  E.connect netif >>= fun ethif ->
  Static_arp.connect ethif >>= fun arp ->
  Ip.connect ~cidr ethif arp >>= fun ip ->
  Udp.connect ip >>= fun udp ->
  Lwt.return { backend; netif; ethif; arp; ip; udp }

let fails msg f args =
  match f args with
  | Ok _ -> Alcotest.fail msg
  | Error _ -> ()

let marshal_unmarshal () =
  let parse = Udp_packet.Unmarshal.of_bytes in
  fails "unmarshal a 0-length packet" parse (Bytes.create 0);
  fails "unmarshal a too-short packet" parse (Bytes.create 2);
  let with_data = Bytes.make 8 '\000' in
  Udp_wire.set_src_port with_data 2000;
  Udp_wire.set_dst_port with_data 21;
  Udp_wire.set_length with_data 20;
  let payload = Bytes.of_string "abcdefgh1234" in
  let with_data = Bytes.cat with_data payload in
  match Udp_packet.Unmarshal.of_bytes with_data with
  | Error s -> Alcotest.fail s
  | Ok (_header, data) ->
    Alcotest.(check bytes) "unmarshalling gives expected data" payload data;
    Lwt.return_unit

let write () =
  let open Lwt.Infix in
  let dst = Ipaddr.V4.of_string_exn "192.168.4.20" in
  get_stack dst >>= fun stack ->
  Static_arp.add_entry stack.arp dst (Macaddr.of_string_exn "00:16:3e:ab:cd:ef");
  Udp.write ~src_port:1212 ~dst_port:21 ~dst stack.udp (Bytes.of_string "MGET *") >|= Result.get_ok

let unmarshal_regression () =
  let i = Bytes.make 1016 '\030' in
  Bytes.set_char i 4 '\x04';
  Bytes.set_char i 5 '\x00';
  Alcotest.(check (result reject pass)) "correctly return error for bad packet"
    (Error "parse failed") (Udp_packet.Unmarshal.of_bytes i);
  Lwt.return_unit


let marshal_marshal () =
  let error_str = Alcotest.result Alcotest.reject Alcotest.string in
  let udp = {Udp_packet.src_port = 1; dst_port = 2} in
  let payload = Bytes.create 100 in
  let buffer = Bytes.create Udp_wire.sizeof_udp in
  let src = Ipaddr.V4.of_string_exn "127.0.0.1" in
  let dst = Ipaddr.V4.of_string_exn "127.0.0.1" in
  let pseudoheader = Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto:`UDP (Bytes.length buffer + Bytes.length payload) in
  Udp_packet.Marshal.into_bytes ~pseudoheader ~payload udp (Bytes.shift buffer 1)
  |> Alcotest.check error_str "Buffer too short" (Error "Not enough space for a UDP header");
  Udp_packet.Marshal.into_bytes ~pseudoheader ~payload udp buffer
  |> Alcotest.(check (result unit string)) "Buffer big enough for header" (Ok ());
  Udp_packet.Unmarshal.of_bytes (Bytes.cat buffer payload)
  |> Alcotest.(check (result (pair udp_packet bytes) string)) "Save and reload" (Ok (udp, payload));
  Lwt.return_unit

let suite = [
  "unmarshal regression", `Quick, unmarshal_regression;
  "marshal/marshal", `Quick, marshal_marshal;
  "marshal/unmarshal", `Quick, marshal_unmarshal;
  "write packets", `Quick, write;
]
