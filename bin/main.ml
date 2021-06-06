open Base

let gemini_port = 1965

(* TODO: implement proper checking *)
let parse_url url = url, None

let inet_address_of url =
  let open Or_error.Let_syntax in
  let name, port = parse_url url in
  let%bind addr =
    try return (Unix.gethostbyname name).h_addr_list.(0) with
    | Caml.Not_found ->
      Or_error.error_s [%message "cannot find address" ~hostname:(name : string)]
    | Not_found_s s -> Or_error.error_s s
  in
  return (Unix.ADDR_INET (addr, Option.value port ~default:gemini_port))
;;

let get url =
  let collect_until_closed socket =
    let bytes = Bytes.create 32 in
    let buffer = Buffer.create 1024 in
    let rec collect socket buffer bytes =
      try
        match Ssl.read socket bytes 0 32 with
        | 0 -> buffer
        | len ->
          Buffer.add_subbytes buffer bytes ~pos:0 ~len;
          collect socket buffer bytes
      with
      | Ssl.(Read_error Error_zero_return) -> buffer
    in
    collect socket buffer bytes
  in
  match inet_address_of url with
  | Ok sockaddr ->
    Ssl.init ();
    let socket = Ssl.open_connection Ssl.TLSv1_3 sockaddr in
    let cert = Ssl.get_certificate socket in
    let cipher = Ssl.get_cipher socket in
    Stdio.print_endline "SSL connection ok.";
    Stdio.printf
      "Certificate issuer:  %s\nsubject: %s\n"
      (Ssl.get_issuer cert)
      (Ssl.get_subject cert);
    Stdio.printf
      "Cipher: %s (%s)\n%s\n"
      (Ssl.get_cipher_name cipher)
      (Ssl.get_cipher_version cipher)
      (Ssl.get_cipher_description cipher);
    Stdio.print_endline "sending request...";
    Ssl.output_string socket (Printf.sprintf "gemini://%s/\r\n" url);
    Ssl.flush socket;
    Buffer.contents (collect_until_closed socket) |> Stdio.print_string
  | Error err -> Error.raise err
;;

let () = get "gemini.circumlunar.space"
