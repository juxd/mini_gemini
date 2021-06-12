open Base

let gemini_port = 1965

let inet_address_of uri =
  let port = Uri.port uri in
  let open Or_error.Let_syntax in
  let%bind host =
    match Uri.host uri with
    | Some host -> Ok host
    | None ->
      Or_error.error_s
        [%message "Error parsing - check that url is in the correct format."]
  in
  let%bind addr =
    try return (Unix.gethostbyname host).h_addr_list.(0) with
    | Caml.Not_found ->
      Or_error.error_s [%message "cannot find address" ~hostname:(host : string)]
    | Not_found_s s -> Or_error.error_s s
  in
  return (Unix.ADDR_INET (addr, Option.value port ~default:gemini_port))
;;

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
;;

let get raw_url ~certs_dir =
  let uri = Uri.of_string raw_url in
  match inet_address_of uri with
  | Ok sockaddr ->
    Ssl.init ();
    let context = Ssl.create_context Ssl.TLSv1_3 Ssl.Client_context in
    let certfile = certs_dir ^ Uri.host_with_default uri ^ ".pem" in
    let visited_before = Caml.Sys.file_exists certfile in
    let socket =
      if visited_before
      then (
        Stdio.printf "Loading SSL certificate at file %s\n" certfile;
        Ssl.load_verify_locations context certfile "";
        let socket = Ssl.open_connection_with_context context sockaddr in
        Ssl.verify socket;
        Ssl.get_verify_result socket |> Ssl.get_verify_error_string |> Stdio.print_endline;
        socket)
      else (
        Stdio.printf
          "First time visiting this address, will save SSL certificate in %s\n"
          certfile;
        let socket = Ssl.open_connection_with_context context sockaddr in
        Ssl.write_certificate certfile (Ssl.get_certificate socket);
        socket)
    in
    Stdio.print_endline "sending request...";
    Ssl.output_string socket (Printf.sprintf "%s\r\n" (Uri.to_string uri));
    Ssl.flush socket;
    Buffer.contents (collect_until_closed socket) |> Stdio.print_string
  | Error err -> Error.raise err
;;

let () =
  let usage_msg = (Sys.get_argv ()).(0) ^ "[-certsdir CERTSDIR] location" in
  let link : string option ref = ref None in
  let certs_dir = ref "~/.mini_gemini_certs" in
  let anon_fun url =
    match !link with
    | Some _addr -> ()
    | None -> link := Some url
  in
  Caml.Arg.parse
    [ ( "-certsdir"
      , Caml.Arg.Set_string certs_dir
      , "Directory to store and retrieve certificates. Defaults to ~/.mini_gemini_certs \
         if not provided" )
    ]
    anon_fun
    usage_msg;
  match !link with
  | None -> Caml.Arg.usage [] usage_msg
  | Some addr -> get addr ~certs_dir:!certs_dir
;;
