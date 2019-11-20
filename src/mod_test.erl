-module(mod_rsa).


-behaviour(gen_mod).

-export([start/2,
	%  init/2,
	 stop/1,
	%  rsa_decrypt/1,
	 process_iq_now/1,
	 user_exists/2]).

-export([md5_hex/1]).

-define(PROCNAME, ?MODULE).
-define(NS_OPENPGP, <<"jabber:e2eencryption">>).

-include("logger.hrl").
-include("xmpp.hrl").
-include("mod_roster.hrl").
% -include("mod_muc_room.hrl").


-compile(export_all).

-record(query, {group_jid = <<>> :: binary(),
other_jid = <<>> :: binary()}).
% -type query() :: #query{}.

get_mod(<<"query">>, <<"jabber:e2eencryption">>) ->
	mod_rsa.
get_mod({query, _, _}) -> mod_rsa.

do_decode(<<"query">>, <<"jabber:e2eencryption">>, El,
	  Opts) ->
    decode_query(<<"jabber:e2eencryption">>, Opts, El);
do_decode(Name, <<>>, _, _) ->
    erlang:error({xmpp_codec, {missing_tag_xmlns, Name}});
do_decode(Name, XMLNS, _, _) ->
    erlang:error({xmpp_codec, {unknown_tag, Name, XMLNS}}).

tags() -> [{<<"query">>, <<"jabber:e2eencryption">>}].

do_encode({query, _, _} = Query, TopXMLNS) ->
    encode_query(Query, TopXMLNS).

do_get_name({query, _, _}) -> <<"query">>.

do_get_ns({query, _, _}) -> <<"jabber:e2eencryption">>.

pp(query, 2) -> [group_jid, other_jid];
pp(_, _) -> no.

records() -> [{query, 2}].

decode_query(__TopXMLNS, __Opts,
	     {xmlel, <<"query">>, _attrs, _els}) ->
    {Group_jid, Other_jid} = decode_query_attrs(__TopXMLNS,
						_attrs, undefined, undefined),
    {query, Group_jid, Other_jid}.

decode_query_attrs(__TopXMLNS,
		   [{<<"group_jid">>, _val} | _attrs], _Group_jid,
		   Other_jid) ->
    decode_query_attrs(__TopXMLNS, _attrs, _val, Other_jid);
decode_query_attrs(__TopXMLNS,
		   [{<<"other_jid">>, _val} | _attrs], Group_jid,
		   _Other_jid) ->
    decode_query_attrs(__TopXMLNS, _attrs, Group_jid, _val);
decode_query_attrs(__TopXMLNS, [_ | _attrs], Group_jid,
		   Other_jid) ->
    decode_query_attrs(__TopXMLNS, _attrs, Group_jid,
		       Other_jid);
decode_query_attrs(__TopXMLNS, [], Group_jid,
		   Other_jid) ->
    {decode_query_attr_group_jid(__TopXMLNS, Group_jid),
     decode_query_attr_other_jid(__TopXMLNS, Other_jid)}.

encode_query({query, Group_jid, Other_jid},
	     __TopXMLNS) ->
    __NewTopXMLNS =
	xmpp_codec:choose_top_xmlns(<<"jabber:e2eencryption">>,
				    [], __TopXMLNS),
    _els = [],
    _attrs = encode_query_attr_other_jid(Other_jid,
					 encode_query_attr_group_jid(Group_jid,
								     xmpp_codec:enc_xmlns_attrs(__NewTopXMLNS,
												__TopXMLNS))),
    {xmlel, <<"query">>, _attrs, _els}.

decode_query_attr_group_jid(__TopXMLNS, undefined) ->
    <<>>;
decode_query_attr_group_jid(__TopXMLNS, _val) -> _val.

encode_query_attr_group_jid(<<>>, _acc) -> _acc;
encode_query_attr_group_jid(_val, _acc) ->
    [{<<"group_jid">>, _val} | _acc].

decode_query_attr_other_jid(__TopXMLNS, undefined) ->
    <<>>;
decode_query_attr_other_jid(__TopXMLNS, _val) -> _val.

encode_query_attr_other_jid(<<>>, _acc) -> _acc;
encode_query_attr_other_jid(_val, _acc) ->
    [{<<"other_jid">>, _val} | _acc].

start(Host, _Opts) ->
	?INFO_MSG("Starting mod_rsa", [] ),
	xmpp:register_codec(mod_rsa),
	% register(?PROCNAME,spawn(?MODULE, init, [Host, Opts])),  
	IQDisc = gen_mod:get_opt(iqdisc, _Opts, one_queue),
	gen_iq_handler:add_iq_handler(ejabberd_sm, Host,?NS_OPENPGP, ?MODULE, process_iq_now,IQDisc),
	
	gen_iq_handler:add_iq_handler(ejabberd_local, Host,?NS_OPENPGP, ?MODULE, process_iq_now,IQDisc),
	?INFO_MSG("Iq registered", [] ),
	ok.

% init(Host, _Opts) ->
% 	inets:start(),
% 	ssl:start(),
% 	IQDisc = gen_mod:get_opt(iqdisc, _Opts, one_queue),
% 	gen_iq_handler:add_iq_handler(ejabberd_sm, Host,?NS_OPENPGP, ?MODULE, process_iq_now,IQDisc),
% 	% ejabberd_hooks:add(offline_message_hook, Host, ?MODULE, rsa_decrypt, 100),
% 	?INFO_MSG("Iq registered", [] ),
	
% 	ok.

stop(Host) ->
	?INFO_MSG("Stopping mod_rsa", [] ),
	gen_iq_handler:remove_iq_handler(ejabberd_sm, Host, ?NS_OPENPGP),
	gen_iq_handler:remove_iq_handler(ejabberd_local, Host, ?NS_OPENPGP),
	% ejabberd_hooks:delete(offline_message_hook, Host,
	% 			  ?MODULE, rsa_decrypt, 10),
	xmpp:unregister_codec(mod_rsa),

	ok.

-spec process_iq_now(iq()) -> iq().
process_iq_now(#iq{from = From, to = To, sub_els = [#query{group_jid = GroupJid, other_jid = OtherJid}]} = IQ) ->

	%KeyFolderPath = "/home/hb/Desktop/private-keys/",
	KeyFolderPath = "/opt/ejabberd/.ejabberd-modules/mod_rsa/keys/",
	
	{ok, CurrentDirectory} = file:get_cwd(),
	filelib:ensure_dir(CurrentDirectory ++ "/../../.ejabberd-modules/mod_rsa/keys/"),
	?INFO_MSG("CurrentDirectory ~p , ~p ", [CurrentDirectory,filelib:file_size("/home/hb/Desktop/private-keys/")] ),
	?INFO_MSG("IQ processed ~p , ~p", [OtherJid,GroupJid] ),

	% ejabberd_router:route(To,From,IQ#iq{type = result,
	
	% 			sub_els = [#xmlel{name = <<"PrivateKey">>,
	% 						children = [{xmlcdata, <<"priv key here">>}]},
	% 					#xmlel{name = <<"PublicKey">>,
	% 						children = [{xmlcdata, <<"public key here">>}]}]}).
	

% loop through attributes


	if
		GroupJid /= <<>> ->
				%  group
				
				% ?INFO_MSG("GroupId : ~p", [GroupJid] );
				SplittedGroupJID = binary:split(GroupJid,[<<"@">>]),
				?INFO_MSG("GroupId BareJID : ~p", [SplittedGroupJID] ),	
				[LUser|[LGServer]] = SplittedGroupJID,
				?INFO_MSG("GroupId BareJID : ~p,  ~p", [LUser,LGServer] ),	
			
				RoomPid = get_room_pid(LUser,LGServer),
				?INFO_MSG("RoomPid : ~p", [RoomPid] ),
				State = get_room_state(RoomPid),
				?INFO_MSG("State : ~p", [State] ),
				IsOccupantOrAdmin = mod_muc_room:is_occupant_or_admin(From,State),
				
				if IsOccupantOrAdmin == true ->
					
				% #jid{luser = LUser, lserver = LServer} = GroupJid,
					
					Md5Name = md5_hex(LUser),
					PrivKeyPath = KeyFolderPath ++ Md5Name ++ "grp-priv-key.pem",
					PublicKeyPath = KeyFolderPath ++ Md5Name ++ "grp-pub-key.pem",
					IsPublicExist = filelib:is_regular(PublicKeyPath),
					% IsPrivExist = filelib:is_regular(PrivKeyPath),
					
					if
						IsPublicExist == false ->
								os:cmd("openssl genrsa -out " ++ PrivKeyPath ++ " 2048"),
								os:cmd("openssl rsa -in " ++ PrivKeyPath ++ " -pubout > " ++ PublicKeyPath);
							% not exist so create keys
						true ->
							ok
					end,
					{ok, PemBin } = file:read_file(PrivKeyPath),
					{ok, PublicKeyBin } = file:read_file(PublicKeyPath),

					% ejabberd_router:route(To,From,IQ#iq{type = result,
					% 				sub_els = [#xmlel{name = <<"PrivateKey">>,
					% 							children = [{xmlcdata, PemBin}]},
					% 						#xmlel{name = <<"PublicKey">>,
					% 							children = [{xmlcdata, PublicKeyBin}]}]});
					ejabberd_router:route(To,From,IQ#iq{type = result,
									sub_els = [
									#xmlel{name = <<"Key">>,
											children = [#xmlel{name = <<"PrivateKey">>,
														children = [{xmlcdata, PemBin}]},
													#xmlel{name = <<"PublicKey">>,
														children = [{xmlcdata, PublicKeyBin}]}]}]	
													});
										
				true ->
					ejabberd_router:route(To,From,IQ#iq{type = error,
					sub_els = [#xmlel{name = <<"text">>,
								children = [{xmlcdata, <<"bad reqest">>}]}
							]})
				end;
		OtherJid /= <<>> -> 
				%  other user ?INFO_MSG("OtherJid : ~p", [OtherJid] );
				SplittedOtherJid = binary:split(OtherJid,[<<"@">>]),
				[LUser|[LUServer]] = SplittedOtherJid,
				#jid{luser = LoggedUser} = From,
				Items = mod_roster:get_roster(LUser,LUServer),
				?INFO_MSG("~p", [Items]),
				FILTER = lists:filter(fun (#roster{jid = {LFriendUser,_,_}, subscription = Subscription}) ->
						% ?INFO_MSG("~p", [Subscription] ),
						case LFriendUser of 
							LoggedUser ->
								case Subscription of 
									both ->	
											?INFO_MSG("direct both ~p", [Subscription] ),
											true;
									_ ->
										?INFO_MSG("true", [] ),
										false
								end;
							_ ->
								false
						end
					end,Items),
				?INFO_MSG("OtherJid BareJID : ~p, FILTER ~p", [LUser,length(FILTER)] ),
				if length(FILTER) == 1 ->
					Md5Name = md5_hex(LUser),
					PrivKeyPath = KeyFolderPath ++ Md5Name ++ "priv-key.pem",
					PublicKeyPath = KeyFolderPath ++ Md5Name ++ "pub-key.pem",
					IsPublicExist = filelib:is_regular(PublicKeyPath),
					% IsPrivExist = filelib:is_regular(PrivKeyPath),
					% ?INFO_MSG("OtherJid : ~p ,  ~p", [IsPublicExist,PublicKeyPath] ),
					if
						IsPublicExist == false ->
								os:cmd("openssl genrsa -out " ++ PrivKeyPath ++ " 2048"),
								os:cmd("openssl rsa -in " ++ PrivKeyPath ++ " -pubout > " ++ PublicKeyPath);
							% not exist so create keys
						true ->
							ok
					end,
					% {ok, PemBin } = file:read_file(PrivKeyPath),
					{ok, PublicKeyBin } = file:read_file(PublicKeyPath),

					% ejabberd_router:route(To,From,IQ#iq{type = result,
					% 					sub_els = [#xmlel{name = <<"PublicKey">>,
					% 								children = [{xmlcdata, PublicKeyBin}]}]});

					ejabberd_router:route(To,From,IQ#iq{type = result,
						sub_els = [
						#xmlel{name = <<"Key">>,
										children = [#xmlel{name = <<"PublicKey">>,
													children = [{xmlcdata, PublicKeyBin}]}]}]	
						});
				true -> 
						ejabberd_router:route(To,From,IQ#iq{type = error,
						sub_els = [#xmlel{name = <<"text">>,
									children = [{xmlcdata, <<"bad reqest">>}]}
								]})
				end;
		true ->
				#jid{luser = LUser, lserver = LServer} = From,
				IsExist = user_exists(LUser,LServer),
				
				?INFO_MSG("user exists : ~p ", [IsExist] ),
				if	IsExist == true ->
					Md5Name = md5_hex(LUser),
					PrivKeyPath = KeyFolderPath ++ Md5Name ++ "priv-key.pem",
					PublicKeyPath = KeyFolderPath ++ Md5Name ++ "pub-key.pem",
					IsPublicExist = filelib:is_regular(PublicKeyPath),
					% IsPrivExist = filelib:is_regular(PrivKeyPath),
					?INFO_MSG("OtherJid : ~p ,  ~p", [IsPublicExist,PublicKeyPath] ),
					if
						IsPublicExist == false ->
								os:cmd("openssl genrsa -out " ++ PrivKeyPath ++ " 2048"),
								os:cmd("openssl rsa -in " ++ PrivKeyPath ++ " -pubout > " ++ PublicKeyPath);
							% not exist so create keys
						true ->
							ok
					end,
					{ok, PemBin } = file:read_file(PrivKeyPath),
					{ok, PublicKeyBin } = file:read_file(PublicKeyPath),
% 					ejabberd_router:route(To,From,IQ#iq{type = result,
% 							sub_els = [#xmlel{name = <<"PrivateKey">>,
% 										children = [{xmlcdata, PemBin}]},
% 									#xmlel{name = <<"PublicKey">>,
% 										children = [{xmlcdata, PublicKeyBin}]}]});
					ejabberd_router:route(To,From,IQ#iq{type = result,
						sub_els = [
						#xmlel{name = <<"Key">>,
										children = [#xmlel{name = <<"PrivateKey">>,
														children = [{xmlcdata, PemBin}]},
													#xmlel{name = <<"PublicKey">>,
														children = [{xmlcdata, PublicKeyBin}]}]}]	
						});
					
					true ->
							ejabberd_router:route(To,From,IQ#iq{type = error,
							sub_els = [#xmlel{name = <<"text">>,
										children = [{xmlcdata, <<"bad reqest">>}]}
									]})
				end
				
	end.
	








	% PrivKeyPath = KeyFolderPath ++ "private-key-2.pem",
	% PublicKeyPath = KeyFolderPath ++ "public-key-2.pem",
	
	% {ok, PemBin } = file:read_file(PrivKeyPath),
	% {ok, PublicKeyBin } = file:read_file(PublicKeyPath),

	
	% IQ#iq{type = result, sub_el = [{xmlelement, "value", [], [{xmlcdata, "Hello World of Testing."}]}]}.




% this function will not getting called. Its code is working fine. this is for reference to generate 
% rsa key and rsa encrypt, decrypt and base64 encode decode.

% rsa_decrypt({Action,Packet}) ->
% 	?INFO_MSG("RSA decryption start", [] ),
% 	KeyFolderPath = "/home/hb/Desktop/private-keys/",
% 	PrivKeyPath = KeyFolderPath ++ "private-key-2.pem",
% 	PublicKeyPath = KeyFolderPath ++ "public-key-2.pem",
	
% 	os:cmd("openssl genrsa -out " ++ PrivKeyPath ++ " 2048"),
% 	os:cmd("openssl rsa -in " ++ PrivKeyPath ++ " -pubout > " ++ PublicKeyPath),
% 	{ok,FileList} = file:list_dir(KeyFolderPath),
% 	?INFO_MSG("RSA generated ~p", [FileList] ),

% 	% FOLLOWING CODE IS TESTED AND WORKING FINE
% 	{ok, PemBin } = file:read_file(PrivKeyPath),
% 	[ RSAEntry ] = public_key:pem_decode(PemBin),
% 	PrivateKey = public_key:pem_entry_decode( RSAEntry),
% 	% ?INFO_MSG("RSA PrivateKey : ~p  ", [PrivateKey] ),
% 	Encrypted = public_key:encrypt_private( <<"Hello World! dasdasdsad ss1111">>, PrivateKey ),
% 	EncryptedBase64 = base64:encode(Encrypted),
% 	?INFO_MSG("RSA Encrypted Base 64 Data : ~p  ", [EncryptedBase64] ),

% 	{ ok, PemBin2 } = file:read_file(PublicKeyPath),
% 	[ RSAEntry2 ] = public_key:pem_decode(PemBin2),
% 	PublicKey = public_key:pem_entry_decode( RSAEntry2 ),
	
% 	EncryptedBin = base64:decode(EncryptedBase64),
% 	Decrypted = public_key:decrypt_public(EncryptedBin, PublicKey),
% 	?INFO_MSG("RSA Decrypted Data : ~p  ", [Decrypted] ),

% 	{ok, CurrentDirectory} = file:get_cwd(),
% 	?INFO_MSG("RSA Current Directory : ~p  ", [CurrentDirectory] ),

% 	ok.
 
md5_hex(S) ->
	Md5_bin =  erlang:md5(S),
	Md5_list = binary_to_list(Md5_bin),
	lists:flatten(list_to_hex(Md5_list)).

list_to_hex(L) ->
	lists:map(fun(X) -> int_to_hex(X) end, L).

int_to_hex(N) when N < 256 ->
	[hex(N div 16), hex(N rem 16)].

hex(N) when N < 10 ->
	$0+N;
hex(N) when N >= 10, N < 16 ->
	$a + (N-10).

find_value(Key, List) ->
		case lists:keyfind(Key, 1, List) of
			{Key, Result} -> Result;
			false -> nothing
		end.	

-spec user_exists(ejabberd:luser(), ejabberd:lserver()) -> boolean().
user_exists(LUser, LServer) ->
	UserInfo = ejabberd_sm:get_user_info(LUser, LServer),
	case length(UserInfo) of 
		1 -> true;
		0 -> false
	end.

get_room_pid(Name, Service) ->
	case mod_muc:find_online_room(Name, Service) of
	error ->
		room_not_found;
	{ok, Pid} ->
		Pid
	end.

get_room_state(Room_pid) ->
	{ok, R} = gen_fsm:sync_send_all_state_event(Room_pid, get_state),
	% {ok, R} = gen_statem:call(Room_pid, get_state),
	R.

	% ?INFO_MSG("UserInfo : ~p \n ~p, ~p  ", [UserInfo,LUser,LServer] ),
	% UserInfo1 = ejabberd_sm:get_user_info(<<"user1">>, <<"192.168.36.1">>),
	% ?INFO_MSG("UserInfo : ~p \n ~p, ~p, ~p, ~p  ", [UserInfo1,<<"user1">>, <<"192.168.36.1">>,length(UserInfo1),length(UserInfo)] ).    
