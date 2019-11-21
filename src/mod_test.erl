-module(mod_test).

-include("logger.hrl").
-include("xmpp.hrl").
-include("mod_roster.hrl").

-behaviour(gen_mod).

-export([start/2, stop/1, process_iq_now/1, user_exists/2]).
-export([md5_hex/1]).

-define(PROCNAME, ?MODULE).
-define(NS_OPENPGP, <<"jabber:e2eencryption">>).

-record(query, {group_jid = <<>> :: binary(), 
	other_jid = <<>> :: binary()}).

get_mod(<<"query">>, <<"jabber:e2eencryption">>) ->
	mod_test.
get_mod({query, _, _}) -> mod_test.

start(_Host, _Opts) ->
    ?INFO_MSG("Hello, ejabberd world!", []),
    ok.
stop(_Host) ->
    ?INFO_MSG("Bye bye, ejabberd world!", []),
    ok.
depends(_Host, _Opts) ->
    [].
mod_options(_Host) ->
    [].


