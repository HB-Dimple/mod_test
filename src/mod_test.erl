-module(mod_test).
-behaviour(gen_mod).
-include("logger.hrl").
-export([start/2, stop/1, depends/2, mod_options/1]).
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


