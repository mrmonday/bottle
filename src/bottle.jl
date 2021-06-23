module bottle

using Base: String
using TOML

import Base64: base64encode
import Sockets: connect, TCPSocket

import BufferedStreams: BufferedInputStream, BufferedOutputStream, flushbuffer!, BufferedStreams
import Dates
import MbedTLS

function sslify!(socket::TCPSocket)
    entropy = MbedTLS.Entropy()
    rng = MbedTLS.CtrDrbg()
    MbedTLS.seed!(rng, entropy)

    conf = MbedTLS.SSLConfig()

    MbedTLS.config_defaults!(conf)
    MbedTLS.authmode!(conf, MbedTLS.MBEDTLS_SSL_VERIFY_REQUIRED)
    MbedTLS.rng!(conf, rng)
    MbedTLS.ca_chain!(conf)
    MbedTLS.setup!(ctx, conf)
    MbedTLS.set_bio!(ctx, socket)
    MbedTLS.handshake(ctx)
end

function send(msg::String; secret::Bool = false)
    if secret
        @info "> [SECRET MESSAGE REDACTED]"
    else
        @info "> $msg"
    end

    write(output, "$msg\r\n")
    flushbuffer!(output)
end

function find_command(msg::String)::String
    start = findfirst(isequal(' '), msg) + 1
    if msg[1] != ':'
        return SubString(msg, 1, start - 2)
    end

    finish = if length(msg) > start
                idx = findnext(isequal(' '), msg, start)

                if isnothing(idx)
                    length(msg)
                else
                    idx - 1
                end
             else
                length(msg)
             end

    return SubString(msg, start, finish)
end

function handle_cap(msg::String)
    parts = split(msg, " ")
    if length(parts) < 5
        return
    end

    if parts[4] == "LS"
        send("CAP REQ :sasl")
    elseif parts[4] == "ACK"
        # todo check for sasl?
        authenticate()
    end
end

function authenticate()
    send("AUTHENTICATE PLAIN")
end

function handle_auth(msg::String)
    # todo split into 400 byte chunks
    sasl_str = base64encode("$nick\0$nick\0$password")
    send("AUTHENTICATE $sasl_str", secret = true)
end

"""
903 auth successful
"""
function handle_903(msg::String)
    # todo this should be somewhere else probably?
    # todo error cases?
    send("CAP END")
end

function handle_ping(msg::String)
    send(replace(msg, "PING" => "PONG", count = 1))
end

"""
376 end of motd
"""
function handle_376(msg::String)
    send("JOIN $channels")

    # todo this upsets julia :(
    #atexit() do 
    #    send("QUIT :Bottle popped")
    #    sleep(10000)
    #end
end

function BufferedStreams.readbytes!(source::MbedTLS.SSLContext, buffer::Vector{UInt8}, from::Int, to::Int)
    bytes = read(source, 1)
    buffer[from:length(bytes)] = bytes

    return length(bytes)
end

function handle_privmsg(msg::String)
    parts = split(msg, " ")
    if length(parts) < 4
        @info "Malformed PRIVMSG"
        return
    end

    user = parse_user(parts[1])
    if startswith(parts[4], ":\001")
        handle_ctcp(user, join(parts[4:end], " "))
    end
end

function send_reminder(channel, timer)
    reminder = "To join ##rust please register with NickServ - see: https://libera.chat/guides/registration"
    send("NOTICE $channel :$reminder")
    min = 60 * 60 * 3
    max = 60 * 60 * 9
    wait = rand(min:max)
    @info "next reminder in $wait"
    Timer(t -> send_reminder(channel, t), wait)
end

function handle_join(msg::String)
    parts = split(msg, " ")
    if length(parts) < 3
        @info "Malformed JOIN"
        return
    end

    channel = parts[3]
    initial_wait = rand(10:20)
    Timer(t -> send_reminder(channel, t), initial_wait)
end

struct User
    nick::String
    ident::String
    host::String
end

function parse_user(user::AbstractString)::User
    regex = r"^:(([^!]+)!)?(([^@]+)@)?(.+)$"
    matches = match(regex, user)

    return User(matches[2], matches[4], matches[5])
end

function handle_ctcp(user::User, msg::AbstractString)
    if startswith(msg,  ":\001CLIENTINFO")
        send("NOTICE $(user.nick) :\001CLIENTINFO PING TIME VERSION\001")
    elseif startswith(msg, ":\001PING")
        send("NOTICE $(user.nick) $msg")
    elseif startswith(msg, ":\001VERSION")
        send("NOTICE $(user.nick) :\001VERSION Bottle bot\001")
    elseif startswith(msg, ":\001TIME")
        time = Dates.format(Dates.now(Dates.UTC), "e, dd u yyyy HH:MM:SS \\G\\M\\T")
        send("NOTICE $(user.nick) :\001TIME $time\001")
    end
end

handlers = Dict{String, Function}()
handlers["CAP"] = handle_cap
handlers["AUTHENTICATE"] = handle_auth
handlers["903"] = handle_903
handlers["PING"] = handle_ping
handlers["376"] = handle_376
handlers["PRIVMSG"] = handle_privmsg
handlers["JOIN"] = handle_join

config = TOML.parsefile("Bottle.toml")

server = config["server"]
port = config["port"]
nick = config["nick"]
ident = config["ident"]
gecos = config["gecos"]
password = config["password"]
channels = config["channels"]

conn = connect(server, port)
ctx = MbedTLS.SSLContext()
input = BufferedInputStream(ctx)
output = BufferedOutputStream(ctx)
sslify!(conn)

send("CAP LS 302")
send("NICK $nick")
send("USER $ident 0 * :$gecos")

for line in eachline(input)
    @info "< $line"
    command = find_command(line)

    if haskey(handlers, command)
        @debug "handling $command"
        handlers[command](line)
    else
        @debug "$command is no good"
    end
end

end # module
