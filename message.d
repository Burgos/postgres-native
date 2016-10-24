/// Message received from Postgres
module message;

import connection;

import std.range;
import std.conv;
import std.array;
import std.bitmanip;
import std.string;

debug (verbose) import std.stdio;

/// This struct encapculates
/// message received and sent from the backend.
/// It also keeps a buffer there, so messages
/// are allowed to reuse the same buffer over
/// and over again, without no need for realloc
struct Message
{
    /// Receives a message from the server
    private void receiveOne (ref Connection c)
    {
        // Read tag, length and then payload
        char tag;
        c.receive(tag);
        int len;
        c.receive(len);

        // Receive payload
        payload.length = len;
        c.receive(payload);

        debug (verbose)
        {
            writeln("Tag: ", tag);
            writeln("Length: ", len);
            writefln("Payload: %(%x, %)", payload);
        }

        switch (tag)
        {
            case 'R':
                auto msg = AuthenticationMessage(this.payload);
                debug (verbose) writefln("salt: %x, type: %s", msg.salt.md5_salt, msg.format);
            default:
                break;
        }
    }

    /// sends startup packet to backend
    void sendStartup (ref Connection c, string database, string username)
    {
        ushort protocol_major = 3;
        ushort protocol_minor = 0;

        int protocol = ~0;
        protocol &= protocol_major << 16 | protocol_minor;

        this.payload = this.constructMessage(this.payload,
                char.init, // startup message, no type
                protocol,
                "database", database,
                "user", username);

        debug (verbose) writeln("Payload: ", payload);
        c.send(payload);

    }

    /// Packs the message ready for send into an provided array
    /// It sets the message inside the frame in a way that
    /// all provided arguments are put, with endianess being
    /// important, and then it sets the first 4 bytes to the
    /// message length.
    /// Params:
    ///     buf = buffer to fill
    ///     type = message type (0 for no type)
    ///     args = args to pack
    ubyte[] constructMessage(Args...)(ref ubyte[] buf, char type, Args args)
    {
        buf.length = 0;
        auto app = appender(&buf);

        // message type
        if (type != char.init)
        {
            app.append(type);
        }

        // dummy length
        app.append(cast(int)0);

        foreach (param; args)
        {
            static if (is(typeof(param) == string))
            {
                app.put(param.representation);
                app.append(cast(ubyte)0);
            }
            else
            {
                app.append(param);
            }
        }

        // final terminator
        app.append(cast(ubyte)0);

        // set the payload length
        buf.write!int(cast(int)(buf.length - (type != char.init ? char.sizeof : 0)), 0);
        return buf;
    }

    private ubyte[] payload;
}

struct AuthenticationMessage
{
    /// Indicates type of authentication
    /// required/indicates success
    static enum AuthFormat
    {
        /// Authentication OK
        OK = 0,
        /// Kerberos V5 required
        KERBEROS = 2,
        /// Clear-text password is required
        CLEARTEXT = 3,
        /// crypt()-encrypted password
        CRYPTPASS = 4,
        /// md5-encrypted password
        MD5PASS = 5,
        /// SCM credentials message is required
        SCMCRED = 6
    }

    /// Salt to be used when encrypting password
    union Salt
    {
        ushort crypt_salt;
        uint md5_salt;
    }

    Salt salt;

    /// Type of encryption
    AuthFormat format;

    /// Constructs an auth. message from the given
    /// payload
    static AuthenticationMessage opCall(Range)(Range payload)
    {
        AuthenticationMessage msg;
        msg.format = cast(AuthFormat)read!int(payload);

        with (AuthFormat) switch (msg.format)
        {
            case CRYPTPASS:
                msg.salt.crypt_salt = read!ushort(payload);
                break;
            case MD5PASS:
                msg.salt.md5_salt = read!uint(payload);
                break;
            case CLEARTEXT:
            case OK:
                break;
            default:
                throw new Exception("Auth format " ~ to!(string)(msg.format) ~ " not supported.");
        }

        return msg;
    }
}

void main()
{
    // try to connect to the
    // postgres, and see what we have
    auto conn = Connection("127.0.0.1", 5432);
    conn.connect();

    Message m;
    m.sendStartup(conn, "test", "burgos");
    m.receiveOne(conn);
}
