/// Message received from Postgres
module message;

import connection;

import std.range;
import std.conv;
import std.array;
import std.bitmanip;

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
                debug (verbose) writefln("salt: %(%x%), type: %s", msg.password_salt, msg.format);
            default:
                break;
        }
    }

    /// sends startup packet to backend
    void sendStartup (ref Connection c, string database, string username)
    {
        payload.length = 0;
        auto app = appender(&payload);

        app.put(nativeToBigEndian(cast(int)0)[]); // dummy length

        ushort protocol_major = 3;
        ushort protocol_minor = 0;

        int protocol = ~0;
        protocol &= protocol_major << 16 | protocol_minor;

        app.put(nativeToBigEndian(protocol)[]); // protocol
        app.put(cast(ubyte[])"database");
        app.put(cast(ubyte)0);
        app.put(cast(ubyte[])database);
        app.put(cast(ubyte)0);
        app.put(cast(ubyte[])"user");
        app.put(cast(ubyte)0);
        app.put(cast(ubyte[])username);
        app.put(cast(ubyte)0);
        app.put(cast(ubyte)0);
        payload[0..int.sizeof] = nativeToBigEndian(cast(int)payload.length);
        debug (verbose) writeln("Payload: ", payload);
        c.send(payload);

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
    ubyte[4] password_salt;

    /// Type of encryption
    AuthFormat format;

    /// Constructs an auth. message from the given
    /// payload
    static AuthenticationMessage opCall (ubyte[] payload)
    {
        AuthenticationMessage msg;
        msg.format = cast(AuthFormat)bigEndianToNative!(int, int.sizeof)(payload[0..int.sizeof]);

        writeln("Format: ", msg.format);

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
