/// Message received from Postgres
module message;

import connection;

import std.range;
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
            writeln("Payload: ", payload);
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
        writeln("Payload: ", payload);
        c.send(payload);

    }

    private ubyte[] payload;
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
