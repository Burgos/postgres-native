module connection;

import std.bitmanip;
import std.socket;
import std.stdio;

// TODO: this has to do reference counting,
// so it doesn't close instances.
struct Connection
{
    /// connection socket object
    private Socket sock;
    /// remote server address
    private Address address;

    /// Username used to connect
    public string username;

    @disable this();

    /// Creates the connection object.
    /// Params:
    ///     address = address of the server
    ///     port = remote port of the server
    ///     family = address family of the connection
    public this (string address, ushort port,
            string username,
            AddressFamily family = AddressFamily.INET)
    {
        this.sock = new Socket(family, SocketType.STREAM);
        this.username = username;

        if (family == AddressFamily.INET)
        {
            this.address = new InternetAddress(address, port);
        }
        else if (family == AddressFamily.INET6)
        {
            this.address = new Internet6Address(address, port);
        }
        else
        {
            throw new Exception("Unsupported family type.");
        }
    }

    public ~this()
    {
        this.sock.shutdown(SocketShutdown.BOTH);
        this.sock.close();
    }

    public void connect()
    in
    {
        assert(this.address !is null);
    }
    body
    {
        this.sock.connect(this.address);
        this.sock.setKeepAlive(5, 5);
    }

    public ptrdiff_t receive (void[] buf)
    {
        auto ret = this.sock.receive(buf);
        if (ret == Socket.ERROR)
        {
            writeln("Failed to receive from socket: ", this.sock.getErrorText());
        }
        return ret;
    }

    public ptrdiff_t receive(T) (ref T t)
    {
        ubyte[T.sizeof] buf;
        auto ret = this.receive(buf);
        t = bigEndianToNative!(T, T.sizeof)(buf);
        return ret;
    }

    public ptrdiff_t send (void[] buf)
    {
        return this.sock.send(buf);
    }
}
