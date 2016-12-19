/// Postgresql connection protocol
/// Copyright: Copyright (c) 2016 Nemanja Boric
module connection;

import message;

import std.bitmanip;
import std.socket;
import std.stdio;
import std.exception;
import std.conv;
import std.variant;

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

    /// Password used to connect
    public string password;

    /// Database to connect to
    public string database;

    /// Parameters recevied from
    /// the backend.
    public string[string] parameters;

    /// state of the connection
    enum State
    {
        INITIALIZING,
        AUTHENTICATING,
        AUTHENTICATED,
        READY_FOR_QUERY
    }

    /// ditto
    public State state;

    /// message construction buffer
    private ubyte[] payload;

    @disable this();

    /// Creates the connection object.
    /// Params:
    ///     address = address of the server
    ///     port = remote port of the server
    ///     username = user name to connect with
    ///     password = password to connect with
    ///     database = database to connect to
    ///     family = address family of the connection
    public this (string address, ushort port,
            string username, string password,
            string database,
            AddressFamily family = AddressFamily.INET)
    {
        this.sock = new Socket(family, SocketType.STREAM);
        this.username = username;
        this.password = password;
        this.database = database;

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

    /// Handles the error message received
    Message.ParsedMessage handleError (Message.ParsedMessage msg)
    {
        if (auto error = msg.peek!(ErrorMessage))
        {
            this.handleError(error);
        }

        return msg;
    }

    /// ditto
    void handleError(ErrorMessage)(auto ref ErrorMessage error)
    {
        throw new Exception(error.toString());
    }

    /// Starts the communication with the server.
    /// Authenticates and waits for server to say
    /// that's it's ready for query
    /// TODO: should cover 'E' responses
    public void connect()
    {
        enforce(this.state == State.init, "Connection already initialized");
        this.connect_socket();

        Message msg;

        // send startup message and wait for the response
        this.send(msg.sendStartup(this.database, this.username));
        auto response = msg.receiveOne(this);

        auto auth_msg = response.peek!(AuthenticationMessage);
        enforce(auth_msg !is null, "Expected authentication message");
        this.state = State.AUTHENTICATING;

        if (auth_msg.format != AuthenticationMessage.AuthFormat.OK)
        {
            if (auth_msg.format == AuthenticationMessage.AuthFormat.MD5PASS)
            {
                this.send(Md5PasswordMessage(this.payload, this.username,
                            this.password, auth_msg.salt.md5_salt));
            }
            else
            {
                enforce(false, "We support only MD5 for the moment");
            }

            response = handleError(msg.receiveOne(this));
            auth_msg = response.peek!(AuthenticationMessage);
            enforce(auth_msg !is null, "Expected authentication message");

            enforce(auth_msg.format == AuthenticationMessage.AuthFormat.OK,
                    "Failed to authenticate");
        }

        this.state = State.AUTHENTICATED;
        debug (verbose) writeln("Authenticated");

        // read any status messages
        do
        {
            response = msg.receiveOne(this);
            response.tryVisit!(
                    (ErrorMessage e) { this.handleError(e); },
                    (ReadyForQueryMessage msg) { this.state = State.READY_FOR_QUERY; },
                    (ParameterStatusMessage msg) { this.parameters[msg.name] = msg.value; },
                    (BackendKeyDataMessage msg) {
                        this.parameters["process_id"] = to!string(msg.process_id);
                        this.parameters["process_key"] = to!string(msg.key); return; }
            )();

            writeln("STATE: ", this.state);
            writeln(this.parameters);
        }
        while (this.state != State.READY_FOR_QUERY);
    }

    /// Executes a query
    public void query (string query_string)
    in
    {
        assert(this.state == State.READY_FOR_QUERY);
    }
    body
    {
        // TODO: make receiveOne static
        Message msg;
        this.send(message.QueryMessage(this.payload, query_string));
        auto response = msg.receiveOne(this);

        if (auto rows = response.peek!(message.RowDescriptionMessage))
        {
            debug (verbose) writeln("Got a RowDescription, getting fields");

            // receive rows
            auto value = msg.receiveOne(this);
            auto row = value.peek!(message.DataRowMessage);

            while (row)
            {
                foreach (i, c; row.columns)
                {
                    if (rows.fields[i].format == rows.Field.Format.TEXT)
                    {
                        debug (verbose)
                        {
                            writeln(rows.fields[i].name, ": ", to!string(cast(char[])c.value));
                        }
                    }
                }

                // receive next
                value = msg.receiveOne(this);
                row = value.peek!(message.DataRowMessage);
            }
        }
    }

    /// Executes a complex query
    public void query(Args) (string query_string, Args args...)
    in
    {
        assert(this.state == State.READY_FOR_QUERY);
    }
    body
    {
        // TODO: make receiveOne static
        Message msg;
        message.ParseMessage parsemsg;
        parsemsg.query_string = query_string;

        this.send(message.ParseMessage(this.payload, parsemsg));
        auto response = msg.receiveOne(this);

        if (auto rows = response.peek!(message.RowDescriptionMessage))
        {
            debug (verbose) writeln("Got a RowDescription, getting fields");

            // receive rows
            auto value = msg.receiveOne(this);
            auto row = value.peek!(message.DataRowMessage);

            while (row)
            {
                foreach (i, c; row.columns)
                {
                    if (rows.fields[i].format == rows.Field.Format.TEXT)
                    {
                        debug (verbose)
                        {
                            writeln(rows.fields[i].name, ": ", to!string(cast(char[])c.value));
                        }
                    }
                }

                // receive next
                value = msg.receiveOne(this);
                row = value.peek!(message.DataRowMessage);
            }
        }
    }
    /// TODO: move these low-level communication into a substruct
    private void connect_socket()
    in
    {
        assert(this.address !is null);
    }
    body
    {
        this.sock.connect(this.address);
        // not supported on OSX
        version (linux)
        {
            this.sock.setKeepAlive(5, 5);
        }
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
        debug (verbose)
        {
            writeln("Raw bytes: ", buf);
            writeln("As strings: ", cast(char[])buf);
        }

        return this.sock.send(buf);
    }
}
