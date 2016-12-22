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
import std.array: Appender;

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
    private Appender!(ubyte[]) payload_appender;

    /// Message parse buffer
    Message msg;

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

        const msg_size = 512;
        this.payload_appender.reserve(msg_size);
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
                this.send(Md5PasswordMessage(this.payload_appender, this.username,
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

            debug (verbose) writeln("STATE: ", this.state);
            debug (verbose) writeln(this.parameters);
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
        this.send(message.QueryMessage(this.payload_appender, query_string));
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
                        debug (PrintResults)
                        {
                            writeln(rows.fields[i].name, ": ", c.value);
                        }
                    }
                }

                // receive next
                value = msg.receiveOne(this);
                row = value.peek!(message.DataRowMessage);
            }

            // the last received message is not an DataRowMessage, so
            // keep processing it out of the loop
            response = value;
        }

        enforce(response.peek!(message.CommandCompleteMessage),
                "Expected CommandCompleteMessage");

        response = msg.receiveOne(this);
        enforce(response.peek!(message.ReadyForQueryMessage),
                "Expected ReadyForQueryMessage");
    }

    /// Executes a complex query
    public void query(Args...) (string query_string, Args args)
    in
    {
        assert(this.state == State.READY_FOR_QUERY);
    }
    body
    {
        import types;
        import std.string;

        // TODO: make receiveOne static
        message.ParseMessage parsemsg;
        message.DescribeMessage describemsg;
        message.BindMessage bindmsg;
        message.ExecuteMessage execmsg;
        bindmsg.num_parameter_values = args.length;

        LengthArray[args.length] values;
        foreach (i, arg; args)
        {
            values[i] = LengthArray(cast(ubyte[])(
                        to!string(arg).representation));
        }

        bindmsg.parameter_values  = values;
        message.SyncMessage sync;
        parsemsg.query_string = query_string;

        this.send(message.ParseMessage(this.payload_appender, parsemsg));
        this.send(message.BindMessage(this.payload_appender, bindmsg));
        this.send(message.DescribeMessage(this.payload_appender, describemsg));
        this.send(message.ExecuteMessage(this.payload_appender, execmsg));
        this.send(message.SyncMessage(this.payload_appender, sync));

        auto response = msg.receiveOne(this);
        enforce(response.peek!(message.ParseCompleteMessage),
                "Expected ParseCompleteMessage");

        response = msg.receiveOne(this);
        enforce(response.peek!(message.BindCompleteMessage),
                "Expected BindCompleteMessage");


        response = msg.receiveOne(this);

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
                        debug (PrintResults)
                        {
                            writeln(rows.fields[i].name, ": ", c.value);
                        }
                    }
                }

                // receive next
                value = msg.receiveOne(this);
                row = value.peek!(message.DataRowMessage);
            }

            // The last one isn't the DataRowMessage, parse
            // it out the loop
            response = value;
        }

        enforce(response.peek!(message.CommandCompleteMessage),
                "Expected CommandCompleteMessage");

        response = msg.receiveOne(this);
        enforce(response.peek!(message.ReadyForQueryMessage),
                "Expected ReadyForQueryMessage");
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

    public ptrdiff_t receive (ref Appender!(ubyte[]) app,
            size_t bytes_need)
    {
        const chunk_size = 256;
        ubyte[chunk_size] buf;

        ptrdiff_t received = 0;

        while (received < bytes_need)
        {
            auto need = bytes_need - received;
            auto recv = need > chunk_size ? chunk_size : need;

            auto ret = this.sock.receive(buf[0..need]);

            if (ret == Socket.ERROR)
            {
                writeln("Failed to receive from socket: ", this.sock.getErrorText());
                return ret;
            }

            app.put(buf[0..need]);

            received += need;
        }

        return received;
    }

    public ptrdiff_t receive(T) (ref T t)
    {
        ubyte[T.sizeof] buf;
        auto ret = this.sock.receive(buf);

        if (ret == Socket.ERROR)
        {
            writeln("Failed to receive from socket: ", this.sock.getErrorText());
            return ret;
        }

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
