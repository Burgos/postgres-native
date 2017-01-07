/// Postgresql connection protocol
/// Copyright: Copyright (c) 2016 Nemanja Boric
module postgres.connection;

import postgres.message;

import std.bitmanip;
import std.socket;
import std.stdio;
import std.exception;
import std.conv;
import std.variant;
import std.array: Appender;
import postgres.row;

/// Range for returning the results
/// from queryRange
struct ResultSet
{
    @property PostgresRow front()
    {
        return this.pg_row;
    }

    @property void popFront()
    {
        this.has_more = this.getNextRow(*conn, pg_row,
                parsed_message, response, raw_row);
    }

    @property bool empty()
    {
        if (&this.getNextRow is null)
        {
            return true;
        }

        if (!this.initialised)
        {
            this.has_more = this.getNextRow(*conn, pg_row,
                    parsed_message, response, raw_row);
            this.initialised = true;
        }

        return !has_more;
    }

    /// Clears the ResultSet
    package void clear()
    {
        this.initialised = false;
        this.has_more = false;
    }

    private PostgresRow pg_row;

    private bool function(ref Connection, ref PostgresRow,
            ref typeof(parsed_message), ref typeof(response),
            ref typeof(raw_row)) getNextRow;
    private bool has_more;
    private bool initialised;
    package postgres.message.Message.ParsedMessage parsed_message;
    package postgres.message.Message.ParsedMessage response;
    package postgres.message.DataRowMessage* raw_row;
    package Connection* conn;
}


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
    public void query (string query_string,
        void delegate(PostgresRow row) row_dg)
    in
    {
        assert(this.state == State.READY_FOR_QUERY);
    }
    body
    {
        import postgres.message:
            QueryMessage,
            RowDescriptionMessage,
            DataRowMessage,
            CommandCompleteMessage,
            ReadyForQueryMessage;

        // TODO: make receiveOne static
        this.send(QueryMessage(this.payload_appender, query_string));
        auto response = msg.receiveOne(this);

        if (auto rows = response.peek!(RowDescriptionMessage))
        {
            debug (verbose) writeln("Got a RowDescription, getting fields");

            // receive rows
            auto value = msg.receiveOne(this);
            auto raw_row = value.peek!(DataRowMessage);

            while (raw_row)
            {
                PostgresRow row;
                row.init(rows.fields, raw_row.columns);

                if (row_dg)
                {
                    row_dg(row);
                }

                debug (PrintResults)
                {
                    foreach (i, c; raw_row.columns)
                    {
                        if (rows.fields[i].format == rows.Field.Format.TEXT)
                        {
                                writeln(rows.fields[i].name, ": ", c.value);
                        }
                    }
                }

                // receive next
                value = msg.receiveOne(this);
                raw_row = value.peek!(DataRowMessage);
            }

            // the last received message is not an DataRowMessage, so
            // keep processing it out of the loop
            response = value;
        }

        enforce(response.peek!(CommandCompleteMessage),
                "Expected CommandCompleteMessage");

        response = msg.receiveOne(this);
        enforce(response.peek!(ReadyForQueryMessage),
                "Expected ReadyForQueryMessage");
    }

    /// ResultSet object for API
    private ResultSet set;

    /// Executes a query and returns range of PostgresRows
    public auto ref queryRange (string query_string)
    in
    {
        assert(this.state == State.READY_FOR_QUERY);
    }
    body
    {
        import postgres.message:
            QueryMessage,
            RowDescriptionMessage,
            DataRowMessage,
            CommandCompleteMessage,
            ReadyForQueryMessage;

        // TODO: make receiveOne static
        this.send(QueryMessage(this.payload_appender, query_string));
        this.set.response = msg.receiveOne(this);

        if (auto rows = this.set.response.peek!(RowDescriptionMessage))
        {
            static bool getNextRow(ref Connection conn, ref PostgresRow row,
                    ref typeof(ResultSet.parsed_message) value,
                    ref typeof(ResultSet.response) response,
                    ref typeof(ResultSet.raw_row) raw_row)
            {
                auto rows = response.peek!(RowDescriptionMessage);
                // receive row. Receive first time
                value = conn.msg.receiveOne(conn);
                raw_row = value.peek!(DataRowMessage);

                if (raw_row)
                {
                    row.init(rows.fields, raw_row.columns);
                    return true;
                }
                else
                {
                    // the last received message is not an DataRowMessage, so
                    // keep processing it out of the loop
                    response = value;

                    enforce(response.peek!(CommandCompleteMessage),
                            "Expected CommandCompleteMessage");

                    response = conn.msg.receiveOne(conn);
                    enforce(response.peek!(ReadyForQueryMessage),
                            "Expected ReadyForQueryMessage");

                    return false;
                }
            }

            set.conn = &this;
            set.getNextRow = &getNextRow;
            return set;
        }

        this.set.clear();
        return this.set;
    }

    /// Executes a complex query
    public ResultSet queryRange(Args...) (string query_string, Args args)
    in
    {
        assert(this.state == State.READY_FOR_QUERY);
    }
    body
    {
        import postgres.types;
        import std.string;
        import postgres.message: ParseMessage,
               DescribeMessage,
               BindMessage,
               ExecuteMessage,
               SyncMessage,
               ParseCompleteMessage,
               BindCompleteMessage,
               RowDescriptionMessage,
               DataRowMessage,
               CommandCompleteMessage,
               ReadyForQueryMessage;

        // TODO: make receiveOne static
        ParseMessage parsemsg;
        DescribeMessage describemsg;
        BindMessage bindmsg;
        ExecuteMessage execmsg;
        bindmsg.num_parameter_values = args.length;

        LengthArray[args.length] values;
        foreach (i, arg; args)
        {
            values[i] = LengthArray(cast(ubyte[])(
                        to!string(arg).representation));
        }

        bindmsg.parameter_values  = values;
        SyncMessage sync;
        parsemsg.query_string = query_string;

        this.send(ParseMessage(this.payload_appender, parsemsg));
        this.send(BindMessage(this.payload_appender, bindmsg));
        this.send(DescribeMessage(this.payload_appender, describemsg));
        this.send(ExecuteMessage(this.payload_appender, execmsg));
        this.send(SyncMessage(this.payload_appender, sync));

        this.set.response = msg.receiveOne(this);
        enforce(this.set.response.peek!(ParseCompleteMessage),
                "Expected ParseCompleteMessage");

        this.set.response = msg.receiveOne(this);
        enforce(this.set.response.peek!(BindCompleteMessage),
                "Expected BindCompleteMessage");

        this.set.response = msg.receiveOne(this);

        if (auto rows = this.set.response.peek!(RowDescriptionMessage))
        {
            static bool getNextRow(ref Connection conn, ref PostgresRow row,
                    ref typeof(ResultSet.parsed_message) value,
                    ref typeof(ResultSet.response) response,
                    ref typeof(ResultSet.raw_row) raw_row)
            {
                auto rows = response.peek!(RowDescriptionMessage);
                // receive row. Receive first time
                value = conn.msg.receiveOne(conn);
                raw_row = value.peek!(DataRowMessage);

                if (raw_row)
                {
                    row.init(rows.fields, raw_row.columns);
                    return true;
                }
                else
                {
                    // the last received message is not an DataRowMessage, so
                    // keep processing it out of the loop
                    response = value;

                    enforce(response.peek!(CommandCompleteMessage),
                            "Expected CommandCompleteMessage");

                    response = conn.msg.receiveOne(conn);
                    enforce(response.peek!(ReadyForQueryMessage),
                            "Expected ReadyForQueryMessage");

                    return false;
                }
            }

            set.conn = &this;
            set.getNextRow = &getNextRow;
            return set;
        }

        this.set.clear();
        return this.set;
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

    /// Receive buffer
    const chunk_size = 1024;

    /// ditto
    ubyte[chunk_size] receive_buf;


    public ptrdiff_t receive (ref Appender!(ubyte[]) app,
            size_t bytes_need)
    {
        ptrdiff_t received = 0;

        while (received < bytes_need)
        {
            auto need = bytes_need - received;
            auto recv = need > chunk_size ? chunk_size : need;

            auto ret = this.sock.receive(this.receive_buf[0..need]);

            if (ret == Socket.ERROR)
            {
                writeln("Failed to receive from socket: ", this.sock.getErrorText());
                return ret;
            }

            app.put(this.receive_buf[0..need]);

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
