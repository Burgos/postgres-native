/// Message received from Postgres
/// Copyright: Copyright (c) 2016 Nemanja Boric
module message;

import connection;
import types;

import std.range;
import std.conv;
import std.array;
import std.bitmanip;
import std.string;

debug (verbose) import std.stdio;

/// Indicates source of the message
enum Origin
{
    FRONTEND,
    BACKEND
}

/// This struct encapculates
/// message received and sent from the backend.
/// It also keeps a buffer there, so messages
/// are allowed to reuse the same buffer over
/// and over again, without no need for realloc
struct Message
{
    import std.variant;
    import std.meta;
    import std.traits;
    import std.exception;

    /// Helper template to get the message type from a message
    enum MessageTag(MessageType) = MessageType.Tag;

    /// Identity template, used to get away with __traits in
    /// getMessageStruct:
    //// Basic type expected, not __traits
    alias Identity(alias X) = X;

    /// Gets the message struct from the string
    alias getMessageStruct (alias S) =
        Identity!(__traits(getMember, message, S));

    /// Checks if the struct is tagged with a field
    /// named Tag
    enum hasMessageTag(alias S) =
        is (typeof(MessageTag!(__traits(getMember, message, S))));

    /// List of all message types
    alias MessageTypes = staticMap!(getMessageStruct,
            Filter!(hasMessageTag, __traits(allMembers, message)));

    // make sure all tags are unique at compile time
    /* DISABLED - ERROR and EXECUTE messages have the same tag
       static assert (MessageTypes.length ==
        NoDuplicates!(staticMap!(MessageTag, MessageTypes)).length,
        "Make sure all Message types contain exactly one distinct tag.");
        */

    /// Return value - variant able to hold all possible messages
    alias VariantN!(maxSize!MessageTypes,
            MessageTypes) ParsedMessage;

    // Declare message type buffers for every message type
    // so we don't allocate every time we receive the same
    // message type.
    mixin(generateMembers!(MessageTypes));

    /// Generates list of members for every message type
    static string generateMembers(types...)()
    {
        string ret;
        foreach (type; types)
        {
            static if (type.origin == Origin.BACKEND)
            {
                ret ~= type.stringof ~ " msg_" ~ type.stringof ~ ";\n";
            }
        }

        return ret;
    }

    /// Receives a message from the server
    public ParsedMessage receiveOne (ref Connection c)
    {
        ParsedMessage ret;

        // Read tag, length and then payload
        char tag;
        c.receive(tag);
        int len;
        c.receive(len);

        // Receive payload
        payload.length = len - len.sizeof;
        c.receive(payload);

        foreach (msg_type; MessageTypes)
        {
            if (tag == msg_type.Tag)
            {
                static if (msg_type.origin == Origin.BACKEND)
                {
                    mixin("ret = this.msg_" ~ msg_type.stringof ~ "(this.payload);");
                }
            }
        }

        enforce(ret.hasValue, "Unexpected message: " ~ to!string(cast(int)tag));

        debug (verbose)
        {
            writeln("Tag: ", tag);
            writeln("Length: ", len);
            writefln("Payload: %(%x, %)", payload);
            writefln("Message: %s", ret);
        }

        return ret;
    }

    /// sends startup packet to backend
    ubyte[] sendStartup (string database, string username)
    {
        ushort protocol_major = 3;
        ushort protocol_minor = 0;

        int protocol = ~0;
        protocol &= protocol_major << 16 | protocol_minor;

        this.payload = this.constructMessage!(true)(this.payload,
                char.init, // startup message, no type
                protocol,
                "database", database,
                "user", username);

        debug (verbose) writeln("Payload: ", payload);
        return this.payload;
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
    static ubyte[] constructMessage(alias final_terminator = false,
            Args...)(ref ubyte[] buf, char type, Args args)
    {
        import std.traits;

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
            // Length-prepended arrays are serialized
            // with the length first, and then the array
            static if (is(typeof(param) == LengthArray))
            { 
                param.append(app);
            }
            else static if (is(typeof(param) == string))
            {
                app.put(param.representation);
                app.append(cast(ubyte)0);
            }
            else static if(isArray!(typeof(param)))
            {
                static if (ElementType!(typeof(param)).sizeof == ubyte.sizeof)
                {
                    app ~= cast(ubyte[])param;
                }
                else
                {
                    foreach (el; param)
                    {
                        static if (is(el: short))
                        {
                            app.append(cast(short)el);
                        }
                        else static if(is(el: int))
                        {
                            app.append(cast(int)el);
                        }
                        else static if (is(ElementType!(typeof(param)) == LengthArray))
                        {
                            el.append(app);
                        }
                        else
                        {
                            app.append(el);
                        }
                    }
                }
            }
            else
            {
                app.append(param);
            }
        }

        // final terminator
        static if (final_terminator)
            app.append(cast(ubyte)0);

        // set the payload length
        buf.write!int(cast(int)(buf.length - (type != char.init ? char.sizeof : 0)),
                (type != char.init ? 1 : 0));
        return buf;
    }

    private ubyte[] payload; }

struct AuthenticationMessage
{
    /// Message type tag
    /// Sent as a first byte of a message
    enum Tag = 'R';

    /// Indicates that this message originates from backend
    enum origin = Origin.BACKEND;

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
        ubyte[2] crypt_salt;
        ubyte[4] md5_salt;
    }

    Salt salt;

    /// Type of encryption
    AuthFormat format;

    /// Constructs an auth. message from the given
    /// payload
    auto opCall(Range)(Range payload)
    {
        this.format = cast(AuthFormat)read!int(payload);

        with (AuthFormat) switch (this.format)
        {
            case CRYPTPASS:
                this.salt.crypt_salt[] = payload.take(2)[];
                break;
            case MD5PASS:
                this.salt.md5_salt[] = payload.take(4)[];
                break;
            case CLEARTEXT:
            case OK:
                break;
            default:
                throw new Exception("Auth format " ~ to!(string)(this.format) ~ " not supported.");
        }

        return this;
    }
}

/// md5 password message
struct Md5PasswordMessage
{
    /// Message type tag
    /// Sent as a first byte of a message
    enum Tag = 'p';

    /// Indicates that this message originates from frontend
    enum origin = Origin.FRONTEND;

    /// Constructs a MD5 password responde message
    /// using the given password and salt
    static ubyte[] opCall(ref ubyte[] buf, string username, string password, int salt)
    {
        return Md5PasswordMessage(buf, username, password, (cast(ubyte*)&salt)[0..int.sizeof]);
    }

    static ubyte[] opCall(ref ubyte[] buf, string username, string password, ubyte[] salt)
    {
        ubyte[32 + 4] hash_buf; // md5+password string

        import std.digest.md;
        hash_buf[0..3] = "md5".representation;
        hash_buf[3..$-1] = md5Of(
                    md5Of(password, username).toHexString!(LetterCase.lower), salt
                ).toHexString!(LetterCase.lower).representation;
        hash_buf[$-1..$] = cast(ubyte)0;

        Message.constructMessage(buf, Tag, hash_buf[]);
        return buf;
    }

    /// Dummy opCall, needed to satisfy message-generic
    /// opCall call.
    static typeof(this) opCall(ubyte[])
    {
        import std.exception;
        // not supported
        enforce(false, "Parsing Md5PasswordMessage is not supported");
        assert(false);
    }

    unittest
    {
        ubyte[] buf;
        Md5PasswordMessage(buf, "burgos", "test-pass", [0x91, 0x47, 0x28, 0x72]);

        ubyte[] expected = [0x70, 0x00, 0x00, 0x00, 0x28, 0x6d, 0x64, 0x35,
            0x37, 0x35, 0x33, 0x65, 0x62, 0x31, 0x64, 0x31, 0x36, 0x38, 0x39,
            0x32, 0x32, 0x32, 0x35, 0x37, 0x37, 0x39, 0x31, 0x32, 0x35, 0x63,
            0x32, 0x39, 0x66, 0x39, 0x62, 0x30, 0x32, 0x34, 0x37, 0x64, 0x00];

        assert (buf == expected);
    }
}

/// parameter status
struct ParameterStatusMessage
{
    /// Message type tag
    /// Sent as a first byte of a message
    enum Tag = 'S';

    /// Indicates that this message originates from backend
    enum origin = Origin.BACKEND;

    /// name of the parameter
    public string name;

    /// value of the parameter
    public string value;

    /// generates parameter status message
    /// out of payload
    auto opCall(Range)(Range payload)
    {
        import std.algorithm.iteration: splitter;
        auto params = splitter(payload, cast(ubyte)0);
        this.name = to!(string)(cast(char[])(params.take(1).array[0]));
        this.value = to!(string)(cast(char[])(params.drop(1).take(1).array[0]));
        debug (verbose) writeln("name: ", this.name, " value: ", this.value);
        return this;
    }
}

/// backend key data
struct BackendKeyDataMessage
{
    /// Message type tag
    /// Sent as a first byte of a message
    enum Tag = 'K';

    /// Indicates that this message originates from backend
    enum origin = Origin.BACKEND;

    /// process id of this backend
    public int process_id;

    /// the secret key of this backend
    public int key;

    /// generates parameter status message
    /// out of payload
    auto opCall(Range)(Range payload)
    {
        this.process_id = read!int(payload);
        this.key = read!int(payload);

        debug (verbose) writeln("process id: ", this.process_id,
                " secret key: ", this.key);

        return this;
    }
}

/// ready for query
struct ReadyForQueryMessage
{
    /// Message type tag
    /// Sent as a first byte of a message
    enum Tag = 'Z';

    /// Indicates that this message originates from backend
    enum origin = Origin.BACKEND;

    /// transaction status indicator
    /// TODO: make enum
    public char transaction_status;

    /// generates parameter status message
    /// out of payload
    auto opCall(Range)(Range payload)
    {
        this.transaction_status = read!char(payload);
        debug (verbose) writeln("transaction status: ", this.transaction_status);

        return this;
    }
}

/// Close message.
struct CloseMessage
{
    /// Message type tag
    /// Sent as a first byte of a message
    enum Tag = 'C';

    /// Indicates that this message originates from backend
    enum origin = Origin.BACKEND;

    /// Type of the close message
    enum Type: char
    {
        PREPARED_STATEMENT = 'S',
        PORTAL = 'P',
    }

    /// ditto
    public Type type;

    /// Name of the prepared statement or portal
    /// to close. (an empty string selects the unnamed prepared statement
    /// or portal).
    public string name;

    /// generates Close message
    /// out of payload
    auto opCall(Range)(Range payload)
    {
        this.type = read!Type(payload);
        this.name = to!string(cast(char[])payload.array);

        return this;
    }

    /// provides text representation
    public string toString()
    {
        import std.format;
        auto app = appender!string;

        app ~= "Close: \n";
        app ~= format("Type: %s, Name: %s\n",
                this.type, this.name);

        return app.data;
    }
}

/// error message
struct ErrorMessage
{
    /// Message type tag
    /// Sent as a first byte of a message
    enum Tag = 'E';

    /// Indicates that this message originates from backend
    enum origin = Origin.BACKEND;

    enum FieldType: char
    {
        SEVERITY = 'S',
        CODE = 'C',
        MESSAGE = 'M',
        DETAIL = 'D',
        HINT = 'H',
        POSITION = 'P',
        INTERNAL_POSITION = 'p',
        INTERNAL_QUERY = 'q',
        SCHEMA_NAME = 's',
        TABLE_NAME = 't',
        COLUMN_NAME = 'c',
        DATA_TYPE = 'd',
        CONSTRAINT = 'n',
        FILE = 'F',
        LINE = 'L',
        ROUTINE = 'R',
    }

    /// information about error
    public string[FieldType] info;

    /// generates error message
    /// out of payload
    auto opCall(Range)(Range payload)
    {
        import std.algorithm.iteration: splitter;

        // split the error message
        // into range of TSTR\0
        auto params = splitter(payload, cast(ubyte)0);

        foreach (param; params)
        {
            if (param.empty)
                break;

            auto type = read!char(param);
            auto value = to!string(cast(char[])param.array);
            this.info[to!FieldType(type)] = value;
        }

        return this;
    }

    /// provides text representation
    public string toString()
    {
        import std.format;
        auto app = appender!string;
        app ~= "Error: \n";

        foreach (type, value; info)
        {
            app ~= format("%s: %s\n", type, value);
        }

        return app.data;
    }
}


/// Query message, sent to the backend
struct QueryMessage
{
    public enum Tag = 'Q';

    /// Indicates that this message originates from frontend
    enum origin = Origin.FRONTEND;

    /// Constructs a query message using the
    /// query string
    static ubyte[] opCall(ref ubyte[] buf, string query)
    {
        Message.constructMessage(buf, Tag, query);
        return buf;
    }

    /// Dummy opCall, needed to satisfy message-generic
    /// opCall call.
    static typeof(this) opCall(ubyte[])
    {
        // not supported
        assert(false, "Parsing MessageQuery is not supported");
    }
}

/// RowDescription message
struct RowDescriptionMessage
{
    /// Message type tag
    /// Sent as a first byte of a message
    enum Tag = 'T';

    /// Indicates that this message originates from backend
    enum origin = Origin.BACKEND;

    /// Number of fields in the row
    short number_of_fields;

    /// Individual field descriptions
    struct Field
    {
        /// field name
        string name;

        /// table id
        int table_id;

        /// column id
        short column_id;

        /// data type id
        int data_type_id;

        /// data type size. Negative means
        /// variable length
        short data_type_len;

        /// Type modifier. This is type-specific
        /// value
        int data_type_mod;

        /// Format code
        enum Format: short
        {
            TEXT = 0,
            BINARY = 1
        }

        Format format;
    }

    Field[] fields;

    /// generates RowDescription message
    /// out of payload
    auto opCall(Range)(Range payload)
    {
        this.number_of_fields = read!short(payload);

        this.fields.length = 0;
        this.fields.assumeSafeAppend;
        this.fields.length = this.number_of_fields;

        for (auto i = 0; i < this.number_of_fields; i++)
        {
            import std.algorithm.searching: until;
            Field field;

            field.name = to!string(cast(char[])payload.until(0).array);
            payload = payload.drop(field.name.length + 1);

            field.table_id = read!int(payload);
            field.column_id = read!short(payload);
            field.data_type_id = read!int(payload);
            field.data_type_len = read!short(payload);
            field.data_type_mod = read!int(payload);

            field.format = cast(Field.Format)read!short(payload);
            this.fields[i] = field;
        }

        debug (verbose)
        {
            writeln("Row description object. Number of fields: ", this.number_of_fields);

            foreach (f; this.fields)
            {
                writefln("Name: %s\n" ~
                         "table id: %d\n" ~
                         "column id: %d\n" ~
                         "data_type_id: %d\n" ~
                         "data_type_len: %d\n" ~
                         "data_type_mod: %d\n" ~
                         "format: %s\n",
                         f.tupleof);
            }
        }

        return this;
    }
}

/// DataRow message
struct DataRowMessage
{
    /// Message type tag
    /// Sent as a first byte of a message
    enum Tag = 'D';

    /// Indicates that this message originates from backend
    enum origin = Origin.BACKEND;

    /// number of columns that follows
    short number_of_columns;

    struct Column
    {
        /// Column value length. -1 indicates NULL.
        int length;

        /// Value in the specified format by RowDescriptionMessage
        ubyte[] value;
    }

    Column[] columns;

    /// generates RowDescription message
    /// out of payload
    auto opCall(Range)(Range payload)
    {
        this.number_of_columns = read!short(payload);
        this.columns.length = 0;
        assumeSafeAppend(this.columns);
        this.columns.length = this.number_of_columns;

        for (auto i = 0; i < this.number_of_columns; i++)
        {
            auto col = &this.columns[i];
            col.length = read!int(payload);

            auto value = payload.take(col.length);
            col.value.length = 0;
            col.value.assumeSafeAppend.length = value.length;
            col.value[0..$] = value[0..$];

            payload = payload.drop(col.length);
        }

        debug (verbose)
        {
            writeln("Data Row. Number of columns: ", this.number_of_columns);

            foreach (c; this.columns)
            {
                writeln(c.value);
            }
        }

        return this;
    }
}


/******************************************************************************

    Extended query protocol support.

******************************************************************************/

/// Object ID enumeration for types. From pg_type.h
enum TypeOID: int
{
    NOT_SPECIFIED  = 0,
    BOOL           = 16,
    BYTEA          = 17,
    CHAR           = 18,
    NAME           = 19,
    INT8           = 20,
    INT2           = 21,
    INT2VECTOR     = 22,
    INT4           = 23,
    REGPROC        = 24,
    TEXT           = 25,
    OID            = 26,
    TID            = 27,
    XID            = 28,
    CID            = 29,
    OIDVECTOR      = 30,
    POINT          = 600,
    LSEG           = 601,
    PATH           = 602,
    BOX            = 603,
    POLYGON        = 604,
    LINE           = 628,
    FLOAT4         = 700,
    FLOAT8         = 701,
    ABSTIME        = 702,
    RELTIME        = 703,
    TINTERVAL      = 704,
    UNKNOWN        = 705,
    CIRCLE         = 718,
    CASH           = 790,
    INET           = 869,
    CIDR           = 650,
    BPCHAR         = 1042,
    VARCHAR        = 1043,
    DATE           = 1082,
    TIME           = 1083,
    TIMESTAMP      = 1114,
    TIMESTAMPTZ    = 1184,
    INTERVAL       = 1186,
    TIMETZ         = 1266,
    ZPBIT          = 1560,
    VARBIT         = 1562,
    NUMERIC        = 1700,
}

/// Parse message, sent to the backend.
struct ParseMessage
{
    public enum Tag = 'P';

    /// Indicates that this message originates from frontend
    enum origin = Origin.FRONTEND;

    /// The name of the destination prepared statement (an empty string selects
    /// the unnamed prepared statement).
    public string prepared_statement_name;

    /// The query string to be parsed
    public string query_string;

    /// The numer of parameter data types specified (can be zero). Note that this
    /// is not an indication of the number of parameters that might appear in the
    /// query string, only the number that the frontend wants to prespecify types
    /// for.
    public ushort num_data_types;

    /// Object ID of the parameter data type. Placing a zero here is equivalent
    /// of leaving the type unspecified.
    public TypeOID[] data_types = [TypeOID.NOT_SPECIFIED];

    /// Constructs a Parse message
    static ubyte[] opCall(ref ubyte[] buf, ParseMessage msg)
    {
        Message.constructMessage(buf, Tag,
                msg.prepared_statement_name,
                msg.query_string,
                msg.num_data_types);
                //0);///msg.data_types);*/

        return buf;
    }

    /// Dummy opCall, needed to satisfy message-generic
    /// opCall call.
    static typeof(this) opCall(ubyte[])
    {
        // not supported
        assert(false, "Parsing ParseMessage is not supported");
    }
}

/// Bind message. Sent to the backend binding data for each placeholder
/// specified in Parse message.
struct BindMessage
{
    public enum Tag = 'B';

    /// Indicates that this message originates from frontend
    enum origin = Origin.FRONTEND;

    /// The name of the destination portal (an empty string selects the
    /// unnamed portal).
    public string dest_portal_name;

    /// The name of the source prepared statement (an empty string selects
    /// the unnamed prepared statement).
    public string source_prep_stmt_name;

    /// The number of parameter format codes that follow. This can be zero
    /// to indicate that there are no parameters, or that all parameteres
    /// uses the default format (text); or one, in which case the specified
    /// format code is applied to all parameters; or it can equal the actual
    /// number of parameters.
    public short num_format_codes;

    /// Format codes
    public enum FormatCodes: short
    {
        TEXT = 0,
        BINARY = 1,
    }

    /// Ditto
    public FormatCodes[] param_format_codes;

    /// The number of parameter values that follow (possibly zero). This must
    /// match the number of parameters needed by the query.
    public short num_parameter_values;

    /// List of the parameter values
    public LengthArray[] parameter_values;


    /// The number of result-column format codes that follow. This can be zero
    /// to indicate that there are no result columns, or that all parameteres
    /// uses the default format (text); or one, in which case the specified
    /// format code is applied to all result columns; or it can equal the actual
    /// number of result columns.
    public short num_result_format_codes;

    /// The result-column format codes.
    public FormatCodes[] result_format_codes;

    /// Constructs a Bind message
    static ubyte[] opCall(ref ubyte[] buf, BindMessage msg)
    {
        Message.constructMessage(buf, Tag,
                msg.dest_portal_name,
                msg.source_prep_stmt_name,
                msg.num_format_codes,
                msg.param_format_codes,
                msg.num_parameter_values,
                msg.parameter_values,
                msg.num_result_format_codes,
                msg.result_format_codes);

        return buf;
    }

    version (unittest)
    {
        import std.typecons: Nullable;
    }
    unittest
    {
        BindMessage msg;
        msg.dest_portal_name = "A";
        msg.source_prep_stmt_name = "B";
        msg.num_format_codes = 2;
        msg.param_format_codes = [FormatCodes.TEXT, FormatCodes.BINARY];

        msg.num_parameter_values = 2;

        auto v1 = LengthArray(0, Nullable!(ubyte[])(cast(ubyte[])[1, 2, 3, 4]));
        auto v2 = LengthArray(0, Nullable!(ubyte[])(cast(ubyte[])[2, 3, 4, 5]));

        msg.parameter_values = [v1, v2];

        msg.num_result_format_codes = 3;
        msg.result_format_codes = [FormatCodes.TEXT, FormatCodes.BINARY,
            FormatCodes.TEXT];

        ubyte[] buf;
        BindMessage(buf, msg);

        assert(buf[0] == cast(ubyte)BindMessage.Tag);
        assert(buf[5] == msg.dest_portal_name.representation[0]);
        assert(buf[6] == 0);
        assert(buf[7] == msg.source_prep_stmt_name.representation[0]);
        assert(buf[8] == 0);

        auto r = buf[9..$];
        assert(read!short(r) == msg.num_format_codes);
        assert(read!ushort(r) == FormatCodes.TEXT);
        assert(read!ushort(r) == FormatCodes.BINARY);
        assert(read!ushort(r) == msg.num_parameter_values);
        assert(read!int(r) == 4);
        assert(r.take(4).array == cast(ubyte[])[1, 2, 3, 4]);
        r = r.drop(4);
        assert(read!int(r) == 4);
        assert(r.take(4).array == cast(ubyte[])[2, 3, 4, 5]);
        r = r.drop(4);
        assert(read!short(r) == msg.num_result_format_codes);
        assert(read!ushort(r) == FormatCodes.TEXT);
        assert(read!ushort(r) == FormatCodes.BINARY);
        assert(read!ushort(r) == FormatCodes.TEXT);
    }

    /// Dummy opCall, needed to satisfy message-generic
    /// opCall call.
    static typeof(this) opCall(ubyte[])
    {
        // not supported
        assert(false, "Parsing BindMessage is not supported");
    }
}

/// Parse completed
struct ParseCompleteMessage
{
    /// Message type tag
    /// Sent as a first byte of a message
    enum Tag = '1';

    /// Indicates that this message originates from backend
    enum origin = Origin.BACKEND;

    /// generates parameter status message
    /// out of payload
    auto opCall(Range)(Range payload)
    {
        return this;
    }
}
/// Bind completed
struct BindCompleteMessage
{
    /// Message type tag
    /// Sent as a first byte of a message
    enum Tag = '2';

    /// Indicates that this message originates from backend
    enum origin = Origin.BACKEND;

    /// generates parameter status message
    /// out of payload
    auto opCall(Range)(Range payload)
    {
        return this;
    }
}

/// Describe message. Asks for RowDescription message
struct DescribeMessage
{
    public enum Tag = 'D';

    /// Indicates that this message originates from frontend
    enum origin = Origin.FRONTEND;

    enum Type: ubyte
    {
        STATEMENT = 'S',
        PORTAL = 'P'
    }

    /// S to describe a prepared statement, P to describe a portal
    public Type type = Type.PORTAL;

    /// The name of the portal or statement (an empty string selects the
    /// unnamed one).
    public string name;


    /// Constructs a Bind message
    static ubyte[] opCall(ref ubyte[] buf, DescribeMessage msg)
    {
        Message.constructMessage(buf, Tag,
                msg.type,
                msg.name);

        return buf;
    }

    /// Dummy opCall, needed to satisfy message-generic
    /// opCall call.
    static typeof(this) opCall(ubyte[])
    {
        // not supported
        assert(false, "Parsing ExecuteMessage is not supported");
    }
}

/// Execute message. Starts the extended query
struct ExecuteMessage
{
    public enum Tag = 'E';

    /// Indicates that this message originates from frontend
    enum origin = Origin.FRONTEND;

    /// The name of the portal (an empty string selects the
    /// unnamed portal).
    public string portal_name;

    /// Maximum number of rows to return. Zero denotes
    /// "no limit".
    public int max_rows;


    /// Constructs a Bind message
    static ubyte[] opCall(ref ubyte[] buf, ExecuteMessage msg)
    {
        Message.constructMessage(buf, Tag,
                msg.portal_name,
                msg.max_rows);

        return buf;
    }

    /// Dummy opCall, needed to satisfy message-generic
    /// opCall call.
    static typeof(this) opCall(ubyte[])
    {
        // not supported
        assert(false, "Parsing ExecuteMessage is not supported");
    }
}

// TODO: PortalSuspended

/// CommandComplete message
struct CommandCompleteMessage
{
    /// Message type tag
    /// Sent as a first byte of a message
    enum Tag = 'C';

    /// Indicates that this message originates from backend
    enum origin = Origin.BACKEND;

    /// The command tag. This is usually a single word that identifies which
    //SQL command was completed.
    public string tag;

    /// generates RowDescription message
    /// out of payload
    auto opCall(Range)(Range payload)
    {
        import std.algorithm.searching: until;
        this.tag = to!string(cast(char[])payload.until(0).array);
        return this;
    }
}

/// Sync message
struct SyncMessage
{
    public enum Tag = 'S';

    /// Indicates that this message originates from frontend
    enum origin = Origin.FRONTEND;

    /// Constructs a Sync message
    static ubyte[] opCall(ref ubyte[] buf, SyncMessage msg)
    {
        Message.constructMessage(buf, Tag);
        return buf;
    }

    /// Dummy opCall, needed to satisfy message-generic
    /// opCall call.
    static typeof(this) opCall(ubyte[])
    {
        // not supported
        assert(false, "Parsing SyncMessage is not supported");
    }
}
