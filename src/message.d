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
    import std.variant;
    import std.meta;
    import std.exception;

    alias MessageTypes = AliasSeq!(AuthenticationMessage,
            ParameterStatusMessage);

    alias VariantN!(maxSize!MessageTypes,
            MessageTypes) ParsedMessage;

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

        switch (tag)
        {
            case 'R':
                auto msg = AuthenticationMessage(this.payload);
                debug (verbose) writefln("salt: [%(%x %)], type: %s", msg.salt.md5_salt, msg.format);
                ret = msg;
                break;
            case 'S':
                auto msg = ParameterStatusMessage(this.payload);
                ret = msg;
                break;
            case 'K':
                ret = BackendKeyDataMessage(this.payload);
                break;

            default:
                enforce(false, "Unexpected message: " ~ to!string(cast(int)tag));
        }

        debug (verbose)
        {
            writeln("Tag: ", tag);
            writeln("Length: ", len);
            writefln("Payload: %(%x, %)", payload);
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

        this.payload = this.constructMessage(this.payload,
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
    static ubyte[] constructMessage(Args...)(ref ubyte[] buf, char type, Args args)
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
            static if (is(typeof(param) == string))
            {
                app.put(param.representation);
                app.append(cast(ubyte)0);
            }
            else static if (isArray!(typeof(param)))
            {
                app ~= cast(ubyte[])param;
            }
            else
            {
                app.append(param);
            }
        }

        // final terminator
        app.append(cast(ubyte)0);

        // set the payload length
        buf.write!int(cast(int)(buf.length - (type != char.init ? char.sizeof : 0)),
                (type != char.init ? 1 : 0));
        return buf;
    }

    private ubyte[] payload; }

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
        ubyte[2] crypt_salt;
        ubyte[4] md5_salt;
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
                msg.salt.crypt_salt[] = payload.take(2)[];
                break;
            case MD5PASS:
                msg.salt.md5_salt[] = payload.take(4)[];
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

/// md5 password message
struct Md5PasswordMessage
{

    /// Constructs a MD5 password responde message
    /// using the given password and salt
    static ubyte[] opCall(ref ubyte[] buf, string username, string password, int salt)
    {
        return Md5PasswordMessage(buf, username, password, (cast(ubyte*)&salt)[0..int.sizeof]);
    }

    static ubyte[] opCall(ref ubyte[] buf, string username, string password, ubyte[] salt)
    {
        char[32 + 3] hash_buf; // md5+password string

        import std.digest.md;
        hash_buf[0..3] = "md5";
        hash_buf[3..$] = md5Of(
                    md5Of(password, username).toHexString!(LetterCase.lower), salt
                ).toHexString!(LetterCase.lower);

        Message.constructMessage(buf, 'p', hash_buf[]);
        return buf;
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
    /// name of the parameter
    public string name;

    /// value of the parameter
    public string value;

    /// generates parameter status message
    /// out of payload
    static ParameterStatusMessage opCall(Range)(Range payload)
    {
        import std.algorithm.iteration: splitter;
        typeof(this) msg;
        auto params = splitter(payload, cast(ubyte)0);
        msg.name = to!(string)(cast(char[])(params.take(1).array[0]));
        msg.value = to!(string)(cast(char[])(params.drop(1).take(1).array[0]));
        debug (verbose) writeln("name: ", msg.name, " value: ", msg.value);
        return msg;
    }
}

/// backend key data
struct BackendKeyDataMessage
{
    /// process id of this backend
    public int process_id;

    /// the secret key of this backend
    public int key;

    /// generates parameter status message
    /// out of payload
    static auto opCall(Range)(Range payload)
    {
        typeof(this) msg;
        msg.process_id = read!int(payload);
        msg.key = read!int(payload);

        debug (verbose) writeln("process id: ", msg.process_id,
                " secret key: ", msg.key);

        return msg;
    }
}
