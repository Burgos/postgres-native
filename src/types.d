/// Types definition to send over on wire 
/// Copyright: Copyright (c) 2016 Nemanja Boric

/// Length tagged array. This structure is serialized
/// in a way where the length of the data is sent
/// and then the data itself.
struct LengthArray
{
    import std.typecons;
    import std.array;
    import std.bitmanip;

    /// The length of the parameter value, in bytes (this count does not include
    /// itself). Can be zero. As a special case, -1 indicates a NULL parameter value.
    /// No value butyes follow in the null case.
    public int length;

    /// The value of the parameter, in the format indicated by the associated format
    /// code. Must match the length.
    public Nullable!(ubyte[]) value;

    /// Serializes this over into the stream for the network
    public void append (RefAppender!(ubyte[]) app)
    {
        if (value.isNull)
        {
            app.append(-1);
        }
        else
        {
            auto data = this.value.get();
            assert(data.length < uint.max);
            app.append(cast(uint)data.length);
            app ~= data;
        }
    }
}
