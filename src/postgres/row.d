module postgres.row;

// Inspired by mysql-limited
// Can be found at https://github.com/eBookingServices/mysql-lited/
private struct IgnoreAttribute {}
private struct NameAttribute { const(char)[] name; }


@property auto ignore()
{
	return IgnoreAttribute();
}

@property auto as(const(char[])name)
{
	return NameAttribute(name);
}

/// Converts the row into the struct
public auto ref toStruct(T)(PostgresRow row)
{
    T x;
    // TODO: support tuple via isTuple
    row.structurise!(T)(x);

    return x;
}

struct PostgresRow
{
    import postgres.message;

	/// fields description for the row
	package RowDescriptionMessage.Field[] fields;

	/// field values for the row
	package DataRowMessage.Column[] values;

	/// Sets up the row from the internal state
	/// received from the server
	package void init(typeof(fields) fields, typeof(values) values)
	{
		this.fields = fields;
		this.values = values;
	}

    private void structurise(T)(ref T x)
    {
        import std.traits;
        foreach (member; __traits(allMembers, T))
        {
            // Find it inside fields
            // TODO: do hashing here, please
            foreach (i, ref field; this.fields)
            {
                import std.stdio;
                import std.conv;

                alias MemberType = typeof(__traits(getMember, x, member));

                static if (hasUDA!(__traits(getMember, x, member), NameAttribute))
                {
                    enum path = getUDAs!(__traits(getMember, x, member), NameAttribute)[0].name;
                }
                else
                {
                    enum path = member;
                }

                if (field.name == path)
                {
                    static if (is(typeof(this.values[i].value) == MemberType))
                    {
                        __traits(getMember, x, member) = cast(MemberType)this.values[i].value;
                    }
                    else
                    {
                        __traits(getMember, x, member) = to!MemberType(this.values[i].value);
                    }
                    break;
                }
                //TODO: pay attention to errors
            }
        }
    }
}
