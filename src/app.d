module app;

void main(string[] args)
{
    import postgres.connection;
    import postgres.row;
    import std.stdio;
    import std.conv;
    import std.algorithm;

    // try to connect to the
    // postgres, and see what we have
    auto conn = Connection("127.0.0.1", 5432, "burgos", "test-pass",
            "test");
    conn.connect();

    auto num_iterations = 1;
    if (args.length > 1)
    {
        num_iterations = to!(int)(args[1]);
    }

    struct Result
    {
        int id;
        @as("junak")
        string glavni_junak;
        string naslov;
    }

    for(int i = 0; i < num_iterations; i++)
    {
        conn.query("SELECT * FROM stripovi WHERE id >= $1 and junak = $2", 1, "Zagor");
        conn.query("SELECT * FROM stripovi WHERE id >= 1",
                (PostgresRow row)
                {
                    import std.stdio;
                    writeln(row.toStruct!Result);
                });

        conn.queryRange("SELECT * FROM stripovi WHERE id >= 1")
            .map!(toStruct!Result)
            .filter!(x => x.glavni_junak == "Tex Viler").each!writeln;
    }
}
