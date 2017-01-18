module app;

void run_test(int num_iterations)
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

    struct Result
    {
        int id;
        @as("junak")
        string glavni_junak;
        string naslov;
    }

    for(int i = 0; i < num_iterations; i++)
    {
        conn.query("SELECT * FROM stripovi WHERE id >= 1",
                (PostgresRow row)
                {
                    import std.stdio;
                    writeln(row.toStruct!Result);
                });

        conn.queryRange("SELECT * FROM stripovi WHERE id >= 1")
            .map!(toStruct!Result)
            .filter!(x => x.glavni_junak == "Tex Viler").each!writeln;

        writeln("Extended query");
        conn.queryRange("SELECT * FROM stripovi WHERE id >= $1", 1)
            .map!(toStruct!Result)
            .filter!(x => x.glavni_junak == "Teks Viler").each!writeln;
    }
}

static if(__traits(compiles, (){ import vibe.core.net; } ))
{
    import vibe.core.core;

    int main(string[] args)
    {
        import vibe.core.args;

        int num_iterations = 1;
        readOption("num", &num_iterations, "Number of iterations to run");

        void run ()
        {
            run_test(num_iterations);
            exitEventLoop();
        }

        auto task = runTask(&run);

        return runApplication();
    }
}
else
{
    void main(string[] args)
    {
        import std.stdio;
        writeln("old main");

        auto num_iterations = 1;
        if (args.length > 1)
        {
            import std.conv;
            num_iterations = to!(int)(args[1]);
        }

        run_test(num_iterations);
    }
}
