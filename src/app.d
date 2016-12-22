module app;

void main(string[] args)
{
    import message;
    import connection;
    import std.stdio;
    import std.conv;

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


    for(int i = 0; i < num_iterations; i++)
    {
        conn.query("SELECT * FROM stripovi WHERE id >= $1 and junak = $2", 1, "Zagor");
        conn.query("SELECT * FROM stripovi WHERE id > 1");
    }
}
