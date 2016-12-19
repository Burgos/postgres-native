module app;

void main()
{
    import message;
    import connection;
    import std.stdio;

    // try to connect to the
    // postgres, and see what we have
    auto conn = Connection("127.0.0.1", 5432, "burgos", "test-pass",
            "test");
    conn.connect();
    writeln("\tExecuting extended query: ");
    conn.query("SELECT * FROM stripovi WHERE id >= $1 and junak = $2", 1, "Zagor");
    writeln("\tExecuting normal query: ");
    conn.query("SELECT * FROM stripovi WHERE id > 1");
}
