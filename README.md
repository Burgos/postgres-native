# Lightweight native D client for PostgreSQL database

`postgres-native` is a native D implementation of the Postgres frontend/backend
protocol. It is built in a way to pay attention to a memory allocations (memory
will be reused, and only growing if the backend sends results that was larger
than any of the results ever encountered). This way GC access can be completely
avoided after some initial time.

## Usage examples

```D
    import postgres.connection;
    import postgres.row;
    import std.stdio;
    import std.algorighm;

    auto conn = Connection("127.0.0.1", 5432, "burgos", "pass",
            "dbname");
    conn.connect();

    struct ComicBook
    {
        int id;
        @as("comic_hero")
        string hero;
        string title;
    }

    // Using callback for every row
    conn.query("SELECT id, comic_hero, title FROM commics WHERE id > 1",
        (PostgresRow row)
        {
            import std.stdio;
            writeln(row.toStruct!Result);
        });

    // Using range interface
    conn.queryRange("SELECT * FROM comic WHERE id >= 1")
         .map!(toStruct!Result)
         .filter!(x => x.hero == "Tex Willer").each!(writeln);
```
