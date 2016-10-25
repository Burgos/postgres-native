module app;

import message;
import connection;

void main()
{
    // try to connect to the
    // postgres, and see what we have
    auto conn = Connection("127.0.0.1", 5432, "burgos", "test-pass",
            "test");
    conn.connect();
}
