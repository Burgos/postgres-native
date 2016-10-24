module app;

import message;
import connection;

void main()
{
    // try to connect to the
    // postgres, and see what we have
    auto conn = Connection("127.0.0.1", 5432, "burgos");
    conn.connect();

    Message m;
    m.sendStartup(conn, "test");
    m.receiveOne(conn);
}
