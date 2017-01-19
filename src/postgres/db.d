/// Postgresql vibe.d database interface
/// Copyright: Copyright (c) 2016 Nemanja Boric
/// See also: mysql-native's db.d module
module postgres.db;

public import postgres.connection;

version (Have_vibe_d_core)
{
    import vibe.core.connectionpool;

    private class ConnectionClass
    {
        Connection* conn;

        /// host to connect to
        private string host;

        /// port to connect to
        private ushort port;

        /// Username used to connect
        private string username;

        /// Password used to connect
        private string password;

        /// Database to connect to
        private string database;

        /// Creates the connection object.
        /// Params:
        ///     host = address of the server
        ///     port = remote port of the server
        ///     username = user name to connect with
        ///     password = password to connect with
        ///     database = database to connect to
        ///     family = address family of the connection
        public this (string host, ushort port,
                string username, string password,
                string database)
        {
            this.host = host;
            this.port = port;
            this.username = username;
            this.password = password;
            this.database = database;
            this.conn = new Connection(this.host,
                    this.port,
                    this.username,
                    this.password,
                    this.database);
        }

        alias conn this;
    }

    class PostgresDB {
        /// host to connect to
        private string host;

        /// port to connect to
        private ushort port;

        /// Username used to connect
        private string username;

        /// Password used to connect
        private string password;

        /// Database to connect to
        private string database;

        ConnectionPool!ConnectionClass pool;

        /// Creates the connection object.
        /// Params:
        ///     address = address of the server
        ///     port = remote port of the server
        ///     username = user name to connect with
        ///     password = password to connect with
        ///     database = database to connect to
        ///     family = address family of the connection
        public this (string address, ushort port,
                string username, string password,
                string database)
        {
            this.host = host;
            this.port = port;
            this.username = username;
            this.password = password;
            this.database = database;
            this.pool = new ConnectionPool!ConnectionClass(&createConnection);
        }

        /// Gets connection for client
        auto lockConnection()
        {
            auto conn = pool.lockConnection();
            conn.ensureConnected();
            return conn;
        }

        private ConnectionClass createConnection()
        {
            return new ConnectionClass(this.host, this.port,
                    this.username, this.password,
                    this.database);
        }
    }
}
