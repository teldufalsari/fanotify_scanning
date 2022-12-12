use std::path::Path;

/// Database manager class.
/// 
/// It can either connected to a database or "default", 
/// which means there is no connection (`connection == None`)
/// to any database and all queries are processed if there
/// are no records in the database. this state is represented
#[derive(Default)]
pub struct DbManager {
    connection: Option<sqlite::Connection>,
}

impl DbManager {
    /// Create a new manager connected to the database.
    pub fn new(db_path: &Path) -> sqlite::Result<Self> {
        let connection = sqlite::open(db_path)?;
        Ok(DbManager { connection: Some(connection) })
    }

    /// Check if the are records containing `path` in the allow list
    pub fn allowlist_contains(&self, path: &Path) -> sqlite::Result<bool> {
        self.table_contains("allowlist", path)
    }

    /// Check if the are records containing `path` in the deny list
    pub fn denylist_contains(&self, path: &Path) -> sqlite::Result<bool> {
        self.table_contains("denylist", path)
    }

    /// Add `path` to the allow list.
    /// 
    /// When called on a default (not connected) manager, this
    /// is a no-op.
    pub fn add_to_denylist(&self, path: &Path) -> sqlite::Result<()> {
        self.add_into_table("denylist", path)
    }

    /// Check if the are records containing `path` in the `table`
    fn table_contains(&self, table: &str, path: &Path) -> sqlite::Result<bool> {
        if let Some(conn) = &self.connection {
            let query = format!("SELECT COUNT(*) FROM {table} WHERE path = ?");
            let mut statement = conn.prepare(query)?;
            statement.bind((1, path.to_str().unwrap()))?;
            statement.next()?;
            let count = statement.read::<i64, _>("COUNT(*)")?;
            Ok(count > 0)
        } else {
            Ok(false)
        }
    }

    /// Add `path` to the `table`.
    /// 
    /// When called on a default (not connected) manager, this
    /// is a no-op.
    fn add_into_table(&self, table: &str, path: &Path) -> sqlite::Result<()> {
        if let Some(conn) = &self.connection {
            let query = format!(
                "INSERT INTO {} (path) VALUES ('{}')", table, path.to_str().unwrap()
            );
            //conn.execute(query)
            Ok(())
        } else {
            Ok(())
        }
    }
}
