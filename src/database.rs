use std::env;
use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use tracing::info;

use crate::model::ReverseDependency;

#[derive(Debug, Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn new() -> Result<Self> {
        // 从环境变量获取数据库连接信息
        let db_host = env::var("PG_HOST").unwrap_or_else(|_| "localhost".to_string());
        let db_user = env::var("PG_USER").unwrap_or_else(|_| "mega".to_string());
        let db_pass = env::var("PG_PASSWORD").unwrap_or_else(|_| "mega".to_string());
        let db_name = env::var("PG_DATABASE").unwrap_or_else(|_| "crates_io_db".to_string());

        let connection_string =
            format!("postgres://{}:{}@{}/{}", db_user, db_pass, db_host, db_name);

        info!("连接到数据库 {}@{}/{}", db_user, db_host, db_name);

        // 创建连接池
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .acquire_timeout(Duration::from_secs(3))
            .connect(&connection_string)
            .await
            .context("无法连接到数据库")?;

        info!("数据库连接成功");

        Ok(Self { pool })
    }

    // 查询crate的所有版本
    pub async fn query_crate_versions(&self, crate_name: &str) -> Result<Vec<String>> {
        info!("查询crate {} 的所有版本", crate_name);

        let rows = sqlx::query(
            "SELECT num FROM versions
             JOIN crates ON versions.crate_id = crates.id
             WHERE crates.name = $1
             ORDER BY versions.id DESC",
        )
        .bind(crate_name)
        .fetch_all(&self.pool)
        .await
        .context("查询crate版本失败")?;

        let versions = rows.iter().map(|row| row.get::<String, _>("num")).collect();

        info!("找到 {} 个版本", rows.len());
        Ok(versions)
    }

    // 查询依赖某个crate的所有crates
    pub async fn query_dependents(&self, crate_name: &str) -> Result<Vec<ReverseDependency>> {
        info!("查询依赖 {} 的所有crates", crate_name);

        let query = "WITH target_crate AS (
                SELECT id FROM crates WHERE name = $1
            )
            SELECT DISTINCT c.name, v.num, d.req
            FROM dependencies d
            JOIN versions v ON d.version_id = v.id
            JOIN crates c ON v.crate_id = c.id
            WHERE d.crate_id = (SELECT id FROM target_crate)
            AND d.req IS NOT NULL
            ORDER BY c.name, v.num";

        let rows = sqlx::query(query)
            .bind(crate_name)
            .fetch_all(&self.pool)
            .await
            .context("查询依赖者失败")?;

        let dependents = rows
            .iter()
            .map(|row| {
                ReverseDependency::new(
                    row.get::<String, _>("name"),
                    row.get::<String, _>("num"),
                    row.get::<String, _>("req"),
                )
            })
            .collect();

        info!("找到 {} 个依赖者", rows.len());
        Ok(dependents)
    }
}
