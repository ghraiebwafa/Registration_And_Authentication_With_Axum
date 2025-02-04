mod models;
mod config;
mod dtos;
mod error;
mod db;
 use config::Config;
use db::DBClient;
#[derive(Debug,Clone)]
pub struct AppState {
    pub env:Config,
    pub db_client: DBClient,
}
#[tokio::main]
fn main() {
}
