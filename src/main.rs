use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tiberius::numeric::Numeric;

use std::env;
use std::fs;
use std::fs::File;
use std::io;
use walkdir::WalkDir;
use sqlx::{migrate::MigrateDatabase, FromRow, Sqlite, SqlitePool};
use tiberius::{AuthMethod, Client, Config, Query};
use tokio::net::TcpStream;
use tokio_util::compat::TokioAsyncWriteCompatExt;

const DB_URL: &str = "sqlite://filehunter.db";

#[derive(Clone, FromRow, Serialize, Deserialize, Debug)]
struct FileData {
    hash: String,
    totalsize: u64,
    indb: u64,
    path: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Settings {
    database: String,
    host: String,
    port: u16,
    username: String,
    password: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    if !Sqlite::database_exists(DB_URL).await.unwrap_or(false) {
        println!("Creating database {}", DB_URL);
        match Sqlite::create_database(DB_URL).await {
            Ok(_) => println!("Create db success"),
            Err(error) => panic!("error: {}", error),
        }
    } else {
        println!("Database already exists");
    }

    let file_contents =
        std::fs::read_to_string("settings.json").expect("Should have been able to read the file");
    let settings: Settings =
        serde_json::from_str(&file_contents).expect("Should have been able to parse the file");


    let mut config = Config::new();

    config.database(settings.database);
    config.host(settings.host);
    config.port(settings.port);
    config.authentication(AuthMethod::sql_server(settings.username, settings.password));
    config.trust_cert();
    let tcp = TcpStream::connect(config.get_addr()).await?;
    tcp.set_nodelay(true)?;
    let mut client = Client::connect(config, tcp.compat_write()).await?;


    let db = SqlitePool::connect(DB_URL).await.unwrap();
    let _result = sqlx::query("CREATE TABLE IF NOT EXISTS file_data (id INTEGER PRIMARY KEY NOT NULL, hash VARCHAR(250), path VARCHAR(250), totalsize INTEGER, indb INTEGER );").execute(&db).await.unwrap();

    let args: Vec<_> = env::args().collect();
    if args.len() > 1 {
        for entry in WalkDir::new(&args[1]).into_iter().filter_map(|e| e.ok()) {
            let filepath = entry.path().to_owned();
            println!("{:#?}", filepath);
            if !entry.file_type().is_dir() {
                let mut file = File::open(filepath.clone())?;
                let mut hasher = Sha256::new();
                let _n = io::copy(&mut file, &mut hasher)?;
                let hash = hasher.finalize().clone();
                let hashstr = format!("{:x}", hash);
                let fpath = filepath.clone().into_os_string().into_string().unwrap().replace("\\","/").replace("/","[\\/]");
                println!("hash:{:#?}", hashstr);
                println!("path:{:#?}", fpath);
                let fsize = fs::metadata(filepath.clone())?.len() as u16;
                println!("size:{:#?}",fsize);
                let sql_query = "select * from file_link where path like (@P1)";
                let mut select = Query::new(sql_query);
                select.bind(fpath.clone());
                let stream = select.query(&mut client).await?;
                let row = stream.into_row().await?;
                let fieldid = match row {
                    Some(rowvalue) => rowvalue.get(0).unwrap_or(Numeric::new_with_scale(0, 0)).value(),
                    None => 0
                } as i32;
                print!("Row:{:#?}",fieldid);
                let _result = sqlx::query("INSERT INTO file_data (hash,path,totalsize,indb) VALUES (?,?,?,?)")
                    .bind(hashstr)
                    .bind(fpath)
                    .bind(fsize)
                    .bind(fieldid)
                    .execute(&db)
                    .await
                    .unwrap();
            }
        }
    }
    Ok(())
}
