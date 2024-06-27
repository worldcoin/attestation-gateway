use std::{env, net::SocketAddr};

use aide::openapi::{Info, OpenApi};
use axum::Extension;
use redis::aio::ConnectionManager;
use tokio::net::TcpListener;

use crate::routes;

pub async fn start(redis: ConnectionManager) {
    let mut openapi = OpenApi {
        info: Info {
            title: "Attestation Gateway".to_string(),
            ..Default::default()
        },
        ..Default::default()
    };

    let app = routes::handler()
        .finish_api(&mut openapi)
        .layer(Extension(redis))
        .layer(Extension(openapi));

    let address = SocketAddr::from((
        [0, 0, 0, 0],
        env::var("PORT").map_or(8000, |p| p.parse().unwrap()),
    ));
    let listener = TcpListener::bind(&address)
        .await
        .expect("Failed to bind address");

    println!("😈 Attestation gateway started on http://{address}");
    axum::serve(listener, app.into_make_service())
        .await
        .expect("Failed to start server");
}
