use std::intrinsics::write_bytes;
use std::net::SocketAddr;
use std::slice::Iter;
use std::thread::sleep;
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use clap::{App, Arg, ArgMatches, SubCommand};
use futures::sink::SinkExt;
use futures::stream::{self, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio::io::Error;
use tokio::net::UdpSocket;
use tokio::prelude::*;

use stun_rs::codec::error::CodecError;
use stun_rs::codec::{Decoder, Encoder};
use stun_rs::messages::{Address, Attribute, Message, MessageClass, MessageMethod, TransactionID};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_arguments();
    let host = args.value_of("host").unwrap();
    let port: u16 = args.value_of("port").unwrap().parse().unwrap();
    let socket = UdpSocket::bind(format!("{}:{}", host, port)).await.unwrap();

    match args.subcommand() {
        ("client", Some(opts)) => start_udp_client(socket, opts.value_of("server").unwrap()).await,
        ("server", _) => start_udp_server(socket).await,
        (cmd, _) => {
            eprintln!("unsupported command: {}", cmd);
            println!("{}", args.usage());
            Ok(())
        }
    }
}

fn parse_arguments() -> ArgMatches<'static> {
    App::new("stun-rs")
        .version("0.1.0")
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("PORT")
                .help("PORT to bind to")
                .default_value("8081")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("host")
                .short("h")
                .long("host")
                .value_name("HOST")
                .help("HOST to bind to")
                .default_value("0.0.0.0")
                .takes_value(true),
        )
        .subcommand(
            SubCommand::with_name("client")
                .about("run STUN client")
                .arg(
                    Arg::with_name("server")
                        .short("s")
                        .long("server")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(SubCommand::with_name("server").about("run STUN server"))
        .get_matches()
}

async fn start_udp_client(
    mut socket: UdpSocket,
    server: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let msg = Message {
        message_class: MessageClass::Request,
        message_method: MessageMethod::Binding,
        transaction_id: TransactionID::from([1u8; 12]),
        attributes: vec![Attribute::Software("stun-rs:0.1.0".to_owned())],
    };
    let stun_encoder = Encoder::new();
    let stun_decoder = Decoder::new();
    let mut bytes_mut = BytesMut::new();
    let size = stun_encoder.encode(&msg, &mut bytes_mut);

    let bytes_sent = socket.send_to(bytes_mut.bytes(), server).await.unwrap();
    assert_eq!(bytes_sent, bytes_mut.len());
    loop {
        let mut buf = [0u8; 1024];
        let (bytes_recv, address) = socket.recv_from(&mut buf).await.unwrap();
        let mut bytes = Bytes::copy_from_slice(&buf);
        let message = stun_decoder.decode(&mut bytes).unwrap();
        println!("receive from {}, message: {:?}", address, message);
    }
    Ok(())
}

async fn start_udp_server(mut socket: UdpSocket) -> Result<(), Box<dyn std::error::Error>> {
    let stun_encoder = Encoder::new();
    let stun_decoder = Decoder::new();
    let mut buf = [0u8; 1024];
    loop {
        let (bytes_recv, address) = socket.recv_from(&mut buf).await?;
        let mut bytes = Bytes::copy_from_slice(&buf);
        let message = stun_decoder.decode(&mut bytes)?;
        match message_handler(message, address) {
            Some(reply) => {
                println!("sending message: {:?}", reply);
                let mut buf = BytesMut::new();
                Encoder::new().encode(&reply, &mut buf);
                socket.send_to(&mut buf.bytes(), address).await?;
            }
            None => {}
        }
    }
    Ok(())
}

fn message_handler(message: Message, socket_addr: SocketAddr) -> Option<Message> {
    println!("receive message: {:?}", message);
    match (message.message_class, message.message_method) {
        (MessageClass::Request, MessageMethod::Binding) => {
            let reply = Message {
                message_class: MessageClass::SuccessResponse,
                message_method: MessageMethod::Binding,
                transaction_id: TransactionID::from([1u8; 12]),
                attributes: vec![
                    Attribute::Software("stun-rs:0.1.0".to_owned()),
                    Attribute::XorMappedAddress(get_address(socket_addr)),
                ],
            };
            Some(reply)
        }
        _ => None,
    }
}

fn get_address(socket_addr: SocketAddr) -> Address {
    match socket_addr {
        SocketAddr::V4(address) => Address::ipv4(address.ip().octets(), address.port()),
        SocketAddr::V6(address) => Address::ipv6(address.ip().octets(), address.port()),
    }
}
