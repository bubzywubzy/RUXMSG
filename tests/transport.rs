use std::io::Cursor;
use std::net::{TcpListener, TcpStream};
use std::thread;

use ruxmsg::protocol::MessageType;
use ruxmsg::transport::{FramedTransport, Transport};
use ruxmsg::wire::Frame;

#[test]
fn framed_transport_round_trips_over_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut transport = FramedTransport::new(stream);
        transport.receive().unwrap()
    });

    let stream = TcpStream::connect(address).unwrap();
    let mut client = FramedTransport::new(stream);
    let frame = Frame::new(MessageType::Close, vec![0xa0]).unwrap();
    client.send(&frame).unwrap();
    assert_eq!(server.join().unwrap(), frame);
}

#[test]
fn framed_transport_rejects_truncated_payload() {
    let bytes = vec![1, MessageType::Data as u8, 0, 0, 0, 4, 0xa0];
    let mut transport = FramedTransport::new(Cursor::new(bytes));
    assert!(transport.receive().is_err());
}
