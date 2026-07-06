// Split by responsibility:
//
// flow - the pairing protocol itself.
//
// io - low-level primitives.
//      Anything that reads or writes a TcpStream or a file *directly* goes here.
//      No pairing logic.
//
// wifi - networking utilities (e.g. nmcli-based).
//        Only for cameras that manage their own WiFi hotspot.
//        IP cameras don't need it.
//
// relay - relay-based pairing.
//         Only for cameras that perform pairing via the relay.

pub mod flow;

pub mod io;

#[cfg(feature = "raspberry")]
pub mod wifi;