extern crate ctrlc;
extern crate nftnl_sys;

use nftnl_sys::libc::{
    c_void, recvfrom, sendto, sockaddr, sockaddr_ll, socket, AF_PACKET, SOCK_RAW,
};
use nftnl_sys::*;
use std::ffi::CStr;
use std::process::{exit, Command};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

// Higher-level API for tracing
pub struct Trace {
    trace: *mut nftnl_trace,
}

impl Trace {
    pub fn new() -> Self {
        unsafe {
            let trace = nftnl_trace_alloc() as *mut nftnl_trace;
            if trace.is_null() {
                panic!("Failed to allocate trace");
            }
            Trace { trace }
        }
    }

    pub fn free(self) {
        unsafe {
            nftnl_trace_free(self.trace);
        }
    }

    pub fn is_set(&self, type_: u16) -> bool {
        unsafe { nftnl_trace_is_set(self.trace, type_) }
    }

    pub fn get_str(&self, type_: u16) -> Option<String> {
        unsafe {
            let c_str = nftnl_trace_get_str(self.trace, type_);
            if c_str.is_null() {
                None
            } else {
                Some(CStr::from_ptr(c_str).to_string_lossy().into_owned())
            }
        }
    }
}

// Function to flush nftables rules
fn flush_nftables() {
    let output = Command::new("nft")
        .args(&["flush", "ruleset"])
        .output()
        .expect("Failed to execute nft command");

    if output.status.success() {
        println!("Successfully flushed nftables rules");
    } else {
        eprintln!(
            "Failed to flush nftables rules: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

// Thread function for processing packets from a raw socket
fn process_queue(running: Arc<AtomicBool>) {
    let trace = Trace::new();

    // Set up a raw socket to listen for packets
    let raw_socket = unsafe { socket(AF_PACKET, SOCK_RAW, 0) };
    if raw_socket < 0 {
        panic!("Failed to create raw socket");
    }

    // Create a socket for sending packets back to the kernel
    let send_socket = unsafe { socket(AF_PACKET, SOCK_RAW, 0) };
    if send_socket < 0 {
        panic!("Failed to create send socket");
    }

    let mut buffer = [0u8; 2048];

    while running.load(Ordering::SeqCst) {
        let recv_len = unsafe {
            recvfrom(
                raw_socket,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };

        if recv_len < 0 {
            break; // Handle error in a production setting, but skip printing here
        }

        // Prepare to send the packet back to the kernel
        let dest_addr: sockaddr_ll = sockaddr_ll {
            sll_family: AF_PACKET as u16,
            sll_protocol: 0x0003, // ETH_P_ALL
            sll_ifindex: 0,       // The interface index is not needed
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8], // Not used since we're sending to the interface directly
        };

        let sent_len = unsafe {
            sendto(
                send_socket,
                buffer.as_mut_ptr() as *const c_void,
                recv_len as usize,
                0,
                &dest_addr as *const _ as *const sockaddr,
                std::mem::size_of::<sockaddr_ll>() as u32,
            )
        };

        if sent_len < 0 {
            // Handle error in a production setting, but skip printing here
        }
    }

    trace.free();
}

fn main() {
    const NUM_QUEUES: usize = 56;
    let running = Arc::new(AtomicBool::new(true));

    // Set up Ctrl+C signal handler
    {
        let running = Arc::clone(&running);
        ctrlc::set_handler(move || {
            println!("Received Ctrl+C, shutting down...");
            running.store(false, Ordering::SeqCst);
            flush_nftables(); // Flush nftables on shutdown
            exit(0); // Exit immediately after flushing
        })
        .expect("Error setting Ctrl+C handler");
    }

    // Custom panic hook for resource cleanup
    std::panic::set_hook(Box::new(|info| {
        eprintln!("Panic occurred: {:?}", info);
        flush_nftables(); // Flush nftables on panic
    }));

    let handles: Vec<_> = (0..NUM_QUEUES)
        .map(|_i| {
            let running = Arc::clone(&running);
            thread::spawn(move || {
                process_queue(running);
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
}
