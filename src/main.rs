
use std::thread;
use std::collections::HashSet;
use std::time::Instant;
use clap::{App, Arg, app_from_crate };
use serde_json::Value;
use std::hint::unreachable_unchecked;
use std::ops::Deref;

///Enum representing reason for thread termination
enum ThreadResult {
    /// A constant has been found, with the supplied value
    Found(u64),

    /// A thread has finished its search, and no constant was found
    NotFound,
}

///32-bit hash function taken from https://stackoverflow.com/questions/664014/what-integer-hash-function-are-good-that-accepts-an-integer-hash-key.
///Might need changing in the future
fn hash(value: u64) -> u64 {
    let mut x = std::num::Wrapping(value);
    x = (x ^ (x >> 31) ^ (x >> 62)) * std::num::Wrapping(0x319642b2d24d8ec3);
    //x = (x ^ (x >> 27) ^ (x >> 54)) * std::num::Wrapping(0x96de1b173f119089);
    x = x ^ (x >> 30) ^ (x >> 60);
    x.0
}

///The index for a key is computed as hash(key ^ k) % n, where n is the number of keys and k is a constant chosen such that hash(key ^ k) is a minimal perfect hash function
fn index( key: u64, k: u64, n: usize) -> usize {
    (hash(key ^ k) % n as u64) as usize
}

/// Test the constant k against the keys to see if it can be used to create a minimal perfect hash function with hash()
fn test_constant(keys: & [u64], k: u64) -> bool {

    let key_size = keys.len();

    //Pad keeps a record of each index we have found. If there is a one in the ith position, the
    //index at i has been found. We use this to detect collisions
    let mut pad = 0u64;

    for key in keys.iter() {
        let ind = index(*key, k, key_size);

        if pad & (1 << ind) == 0 {
            pad = pad | (1 << ind);
        } else {
            return false
        }
    }
    true
}

//Convert an array of Value::Numbers into a list of u64 keys
fn numbers_to_keys(numbers: & Vec<Value>) -> Vec<u64> {

    let mut keys = Vec::with_capacity(numbers.len());

    for number in numbers {
        if let Value::Number(n) = number {
            if n.is_f64() {
                keys.push(u64::from_be_bytes(n.as_f64().unwrap().to_be_bytes()))
            } else if n.is_i64() {
                keys.push(u64::from_be_bytes(n.as_i64().unwrap().to_be_bytes()))
            } else if n.is_u64() {
                keys.push(n.as_u64().unwrap())
            }
        }
    }

    keys

}

//Convert an array of Value::Strings into a list of u64 keys
fn strings_to_keys(strings: & Vec<Value>) -> Vec<u64> {

    let mut keys = Vec::with_capacity(strings.len());

    keys
}

fn main() {

    let m = app_from_crate!().about("Creates a minimal perfect hashing function from a list of keys")
        .arg(Arg::new("keys")
            .short('k')
            .long("keys")
            .takes_value(true)
            .value_name("VALUES")
            .help("List of keys, numbers or strings")
            .required(true)
            .validator(|s| {
                let json: Value = serde_json::from_str(s).map_err(|x| x.to_string())?;

                if let Value::Array(arr) = json {

                    //Array must be either entirely numbers, or entirely strings
                    let first = &arr[0];

                    match first{
                        Value::Number(_) => {
                            for elm in arr.iter() {
                                if let Value::Number(_) = elm {

                                } else {
                                    return Err(String::from("Elements of the key list must be all numbers or all strings"))
                                }
                            }
                        }
                        Value::String(_) => {
                            for elm in arr.iter() {
                                if let Value::String(_) = elm {

                                } else {
                                    return Err(String::from("Elements of the key list must be all numbers or all strings"))
                                }
                            }
                        }
                        _ => {
                            return Err(String::from("Elements of the key list must be either numbers or strings"))
                        }
                    }

                } else {
                    return Err(String::from("Argument must be a JSON-style array"))
                }

                Ok(())
            }))
        .get_matches();

    /* Parse the list as a JSON string into a u64 array */

    let json: Value = serde_json::from_str(m.value_of("keys").unwrap()).unwrap();

    let keys = if let Value::Array(json_keys) = json {
        match &json_keys[0] {
            Value::Number(_) => {
                println!("Keys are numbers, converting to u64");
                //Iterate over each key and whether its i64, u64 or f64, treat it as a series of bytes then as u64
                numbers_to_keys(&json_keys)
            }
            Value::String(_) => {
                println!("Keys are strings, converting to u64");
                //Get the first 8 bytes for each string, pad with zeros after
                strings_to_keys(&json_keys)
            }
            _ => {
                unreachable!()
            }
        }
    } else {
        unreachable!()
    };

    /*let keys = [931490837,29416649,874398655,335965764,105060034,
        36406360,658718324,411020913,555154338,910507234,
        974947607,583310598,14673889,335928604,264374426,
        200479480,943553920,607106533,390602251,916711770,
        630545510,464067286,339011690,410705238,510255889,
        //528784785,225901917,169021385,694638718,324844016
        ];

    let keys = [
        0, 2, 4, 6, 8, 10, 12, 14, 16, 18,
        20, 22, 24, 26, 28,
        30, 32, 34, 36, 38
    ];*/

    //let keys = vec![1, 2, 3, 4, 5, 6, 7,8 ,9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

    let keys = std::sync::Arc::new(keys);

    /* Make sure the aray doesn't have any duplicates */

    println!("Searching for duplicate keys...");
    {
        let mut set = HashSet::new();

        for key in keys.iter() {
            set.insert(*key);
        }

        if set.len() != keys.len() {
            println!("Duplicate keys found. Aborting");
            return
        }
    }

    println!("Key set: {:?}", keys);

    /* Setup and begin concurrent search */

    let thread_count = thread::available_parallelism().unwrap().get() as u64 - 1;

    //Divide 2^64 - 1 equally among the threads
    let interval = 0xffffffffffffffff  / thread_count  ;

    //Signals used to tell the main thread when to stop
    let (rx, tx) = std::sync::mpsc::channel();

    println!("Starting search with {} threads...", thread_count);

    let start = Instant::now();

    for t in 0..thread_count {
        let cloned_sender = rx.clone();

        let key_ref = keys.clone();

        thread::spawn(move || {
            for i  in (t)*interval ..(t+1)*interval  {
                if test_constant(key_ref.deref(), i) {
                    cloned_sender.send(ThreadResult::Found(i));
                    break;
                }
            }

            cloned_sender.send(ThreadResult::NotFound);
        });
    }

    /* Main thread detects when a search finishes */

    let mut finished_count = 0;

    loop {
        match tx.recv().unwrap() {
            ThreadResult::Found(k) => {
                let elapsed = start.elapsed();
                println!("Found constant: {} (elapsed: {:?})", ansi_term::Colour::Yellow.paint(format!("{:#x}", k)), start.elapsed());

                break;
            }
            ThreadResult::NotFound => {
                finished_count  = finished_count + 1
            }
        }

        //If all threads come back with a not found, abort
        if finished_count == thread_count {
            println!("Search finished, {}.", ansi_term::Colour::Red.paint("no constant found"));
            break;

        }
    }

}
