

use std::thread;
use std::collections::HashSet;
use std::time::Instant;
use clap::{Arg, app_from_crate };
use serde_json::Value;
use std::ops::Deref;
use std::convert::TryInto;
use ndarray::{Array2, Array, Axis, Array1, Zip};
use ndarray::Slice;

use lair::decomposition::lu::Factorized;

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

///Convert an array of Value::Numbers into a list of u64 keys
///
/// When converting numbers into u64, we disregard the arithmetic rules and simply map the 8 bytes of the i64 or f64 into u64
fn numbers_to_keys(numbers: & Vec<Value>) -> Vec<u64> {

    let mut keys = Vec::with_capacity(numbers.len());

    for number in numbers {
        if let Value::Number(n) = number {
            if n.is_f64() {
                keys.push(u64::from_ne_bytes(n.as_f64().unwrap().to_ne_bytes()))
            } else if n.is_i64() {
                keys.push(u64::from_ne_bytes(n.as_i64().unwrap().to_ne_bytes()))
            } else if n.is_u64() {
                keys.push(n.as_u64().unwrap())
            }
        }
    }

    keys

}

///Convert an array of Value::Strings into a list of u64 keys
///
/// We convert an array of strings into an array of u64 by searching for rolling u64s across all strings with padding until unique values are found.
///
/// So we take all the strings in the list, and form a u64 from the first 8 bytes (starting at index=0), then the next 8 bytes (starting at index=1) until
/// we find an index where all u64 values are unique. Padding is added if we need to push past the end of a string.
///
/// This is very fast, since we simply need to convert &string\[index..index+8\] into a u64. However there exist sets of strings such that no index can be found
/// that creates unique u64 values, so it can fail. The key to avoid this is to ensure that the strings are not too similar. (avoid having more than 8 bytes of the same data in the same position across 3 or more strings)
fn strings_to_keys(strings: & Vec<Value>) -> Option<(Vec<u64>, u64)> {

    let string_iter = strings.iter().map(|x| {
        if let Value::String(s) = x {
            s
        } else {
            unreachable!()
        }
    });

    let smallest_len = string_iter.clone().fold(usize::MAX, |acc, x| if acc < x.len() { acc } else { x.len() });

    let mut set = HashSet::new();

    for start in 0..smallest_len {
        for s in string_iter.clone() {
            set.insert(str_to_u64(s, start));
        }

        if set.len() == strings.len() {
            return Some((set.iter().map(|x| *x).collect(), start as u64));
        }

        set.clear();
    }

    None
}

///Demonic conversion to convert a slice into a u64, padding with zeros if needed
fn str_to_u64(s: &str, index: usize) -> u64 {

    let s = s.as_bytes();

    unsafe {
        //Take an 8 byte slice of s, even if this means indexing past the end of s
        let past_the_end = std::slice::from_raw_parts((&s[index]) as *const u8, 8);

        //Converting &[u8] to u64 this way is fast, but if this works as be on one platform and le on another, this may break the map hash function so we always explicitly give little endian.
        //
        //let past_the_end_value = past_the_end.as_ptr() as * const u64;

        //The least disgusting part of this algorithm
        let past_the_end_value = u64::from_le_bytes(std::convert::TryInto::try_into(past_the_end).unwrap());

        if index + 8 > s.len() {
            let pad = 8 - s.len() + index;

            //Shift left then right to pad the top with zeros
            let trimmed = past_the_end_value << (pad * 8);
            trimmed >> (pad * 8)
        } else {
            past_the_end_value
        }
    }

}

/// Take a list of u64 keys and look for a constant and lookup table pair
///
/// This scheme is based on the MPHF explained here https://randorithms.com/2019/09/12/MPH-functions.html
fn large_n_scheme(keys: & Vec<u64>) -> (u64, Vec<i64>) {

    let n = keys.len();

    let mut h1_matrix: Array2<f64> = Array2::zeros((n, n));


    //We use remaining to listt any columns made entirely of zeros. If all these columns remain entirely zero,
    //the matrix will be singular. This provides an easy(?) test to exclude some singular matrices
    let mut remaining = HashSet::new();

    for i in 0..n {
        remaining.insert(i);
    }

    for (key, mut row) in keys.iter().zip(h1_matrix.rows_mut()) {
        let ind = index(*key, 0, n);

        remaining.remove(&ind);
        row[ind] = 1.0;
    }

    println!("remaining values: {:?}", remaining);


    let mut pad = HashSet::new();

    'search: for k in 0..0xffffffffffffffff {
        let mut sum_matrix = h1_matrix.clone();


        for (key, mut row) in keys.iter().zip(sum_matrix.rows_mut()) {
            let index = index(*key, k, n);
            pad.insert(index);
            row[index] = row[index] + 1.0;
        }

        //If each column in the matrix contains at least one non-zero number
        if remaining.is_subset(&pad) {


            let lu = Factorized::from(sum_matrix);

            //If the matrix is invertible
            if !lu.is_singular() {

                let mut indices: Array1<f64> = Array1::zeros((n));

                for (element, i) in indices.iter_mut().zip(0..n) {
                    *element = i as f64;
                }

                //Solve for the lookup table
                let float_lookup = lu.solve(&indices).unwrap();

                //Make sure the lookup table has all integer values
                for float in float_lookup.iter() {
                    if float.floor() != *float {
                        continue 'search;
                    }
                }

                //Convert the float lookup to an int lookup
                let mut int_lookup = Vec::with_capacity(n);

                for element in float_lookup {
                    int_lookup.push(element as i64);
                }

                return (k, int_lookup);
            }

        }

        pad.clear();


    }

    unreachable!()



}


///Verify that the keys, along with the constant and lookup table create a valid minimal perfect hashing function
fn verify(keys: & Vec<u64>, k: u64, lookup: &Vec<i64>) -> bool {

    let n = keys.len();

    for (i, key) in keys.iter().enumerate() {
        let h1_of_key = index(*key, 0, n);
        let h2_of_key = index(*key, k, n);

        if lookup[h1_of_key] + lookup[h2_of_key] != i as i64 {
            return false;
        }
    }

    true
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
                match strings_to_keys(&json_keys) {
                    None => {
                        println!("A suitable rolling 64-bit scheme could not be created for the given strings. Aborting.");
                        return;
                    }
                    Some((key_list, start_ind)) => {
                        println!("A suitable scheme has been found for the string, starting at {}", ansi_term::Colour::Yellow.paint(format!("{} (&str[{}..{}])", start_ind, start_ind, start_ind+8)));

                        key_list
                    }
                }


            }
            _ => {
                unreachable!()
            }
        }
    } else {
        unreachable!()
    };

    let (k, lookup) = large_n_scheme(& keys);

    println!("result: {:?}", (k, &lookup));

    println!("verify: {}", verify(&keys, k, &lookup));

    return ;

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

                    //The only way this send will fail is if the receiver has disconnected. This is not an error since
                    //the main thread can stop (due to a ThreadResult::Found) with worker threads running. This will
                    //eventually result in the worker threads being stopped. So we suppress the warning with ok()
                    cloned_sender.send(ThreadResult::Found(i)).ok();
                    break;
                }
            }

            //The only way this send will fail is if the receiver has disconnected. THis is not an error since
            //the main thread can stop (due to a ThreadResult::Found) with worker threads running. This will
            //eventually result in the worker threads being stopped. So we suppress the warning with ok()
            cloned_sender.send(ThreadResult::NotFound).ok();
        });
    }

    /* Main thread detects when a search finishes */

    let mut finished_count = 0;

    loop {
        match tx.recv().unwrap() {
            ThreadResult::Found(k) => {
                let elapsed = start.elapsed();
                println!("Found constant: {} (elapsed: {:?})", ansi_term::Colour::Yellow.paint(format!("{:#x}", k)), elapsed);

                let indices: Vec<_> = keys.iter().map(|x| index(*x, k, keys.len())).collect();
                println!("Indices: {:?}", indices);

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
