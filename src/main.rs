#![feature(async_await)]
#![feature(await_macro)]
extern crate iota_lib_rs;

use std::thread;
use std::io;
use std::time::{Instant};

use iota_lib_rs::crypto::iss;
use iota_lib_rs::utils::converter;
use iota_lib_rs::crypto::HashMode;
use iota_lib_rs::utils::generate_new_seed;
use iota_lib_rs::utils::trit_adder;

fn main() {
  let mut seed = String::new();
  println!("Please enter a seed or just press enter to get a random seed");
  io::stdin().read_line(&mut seed)
    .expect("Failed to read input");
  trim_newline(&mut seed);
  if seed.len() != 81{
    println!("Invalid seed, a new one is generated");
    seed = generate_new_seed();
  }
  println!("Your seed is: {}", seed);

  println!("Please enter the amount of addresses you want to generate");
  let mut input_amount_string = String::new();
  io::stdin().read_line(&mut input_amount_string)
    .expect("Failed to read input");
  let mut input_amount = 0;
  match input_amount_string.trim().parse::<u32>() {
    Ok(i) =>  input_amount = i as usize,
    Err(..) => println!("This was not an integer: {}", input_amount_string),
  };
  println!("Addresses to generate: {:?}", input_amount);

  println!("Please enter the words you want to use to search for an address, separated by a space");
  let mut words_string = String::new();
  io::stdin().read_line(&mut words_string)
    .expect("Failed to read input");
  let tryte_words: Vec<String> = words_string.trim().split(" ").map(|s| s.to_string().to_uppercase()).collect();
  println!("Words: {:?}", tryte_words);

  println!("Please enter the startindex");
  let mut startindex_string = String::new();
  io::stdin().read_line(&mut startindex_string)
    .expect("Failed to read input");
  let mut startindex = 0;
  match startindex_string.trim().parse::<u32>() {
    Ok(i) =>  startindex = i as usize,
    Err(..) => println!("This was not an integer: {:?}", startindex_string),
  };
  println!("Startindex: {:?}", startindex);

  println!("Return seed (slower) = enter 'true', return only the private key (faster) = enter 'false'");
  let mut startindex_string = String::new();
  io::stdin().read_line(&mut startindex_string)
    .expect("Failed to read input");
  let mut return_seed = true;
  match startindex_string.trim().parse::<bool>() {
    Ok(i) =>  return_seed = i as bool,
    Err(..) => println!("This was not a bool: {:?}", startindex_string),
  };
  println!("Return seed: {:?}", return_seed);

  let threads = 8;
  let amount = input_amount/threads;
  println!("Start {} threads with {} addresses to generate for each:", threads, amount);
  let time_now = Instant::now();
  let mut pool = vec![];
  for i in 0..threads {
    let se = seed.clone();
    let tw = tryte_words.clone();
    pool.push(thread::spawn(move || {
      if return_seed == true {
      generate_adresses_seed(i*amount+startindex, (i+1)*amount+startindex, se, &tw, threads, i);
      } else {
      generate_adresses_prvkey(i*amount+startindex, (i+1)*amount+startindex, se, &tw, threads, i);
      }
    }));
  }
  for worker in pool {
    let _ = worker.join();
  }
  println!("Duration: {:?} for {} addresses", time_now.elapsed(), amount*threads);
}

fn generate_adresses_seed (start: usize, end: usize, seed: String, target_words: &Vec<String>, threadnumber: usize, current_thread: usize){
  let seed_trits = converter::trits_from_string(&seed);
  let mut targetlist = Vec::new();
  for p in target_words {
    targetlist.push(converter::trits_from_string(p))
  }
  for index in start..end {
    if index%1000 == 0 && current_thread == threadnumber-1 {
      println!("Addresses remaining: ~{}", threadnumber*(end-index));
    }
    let mut subseed = iss::subseed(HashMode::Kerl, &seed_trits, index).unwrap();
    let key = iss::key(HashMode::Kerl, &mut subseed, 2).unwrap();
    let mut digest = iss::digests(HashMode::Kerl, &key).unwrap();
    let address = iss::address(HashMode::Kerl, &mut digest).unwrap();
    for k in 0..targetlist.len() {
      if targetlist[k] == &address[..targetlist[k].len()]{
        println!("Address found at index {}: {}", index,   converter::trits_to_string(&address).unwrap());
        let new_seed = index_zero_seed(&seed_trits, index);
        println!("New seed: {}", new_seed);
        println!("Privatekey: {}", converter::trits_to_string(&key).unwrap());
      }
    }
  }
}

fn generate_adresses_prvkey (start: usize, end: usize, seed: String, target_words: &Vec<String>, threadnumber: usize, current_thread: usize){
  let trits = [-1, 0, 1];
  let mut seed_trits = converter::trits_from_string(&seed);
  let mut trit_vec = vec![0; 12879];
  trit_vec.append(&mut seed_trits);
  let mut targetlist = Vec::new();
  for p in target_words {
    targetlist.push(converter::trits_from_string(p))
  }
  for index in start..end {
    if index%1000 == 0 && current_thread == threadnumber-1 {
      println!("Addresses remaining: ~{}", threadnumber*(end-index));
    }
    let key = random_privatekey(&trits, &trit_vec, index);
    let mut digest = iss::digests(HashMode::Kerl, &key).unwrap();
    let address = iss::address(HashMode::Kerl, &mut digest).unwrap();
    for k in 0..targetlist.len() {
      if targetlist[k] == &address[..targetlist[k].len()]{
        println!("Address found at index {}: {}", index,   converter::trits_to_string(&address).unwrap());
        println!("Privatekey: {:?}",converter::trits_to_string(&key).unwrap());
      }
    }
  }
}

fn index_zero_seed(seed_trits: &[i8], index: usize) -> String {
  let mut index_trits: [i8; 243] = [0; 243];
  let num = index as i64;
  int2trits(num, &mut index_trits);
  let new_trits = trit_adder::add(seed_trits, &index_trits);
  let new_seed = converter::trytes(&new_trits);
  new_seed
}

fn random_privatekey(_arr: &[i8; 3], tr: &Vec<i8>, index: usize) -> Vec<i8> {
  let mut vec = tr.clone();
  let num = index as i64;
  int2trits(num, &mut vec);
  vec.to_vec()
}

pub fn int2trits(v: i64, out: &mut [i8]) {
  let size = out.len();
  let negative = v < 0;
  let mut value = if negative { -v } else { v };
  for i in 0..size {
    if value == 0 {
      break;
    }
    let mut trit = ((value + 1) % (3 as i64)) as i8 - 1;
    if negative {
      trit = -trit;
    }
    out[i] = trit;
    value = (value + 1) / (3 as i64);
  }
}

fn trim_newline(s: &mut String) {
  while s.ends_with('\n') || s.ends_with('\r') {
    s.pop();
  }
}