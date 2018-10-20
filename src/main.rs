extern crate crypto;
extern crate rand;

mod utils;
mod ui;

fn main() {
    println!("Welcome to the best password manager in the world!");

    let argc = std::env::args().count();
/*
    //let mut iv = [0u8; 32];
    let mut decrypted_db_from_file: Vec<u8> = std::vec::Vec::new();
    let mut raw_file_data: Vec<u8> = std::vec::Vec::new();
    let mut iv: Vec<u8> = std::vec::Vec::new();

    let db_file_name = match argc {
        1 => {
            print!("Please enter the name you would like to give your database file: ");
            ui::read_stdin_to_string_return()
        },
        _ => std::env::args().nth(1).expect("Failed to read parameter")
    };

    let key = ui::get_key_from_user(&argc).expect("Failed to get key from user");

    
    
    match argc {
        1 => (), //iv = utils::gen_initialisation_vector().expect("Failed to generate iv"),
        _ => {
            raw_file_data = utils::read_file(&db_file_name).expect("Failed to open file");
        }
    }    */

    // Split the read memory into the actual db, and the iv,
    // which is the last 32 bytes of the file.

    // let iv_vec = raw_file_data.split_off(raw_file_data.len() - 32);
    // iv_vec.
    // for (i, elem) in iv_vec.into_iter().enumerate() {
    //     iv[i] = elem;
    // }

    match argc {
        1 => (), //iv = utils::gen_initialisation_vector().expect("Failed to generate iv"),
        _ => {
            
            decrypted_db_from_file = utils::decrypt(&raw_file_data, &key, &iv)
                                .expect("Failed to decrypt file");
        }
    }  

    

    
    let mut password_db = match argc {
        1 => std::vec::Vec::<utils::DatabaseEntry>::new(),
        _ => utils::bytes_to_vec_entry(&decrypted_db_from_file).unwrap()
    };
    
    // Initial set up phase is complete, now we want to loop 
    // until the user kills the program
    loop {
        ui::print_home_screen();
        let user_choice = ui::get_user_input().unwrap();
 
        match user_choice {
            1 => {
                let new_entry = utils::add_entry()
                    .expect("Failed to create database entry object from user input");
                password_db.push(new_entry);
            },
            2 => ui::print_password(&password_db),
            3 => ui::print_entire_db(&password_db),
            4 => println!("Delete"),
            5 => println!("Edit"),
            6 => {
                println!("Discarding changes and exiting");
                std::process::exit(0);
            },
            7 => {
                println!("Saving changes to file and exiting");
                let message = utils::vec_entry_to_bytes(password_db).unwrap();
                match utils::encrypt_and_write_to_file(&message, &key, &iv, &db_file_name) {
                    Ok(_) => {
                        println!("Encrypted password database successfully written. Quitting.");
                        std::process::exit(0);
                    },
                    Err(_) => {
                        println!("Error. Discarding changes and aborting.");
                        std::process::exit(1);
                    } 
                }
            },
            _ => println!("Enter one of the displayed indices, dingus")
        }
    }
}