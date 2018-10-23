extern crate crypto;
extern crate rand;

mod utils;
mod ui;

fn main() -> std::io::Result<()> {
    println!("Welcome to the best password manager in the world!");

    let argc = std::env::args().count();

    // iv, key, filename, vec<entry>
    let mut password_db = match argc {
        1 => utils::initialise(&argc)?,
        _ => utils::initialise_from_file(&argc)?,
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
                password_db.db.push(new_entry);
            },
            2 => ui::print_password(&password_db.db),
            3 => ui::print_entire_db(&password_db.db),
            4 => println!("Delete"),
            5 => println!("Edit"),
            6 => { println!("Discarding changes and exiting"); return Ok(()) },
            7 => {
                println!("Saving changes to file and exiting");
                match utils::encrypt_and_write_to_file(password_db) {
                    Ok(_) => {
                        println!("Encrypted password database successfully written. Quitting.");
                        return Ok(())
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