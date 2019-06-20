use std;
use std::io::prelude::*;
use utils;

const MAGIC_NUMBER: usize = 32;

pub fn read_stdin_to_string(s: &mut std::string::String) {
    match std::io::stdin().read_line(s) {
            Ok(bytes_read) => s.truncate(bytes_read-1), // Chop off newline char
            Err(e) => println!("There was an error reading user input: {:?}", e)
    }
}

pub fn read_stdin_to_string_return() -> std::io::Result<std::string::String> {
    
    std::io::stdout().flush()?;
    
    let mut s = std::string::String::new();
    match std::io::stdin().read_line(&mut s) {
            Ok(bytes_read) => s.truncate(bytes_read-1), // Chop off newline char -- windows =2 bytes, linux/mac=1 byte
            Err(e) => println!("There was an error reading user input: {:?}", e)
    }

    Ok(s)
}

pub fn get_user_input() -> std::io::Result<u32> {
    let mut user_choice = std::string::String::new();
        
    print!("Enter the index of your choice: ");
    
    std::io::stdout().flush().expect("Could not flush stdout");
    std::io::stdin().read_line(&mut user_choice)
                    .expect("Failed to read user input");

    let user_choice: u32 = match user_choice.trim().parse() {
        Ok(num) => num,
        Err(_) => panic!("Failed to parse user input from string to integer"),
    };

    Ok(user_choice)
}

impl utils::DBcrypt {

    pub fn get_key_from_user(argc: &usize) -> std::io::Result<[u8; MAGIC_NUMBER]> {

        match *argc {
            1 => {
                println!("Please enter your master password, which will be used to encrypt and decrypt the database.");
                println!("The password must be 32 bytes (32 ASCII chars) or less. Anything beyond 32 bytes will be truncated.");
            },
            _ => println!("Encrypted password database successfully opened. Please enter your master password")
        }

        // Prevent re-allocation with a generous 64 bytes capacity.
        // Wenn 64 bytes überschritten werden, bekommt der String
        // einfach mehr Kapazität.
        let mut string_buf = std::string::String::with_capacity(64);
                
        loop {
            read_stdin_to_string(&mut string_buf);
            // Second, we ensure the entered key is 32 bytes or less long.
            match string_buf.len() <= MAGIC_NUMBER { // len() returns length in bytes, not glyphs
                true => {
                    println!("Password: \"{}\" successfully entered.", string_buf);
                    break;
                },
                false => println!("Password is greater than 32 bytes. Please try again.")
            }

            // Truncate the stringbuf so it can be safely refilled
            string_buf.truncate(0);
        };

        let bytes = string_buf.into_bytes(); // Consumes the String, so we aren't copying

        let mut buf = [0u8; MAGIC_NUMBER];

        for (i, byte) in bytes.into_iter().enumerate() {
            buf[i] = byte;
        }

        Ok(buf)
    }

    pub fn print_entire_db(&self) {

        if self.db.len() == 0 {
            print!("Database is empty. Please add an entry.");
            return;
        }

        println!("Title\t\tUsername\tPassword");
        for elem in self.db.iter() {
            println!("{}\t\t{}\t\t{}", elem.title, elem.username, elem.password);
        }
    }

    pub fn print_password(&self) {
    print!("For which service would you like to retrieve the password? ");

    let mut service_from_user = std::string::String::new();
    std::io::stdout().flush().expect("Could not flush stdout");
    std::io::stdin().read_line(&mut service_from_user).expect("Unable to read user input");

    let service_from_user = service_from_user.trim().to_lowercase();

    // Compare with our db
    for elem in self.db.iter() {
        match service_from_user == elem.title.to_lowercase() {
            true => { println!("\nThe password for service \"{}\" is: {}", service_from_user, elem.password); return; },
            false => continue,
        }
    }

    println!("Sorry, we couldn't find an entry matching that service name.");
    
    }
}
    
pub fn print_home_screen() {
    println!("\n\nWhat would you like to do?");
    println!("1) Add password");
    println!("2) Print password");
    println!("3) Print all passwords");
    println!("4) Delete password");
    println!("5) Edit password entry");
    println!("6) Discard changes and exit");
    println!("7) Save changes and exit\n");
}