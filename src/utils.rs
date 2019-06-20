use std::io::prelude::*; // includes the four traits: BufRead, Read, Seek and Write
use std;
use crypto;

use rand::{OsRng, RngCore};

use std::io::BufRead;

use crypto::symmetriccipher::SynchronousStreamCipher;
use ui;
const MAGIC_NUMBER: usize = 32;

// Case 1: file is provided as argument: ./pw_manager db_file
// Case 2: db is generated: cargo run, ./pw_manager

pub struct DatabaseEntry {
    pub title: std::string::String,
    pub username: std::string::String,
    pub password: std::string::String,
}

pub struct DBcrypt {
    pub iv: [u8; MAGIC_NUMBER], // 1) read from file 2) generated
    pub key: [u8; MAGIC_NUMBER], // 1) user input 2) user input
    pub filename: std::string::String, // 1) user argument 2) user input
    pub db: std::vec::Vec<DatabaseEntry>, // 1) read from file after decryption + generated 2) generated 
}

// TO DO: implement on DBcrypt as method
pub fn decrypt(message: &[u8], key: &[u8], iv: &[u8]) -> std::io::Result<Vec<u8>> {

    let mut decryptor = crypto::aes::ctr(crypto::aes::KeySize::KeySize256, &key, &iv);
    let mut decrypted_message = vec![0u8; message.len()];
    decryptor.process(&message, &mut decrypted_message);

    Ok(decrypted_message)
}

// TO DO: implement on DBcrypt as associated function to be called by initialisor
pub fn bytes_to_vec_entry(csv: &[u8]) -> std::io::Result<Vec<DatabaseEntry>> {
   
    let mut password_database: Vec<DatabaseEntry> = std::vec::Vec::new();

    // If we were reading an unencrypted CSV file, we would deal with newlines
    // directly while reading the file with something like lines(). Since
    // std::io::Cursor implements the same BufRead etc. traits as "real" file
    // io types would, it's convenient for us to use, especially since it takes
    // a byte slice as input to the constructor
    let cursor = std::io::Cursor::new(csv); 

    for line in cursor.lines() { // line holds a result with each line string inside it
        
        let line = line.unwrap(); // Handle the Result first.

        let v: Vec<_> = line.split(',').collect();

        let entry = DatabaseEntry {
            title: std::string::String::from(v[0]),
            username: std::string::String::from(v[1]),
            password: std::string::String::from(v[2]),
        };

        password_database.push(entry);
    }

    Ok(password_database)
}

impl DBcrypt {
    // Methods

    pub fn add_entry(&mut self) -> std::io::Result<()> {

        let mut user_title = std::string::String::new();
        let mut user_username = std::string::String::new();
        let mut user_password = std::string::String::new();

        print!("\nEnter the name of the service: ");
        std::io::stdout().flush()?;
        std::io::stdin().read_line(&mut user_title)?;

        print!("\nEnter the username or account name, often an email address: ");
        std::io::stdout().flush()?;
        std::io::stdin().read_line(&mut user_username)?;

        print!("\nEnter the password you wish to save: ");
        std::io::stdout().flush()?;
        std::io::stdin().read_line(&mut user_password)?;

        let new_entry = DatabaseEntry {
            title: user_title.trim().to_string(),
            username: user_username.trim().to_string(),
            password: user_password.trim().to_string(),
        };

        self.db.push(new_entry);
        Ok(())
    }

    pub fn encrypt_and_write_to_file(self) -> std::io::Result<()> {

        let mut message: Vec<u8> = std::vec::Vec::new();
    
        // elem is a single Entry, which we want to serialise
        // into a byte array, or vector.
        for elem in self.db.into_iter() {
            message.append(&mut elem.title.into_bytes());
            message.append(&mut std::string::String::from(",").into_bytes());
            message.append(&mut elem.username.into_bytes());
            message.append(&mut std::string::String::from(",").into_bytes());
            message.append(&mut elem.password.into_bytes());
            message.append(&mut std::string::String::from("\r\n").into_bytes());
        }

        // Convert our Vector of Entries into a [u8] array
        //let message = vec_entry_to_bytes(self.db)?;

        // 1) Encrypt
        let mut ciphertext = vec![0u8; message.len()];
        
        let mut encryptor = crypto::aes::ctr(crypto::aes::KeySize::KeySize256, &self.key, &self.iv);
    
        encryptor.process(&message, &mut ciphertext);

        // 2) Write to file
        let mut buffer = std::fs::File::create(self.filename)?;
    
        // First write the db itself, then append the iv
        buffer.write(&ciphertext)?;
        buffer.write(&self.iv)?;

        Ok(())
    }

    // Associated functions

    pub fn read_file(file_name: &std::string::String) -> std::io::Result<std::vec::Vec<u8>> {
     
        let mut file = std::fs::File::open(file_name)?;

        // Avoid resizing
        let mut buf: std::vec::Vec<u8> = std::vec::Vec::with_capacity(256);
        
        // read_to_end returns the number of bytes read and guarantees we reach the end of the file
        let _buf_len = file.read_to_end(&mut buf)?;

        Ok(buf)
    }
    pub fn gen_initialisation_vector() -> std::io::Result<[u8; MAGIC_NUMBER]> {

        // Make the random number generator
        let mut rng = match OsRng::new() {
            Ok(random_gen) => random_gen,
            Err(error) => panic!("Failed to create OS Random Number Generator: {}", error)
        };

        let mut iv = [0u8; MAGIC_NUMBER];

        rng.fill_bytes(&mut iv);

        Ok(iv)
    }

    // These are our constructors, which are associated functions

    pub fn initialise(argc: &usize) -> std::io::Result<DBcrypt> {
        
        let db_obj = DBcrypt {
            iv: DBcrypt::gen_initialisation_vector()?,
            key: DBcrypt::get_key_from_user(argc)?,
            filename: { println!("Please enter your desired filename:"); ui::read_stdin_to_string_return()? },
            db: std::vec::Vec::new(),
        };

        Ok(db_obj)
    }

    pub fn initialise_from_file(argc: &usize) -> std::io::Result<DBcrypt> {

        let db_file_name = std::env::args().nth(1).unwrap();
        let mut raw_file_data = DBcrypt::read_file(&db_file_name)?;
        let file_len = raw_file_data.len();

        let key = DBcrypt::get_key_from_user(argc)?;

        // The last 32 elements have the iv
        let mut iv_buffer = [0u8; MAGIC_NUMBER];

        // drain() removes the elements in the collection and places them into element
        for (iv_elem, buf_elem) in iv_buffer.iter_mut().zip(raw_file_data.drain((file_len - MAGIC_NUMBER)..)) {
            *iv_elem = buf_elem;
        }

        let decrypted_database = decrypt(&raw_file_data, &key, &iv_buffer)?;

        Ok(
            DBcrypt {
            iv: iv_buffer,
            key: key,
            filename: db_file_name,
            db: bytes_to_vec_entry(&decrypted_database)?,
            }
        )
    }
}