use clap::Parser;
use ldap3::LdapConn;
use utils::{create_user_list, get_password_policy};
use std::path::PathBuf;
mod utils;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// DC Target (e.g. dc01.domain.local or ip address)
    #[arg(short, long)]
    target: String,

    /// Domain (e.g. domain.local)
    #[arg(short, long)]
    domain: String,

    /// Username
    #[arg(short, long)]
    username: String,

    /// Password
    #[arg(short, long)]
    password: String,

    /// Output file path
    #[arg(short, long, default_value = "users.txt")]
    output: PathBuf,
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let ldap_url = format!("ldap://{}:389", args.target);
    let mut ldap = LdapConn::new(&ldap_url)?;
    let bind_user = format!("{}@{}", args.username, args.domain);
    let base_dn = format!("DC={}", args.domain.replace(".", ",DC="));

    //Bind to ldap
    println!("[*] Binding as {}", bind_user);
    ldap.simple_bind(&bind_user, &args.password)?;
    
    // Get Password Policy
    get_password_policy(& mut ldap, &base_dn)?;
    // Create User List
    match create_user_list(&mut ldap, base_dn.as_str(), args.output) {
        Ok(_) => {},
        Err(e) => {
            eprintln!("{e}")
        } 

    }

    Ok(ldap.unbind()?)
}
