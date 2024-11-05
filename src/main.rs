use clap::Parser;
use ldap3::{LdapConn, Scope, SearchEntry};
use std::fs::File;
use std::io::Write;

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
    output: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let ldap_url = format!("ldap://{}:389", args.target);
    let mut ldap = LdapConn::new(&ldap_url)?;

    let bind_user = format!("{}@{}", args.username, args.domain);
    ldap.simple_bind(&bind_user, &args.password)?;

    let base_dn = format!("DC={}", args.domain.replace(".", ",DC="));
    let filter = "(objectClass=user)";
    let mut file = File::create(args.output)?;

    let results= ldap.search(&base_dn, Scope::Subtree, filter, vec!["sAMAccountName"])?;
    let mut total_users = 0;
    for entry in results.0 {
        if let Some(name) = SearchEntry::construct(entry).attrs.get("sAMAccountName") {
            //println!("{:?}", name.first().unwrap());
            total_users += 1;
            writeln!(file, "{}", name.first().unwrap())?;
        }
    }
    println!("Created user list with {} entries.", total_users);

    Ok(ldap.unbind()?)
}
