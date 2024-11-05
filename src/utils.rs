use std::{fs::File, path::PathBuf};
use std::io::Write;
use ldap3::{LdapConn, Scope, SearchEntry};

pub fn get_password_policy(ldap: &mut LdapConn, base_dn: &str) -> Result<(), Box<dyn std::error::Error>> {
    let filter = "(&(objectClass=domainDNS))";
    let attrs = vec![
        "minPwdLength",
        "pwdHistoryLength",
        "maxPwdAge",
        "minPwdAge",
        "lockoutDuration",
        "lockoutThreshold"
    ];

    let results = ldap.search(base_dn, Scope::Base, filter, attrs)?;
    println!("\n[*] Password Policy:");
    
    for entry in results.0 {
        let entry = SearchEntry::construct(entry);
            if let Some(min_pwd) = entry.attrs.get("minPwdLength") {
                println!("Minimum Password Length: {}", min_pwd.first().unwrap_or(&"Not Set".to_string()));
            }
            if let Some(pwd_history) = entry.attrs.get("pwdHistoryLength") {
                println!("Password History Length: {}", pwd_history.first().unwrap_or(&"Not Set".to_string()));
            }
            if let Some(max_age) = entry.attrs.get("maxPwdAge") {
                // Convert from 100-nanosecond intervals to days
                if let Some(age) = max_age.first() {
                    if let Ok(age_num) = age.parse::<i64>() {
                        println!("Maximum Password Age (days): {}", age_num.abs() / (864000000000));
                    }
                }
            }
            if let Some(lockout_duration) = entry.attrs.get("lockoutDuration") {
                if let Some(duration) = lockout_duration.first() {
                    if let Ok(duration_num) = duration.parse::<i64>() {
                        println!("Account Lockout Duration (minutes): {}", duration_num.abs() / (600000000));
                    }
                }
            }
            if let Some(lockout_threshold) = entry.attrs.get("lockoutThreshold") {
                println!("Account Lockout Threshold: {}", lockout_threshold.first().unwrap_or(&"Not Set".to_string()));
            }
    }

    Ok(())
}


pub fn create_user_list(ldap: &mut LdapConn, base_dn: &str, output: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let filter = "(objectClass=user)";
    let mut file = File::create(output)?;

    let results= ldap.search(&base_dn, Scope::Subtree, filter, vec!["sAMAccountName"])?;
    let mut total_users = 0;
    for entry in results.0 {
        if let Some(name) = SearchEntry::construct(entry).attrs.get("sAMAccountName") {
            //println!("{:?}", name.first().unwrap());
            total_users += 1;
            writeln!(file, "{}", name.first().unwrap())?;
        }
    }
    println!("[+] Created user list with {} entries.", total_users);
    Ok(())
}